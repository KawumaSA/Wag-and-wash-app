from __future__ import annotations

import logging
import os
import re
import secrets
import hmac
import base64
import binascii
import json
import smtplib
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from email.message import EmailMessage
from hashlib import sha256
from pathlib import Path
from smtplib import SMTPException
from ssl import create_default_context
from typing import Annotated, Literal

import httpx
from google.auth import exceptions as google_auth_exceptions
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from postgrest.exceptions import APIError
from supabase import Client, create_client


ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("wag_wash")

SERVICES = {
    "bath": {"name": "Bath and brush", "duration": 60, "price": 45},
    "groom": {"name": "Full groom", "duration": 120, "price": 85},
    "nails": {"name": "Nail trim", "duration": 30, "price": 20},
}
OPEN_MINUTE = 9 * 60
WEEKDAY_CLOSE_MINUTE = 19 * 60
SATURDAY_CLOSE_MINUTE = 16 * 60
SLOT_STEP_MINUTE = 30
DEPOSIT_AMOUNT = 25
LOGIN_CODE_TTL_MINUTES = 10
LOGIN_CODE_REQUEST_LIMIT = 3
LOGIN_CODE_REQUEST_WINDOW_MINUTES = 15
LOGIN_CODE_MAX_ATTEMPTS = 5
CUSTOMER_SESSION_TTL_MINUTES = 30
PAYMENT_RESERVATION_MINUTES = 30
PAYMENT_CURRENCY = "USD"

app = FastAPI(title="Wag & Wash API", version="1.0.0")


@app.exception_handler(httpx.RequestError)
async def handle_supabase_connection_error(_request: Request, _exc: httpx.RequestError) -> JSONResponse:
    logger.exception("A request to Supabase failed.")
    return JSONResponse(
        status_code=503,
        content={
            "detail": (
                "Could not reach Supabase. Check SUPABASE_URL and this computer's "
                "network/DNS connection."
            )
        },
    )


class BookingRequest(BaseModel):
    booking_date: date
    start_minute: int = Field(ge=0, le=1439)
    service_id: Literal["bath", "groom", "nails"]
    name: str = Field(min_length=1, max_length=120)
    email: str = Field(min_length=5, max_length=254)
    dog: str = Field(min_length=1, max_length=120)
    breed: str = Field(default="", max_length=120)
    notes: str = Field(default="", max_length=2000)
    booking_email_consent: bool


class BookingStatusUpdate(BaseModel):
    status: Literal["confirmed", "completed", "cancelled", "no_show"]


class CustomerBookingLookup(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    email_code: str = Field(pattern=r"^\d{6}$")


class CustomerEmailRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)


class CustomerGoogleLogin(BaseModel):
    credential: str = Field(min_length=1, max_length=8192)


class BookingCheckoutRequest(BaseModel):
    access_code: str = Field(min_length=1, max_length=128)


class BookingCaptureRequest(BaseModel):
    order_id: str = Field(min_length=1, max_length=64)
    access_code: str = Field(min_length=1, max_length=128)


class OwnerLoginRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=1, max_length=1024)


def business_close(day: date) -> int | None:
    if day.weekday() == 6:
        return None
    if day.weekday() == 5:
        return SATURDAY_CLOSE_MINUTE
    return WEEKDAY_CLOSE_MINUTE


def make_slots(day: date, duration: int, now: datetime | None = None) -> list[int]:
    close = business_close(day)
    if close is None:
        return []
    slots = list(range(OPEN_MINUTE, close - duration + 1, SLOT_STEP_MINUTE))
    current = now or datetime.now()
    if day == current.date():
        current_minute = current.hour * 60 + current.minute
        slots = [slot for slot in slots if slot > current_minute]
    return slots


def get_supabase() -> Client:
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    if not url or not key:
        raise HTTPException(
            status_code=503,
            detail="Supabase is not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in .env.",
        )
    try:
        return create_client(url, key)
    except (ValueError, RuntimeError) as exc:
        logger.exception("Could not initialize the Supabase client.")
        raise HTTPException(status_code=503, detail="Supabase client configuration is invalid.") from exc


def require_owner(
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    configured_email = os.getenv("OWNER_EMAIL", "").strip().lower()
    configured_password = os.getenv("OWNER_PASSWORD", "")
    session_secret = os.getenv("OWNER_SESSION_SECRET", "")
    if not configured_email or not configured_password or len(session_secret) < 32:
        raise HTTPException(
            status_code=503,
            detail="Owner access is not configured. Set OWNER_EMAIL, OWNER_PASSWORD, and OWNER_SESSION_SECRET in .env.",
        )
    scheme, _, supplied_token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not supplied_token:
        raise HTTPException(status_code=401, detail="Sign in with the owner email and password.")
    try:
        encoded, supplied_signature = supplied_token.split(".", 1)
        expected_signature = hmac.new(
            session_secret.encode("utf-8"), encoded.encode("ascii"), sha256
        ).digest()
        expected = base64.urlsafe_b64encode(expected_signature).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(supplied_signature, expected):
            raise ValueError("Invalid signature")
        padding = "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded + padding))
        if not isinstance(payload, dict):
            raise ValueError("Invalid session")
        session_email = payload.get("email")
        if not isinstance(session_email, str) or not hmac.compare_digest(
            session_email.encode("utf-8"), configured_email.encode("utf-8")
        ):
            raise ValueError("Invalid session")
    except (ValueError, TypeError, UnicodeError, binascii.Error, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=401, detail="Your owner session is invalid. Please sign in again.") from exc


def owner_session_token(email: str) -> str:
    secret = os.getenv("OWNER_SESSION_SECRET", "")
    if len(secret) < 32:
        raise HTTPException(status_code=503, detail="Owner session security is not configured.")
    payload = {
        "email": email,
        "nonce": secrets.token_urlsafe(16),
    }
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    signature = hmac.new(secret.encode("utf-8"), encoded.encode("ascii"), sha256).digest()
    signed = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"{encoded}.{signed}"


@app.post("/api/owner/login")
def owner_login(credentials: OwnerLoginRequest) -> dict[str, str]:
    configured_email = os.getenv("OWNER_EMAIL", "").strip().lower()
    configured_password = os.getenv("OWNER_PASSWORD", "")
    session_secret = os.getenv("OWNER_SESSION_SECRET", "")
    if not configured_email or not configured_password or len(session_secret) < 32:
        raise HTTPException(
            status_code=503,
            detail="Owner access is not configured. Set OWNER_EMAIL, OWNER_PASSWORD, and OWNER_SESSION_SECRET in .env.",
        )
    supplied_email = credentials.email.strip().lower()
    email_matches = hmac.compare_digest(supplied_email.encode("utf-8"), configured_email.encode("utf-8"))
    password_matches = hmac.compare_digest(
        credentials.password.encode("utf-8"), configured_password.encode("utf-8")
    )
    if not (email_matches and password_matches):
        raise HTTPException(status_code=401, detail="Invalid owner email or password.")
    return {"session_token": owner_session_token(configured_email)}


def booking_response(record: dict) -> dict:
    return {
        "id": record["id"],
        "date": record["booking_date"],
        "start": record["start_minute"],
        "svc": record["service_id"],
        "name": record["name"],
        "email": record.get("email", ""),
        "dog": record["dog"],
        "breed": record["breed"],
        "notes": record["notes"],
        "status": record["status"],
        "deposit_amount": float(record["deposit_amount"]),
        "paid": float(record["paid"]),
        "refunded": record["refunded"],
        "payment_status": record.get("payment_status", "unpaid"),
        "payment_confirmation_email_sent": record.get("payment_confirmation_email_sent", False),
    }


def customer_email(raw_email: str) -> str:
    email = raw_email.strip().lower()
    if len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(status_code=422, detail="Enter a valid email address.")
    return email


def paypal_mode() -> str:
    mode = os.getenv("PAYPAL_MODE", "sandbox").strip().lower()
    if mode not in {"sandbox", "live"}:
        raise HTTPException(status_code=503, detail="PAYPAL_MODE must be set to sandbox or live.")
    return mode


def paypal_api_base() -> str:
    return "https://api-m.paypal.com" if paypal_mode() == "live" else "https://api-m.sandbox.paypal.com"


def paypal_credentials() -> tuple[str, str]:
    client_id = os.getenv("PAYPAL_CLIENT_ID", "").strip()
    client_secret = os.getenv("PAYPAL_CLIENT_SECRET", "")
    webhook_id = os.getenv("PAYPAL_WEBHOOK_ID", "").strip()
    if not client_id or not client_secret or not webhook_id:
        raise HTTPException(
            status_code=503,
            detail="Online payments are not configured. Set the PayPal client ID, secret, and webhook ID in .env.",
        )
    return client_id, client_secret


def paypal_api_request(
    method: str,
    path: str,
    body: dict | None = None,
    headers: dict[str, str] | None = None,
) -> dict:
    client_id, client_secret = paypal_credentials()
    try:
        token_response = httpx.post(
            f"{paypal_api_base()}/v1/oauth2/token",
            auth=(client_id, client_secret),
            data={"grant_type": "client_credentials"},
            timeout=15,
        )
        token_response.raise_for_status()
        access_token = token_response.json()["access_token"]
        response = httpx.request(
            method,
            f"{paypal_api_base()}{path}",
            headers={"Authorization": f"Bearer {access_token}", **(headers or {})},
            json=body,
            timeout=20,
        )
        response.raise_for_status()
        return response.json() if response.content else {}
    except httpx.RequestError as exc:
        logger.exception("Could not connect to PayPal.")
        raise HTTPException(status_code=503, detail="Could not reach PayPal. Please try again.") from exc
    except httpx.HTTPStatusError as exc:
        logger.error("PayPal returned HTTP %s for %s.", exc.response.status_code, path)
        raise HTTPException(status_code=502, detail="PayPal could not complete the payment request.") from exc
    except (KeyError, TypeError, ValueError) as exc:
        logger.exception("PayPal returned an invalid response.")
        raise HTTPException(status_code=502, detail="PayPal returned an invalid response.") from exc


def create_paypal_order(booking: dict) -> str:
    order = paypal_api_request(
        "POST",
        "/v2/checkout/orders",
        {
            "intent": "CAPTURE",
            "purchase_units": [{
                "reference_id": str(booking["id"]),
                "custom_id": str(booking["id"]),
                "description": f"Wag & Wash deposit for {booking['dog']}",
                "amount": {
                    "currency_code": PAYMENT_CURRENCY,
                    "value": f"{float(booking['deposit_amount']):.2f}",
                },
            }],
            "payment_source": {
                "paypal": {
                    "experience_context": {
                        "brand_name": "Wag & Wash",
                        "user_action": "PAY_NOW",
                        "shipping_preference": "NO_SHIPPING",
                    }
                }
            },
        },
    )
    order_id = order.get("id")
    if not isinstance(order_id, str) or not order_id:
        logger.error("PayPal order creation response did not contain an order ID.")
        raise HTTPException(status_code=502, detail="PayPal did not create a checkout order.")
    return order_id


def expire_unpaid_bookings(client: Client, booking_date: date) -> None:
    try:
        response = (
            client.table("bookings")
            .select("id,payment_expires_at")
            .eq("booking_date", booking_date.isoformat())
            .eq("status", "pending")
            .in_("payment_status", ["unpaid", "initializing", "pending"])
            .execute()
        )
    except APIError as exc:
        logger.exception("Supabase could not check for expired payment reservations.")
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "check appointment availability")) from exc
    now = datetime.now().astimezone()
    for booking in response.data:
        expires_at = booking.get("payment_expires_at")
        if not expires_at:
            continue
        try:
            expiration = datetime.fromisoformat(expires_at)
        except (TypeError, ValueError) as exc:
            logger.error("Booking %s has an invalid payment expiration.", booking["id"])
            raise HTTPException(status_code=503, detail="A payment reservation has invalid expiration data.") from exc
        if expiration <= now:
            try:
                (
                    client.table("bookings")
                    .update({"status": "cancelled", "payment_status": "expired"})
                    .eq("id", booking["id"])
                    .eq("status", "pending")
                    .in_("payment_status", ["unpaid", "initializing", "pending"])
                    .execute()
                )
            except APIError as exc:
                logger.exception("Could not release an expired payment reservation.")
                raise HTTPException(status_code=503, detail=database_error_detail(exc, "release an expired appointment")) from exc


def verify_google_id_token(credential: str) -> str:
    client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip()
    if not client_id:
        raise HTTPException(status_code=503, detail="Google sign-in is not configured. Set GOOGLE_CLIENT_ID in .env.")
    try:
        claims = id_token.verify_oauth2_token(credential, GoogleAuthRequest(), client_id)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Google sign-in could not be verified. Try again.") from exc
    except google_auth_exceptions.GoogleAuthError as exc:
        logger.exception("Could not verify a Google sign-in token.")
        raise HTTPException(status_code=503, detail="Could not verify Google sign-in. Try again shortly.") from exc
    email = claims.get("email")
    if claims.get("email_verified") is not True or not isinstance(email, str):
        raise HTTPException(status_code=401, detail="Use a Google account with a verified email address.")
    return customer_email(email)


def access_code_hash(access_code: str) -> str:
    return sha256(access_code.encode("utf-8")).hexdigest()


def login_code_hash(code: str) -> str:
    secret = os.getenv("CUSTOMER_CODE_HASH_SECRET")
    if not secret:
        raise HTTPException(
            status_code=503,
            detail="Email-code security is not configured. Set CUSTOMER_CODE_HASH_SECRET in .env.",
        )
    return hmac.new(secret.encode("utf-8"), code.encode("utf-8"), sha256).hexdigest()


def customer_session_token(email: str) -> str:
    secret = os.getenv("CUSTOMER_CODE_HASH_SECRET")
    if not secret:
        raise HTTPException(status_code=503, detail="Customer session security is not configured.")
    payload = {
        "email": email,
        "expires": int((datetime.now().astimezone() + timedelta(minutes=CUSTOMER_SESSION_TTL_MINUTES)).timestamp()),
        "nonce": secrets.token_urlsafe(16),
    }
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    signature = hmac.new(secret.encode("utf-8"), encoded.encode("ascii"), sha256).digest()
    signed = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"{encoded}.{signed}"


def customer_session_email(authorization: str | None) -> str:
    supplied_token = authorization.removeprefix("Bearer ").strip() if authorization else ""
    try:
        encoded, supplied_signature = supplied_token.split(".", 1)
        secret = os.getenv("CUSTOMER_CODE_HASH_SECRET")
        if not secret:
            raise HTTPException(status_code=503, detail="Customer session security is not configured.")
        expected_signature = hmac.new(secret.encode("utf-8"), encoded.encode("ascii"), sha256).digest()
        expected = base64.urlsafe_b64encode(expected_signature).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(supplied_signature, expected):
            raise ValueError("Invalid signature")
        padding = "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded + padding))
        if not isinstance(payload, dict) or payload.get("expires", 0) <= int(datetime.now().timestamp()):
            raise ValueError("Expired session")
        email = customer_email(payload["email"])
    except (ValueError, KeyError, TypeError, binascii.Error, json.JSONDecodeError, HTTPException) as exc:
        if isinstance(exc, HTTPException) and exc.status_code == 503:
            raise
        raise HTTPException(status_code=401, detail="Your sign-in has expired. Sign in again to continue.") from exc
    return email


def send_email(recipient: str, subject: str, body: str) -> None:
    host = os.getenv("SMTP_HOST")
    port_value = os.getenv("SMTP_PORT", "465")
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    sender = os.getenv("SMTP_FROM_EMAIL")
    ssl_setting = os.getenv("SMTP_USE_SSL", "true").strip().lower()
    if ssl_setting not in {"true", "1", "yes", "false", "0", "no"}:
        raise HTTPException(status_code=503, detail="SMTP_USE_SSL must be true or false.")
    use_ssl = ssl_setting in {"true", "1", "yes"}
    if not host or not username or not password or not sender:
        raise HTTPException(
            status_code=503,
            detail="Email is not configured. Set SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, and SMTP_FROM_EMAIL in .env.",
        )
    try:
        port = int(port_value)
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="SMTP_PORT must be a valid port number.") from exc
    if not 1 <= port <= 65535:
        raise HTTPException(status_code=503, detail="SMTP_PORT must be between 1 and 65535.")
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = recipient
    message.set_content(body)
    try:
        if use_ssl:
            with smtplib.SMTP_SSL(host, port, context=create_default_context(), timeout=20) as smtp:
                smtp.login(username, password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=20) as smtp:
                smtp.ehlo()
                smtp.starttls(context=create_default_context())
                smtp.ehlo()
                smtp.login(username, password)
                smtp.send_message(message)
    except (SMTPException, OSError) as exc:
        logger.error("SMTP could not send an email (%s).", type(exc).__name__)
        raise HTTPException(
            status_code=502,
            detail="The email provider could not send the message. Check the SMTP settings and destination address.",
        ) from exc


def database_error_detail(exc: APIError, operation: str) -> str:
    if getattr(exc, "code", None) in {"PGRST204", "PGRST205", "42703"}:
        return (
            "The Supabase schema is missing a required table or column. "
            "Run the latest supabase/schema.sql in the Supabase SQL Editor."
        )
    return f"Could not {operation} in Supabase."


def load_day_bookings(client: Client, day: date) -> list[dict]:
    expire_unpaid_bookings(client, day)
    try:
        response = (
            client.table("bookings")
            .select("start_minute,service_duration_min")
            .eq("booking_date", day.isoformat())
            .in_("status", ["pending", "confirmed"])
            .execute()
        )
    except APIError as exc:
        logger.exception("Supabase could not retrieve day availability.")
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "check availability")) from exc
    return response.data


@app.get("/", include_in_schema=False)
def home() -> FileResponse:
    return FileResponse(
        ROOT / "app" / "Wag & Wash booking app.html",
        media_type="text/html",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/api/public-config")
def public_config() -> dict[str, str]:
    paypal_configured = all(
        os.getenv(key, "").strip()
        for key in ("PAYPAL_CLIENT_ID", "PAYPAL_CLIENT_SECRET", "PAYPAL_WEBHOOK_ID")
    )
    return {
        "google_client_id": os.getenv("GOOGLE_CLIENT_ID", "").strip(),
        "paypal_client_id": os.getenv("PAYPAL_CLIENT_ID", "").strip() if paypal_configured else "",
        "paypal_currency": PAYMENT_CURRENCY,
    }


@app.get("/api/health")
def health(client: Client = Depends(get_supabase)) -> dict[str, str]:
    try:
        client.table("bookings").select("id,access_code_hash,email").limit(1).execute()
        client.table("customer_email_verification_codes").select("id").limit(1).execute()
    except APIError as exc:
        logger.exception("Supabase health check failed.")
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "check the database connection")) from exc
    return {"status": "ok", "supabase": "connected"}


@app.get("/api/availability")
def availability(
    booking_date: date = Query(alias="date"),
    service_id: Literal["bath", "groom", "nails"] = Query(alias="serviceId"),
    client: Client = Depends(get_supabase),
) -> dict:
    duration = SERVICES[service_id]["duration"]
    slots = make_slots(booking_date, duration)
    bookings = load_day_bookings(client, booking_date)
    available = [
        slot
        for slot in slots
        if not any(
            slot < booking["start_minute"] + booking["service_duration_min"]
            and booking["start_minute"] < slot + duration
            for booking in bookings
        )
    ]
    close = business_close(booking_date)
    return {
        "date": booking_date.isoformat(),
        "serviceId": service_id,
        "closed": close is None,
        "closingTime": close,
        "slots": available,
    }


@app.post("/api/bookings", status_code=201)
def create_booking(
    request: BookingRequest,
    client: Client = Depends(get_supabase),
) -> dict:
    service = SERVICES[request.service_id]
    email = customer_email(request.email)
    if not request.booking_email_consent:
        raise HTTPException(
            status_code=422,
            detail="Agree to receive the booking confirmation and private booking code by email.",
        )
    name = request.name.strip()
    dog = request.dog.strip()
    if not name or not dog:
        raise HTTPException(status_code=422, detail="Enter both your name and your dog's name.")
    if request.start_minute % SLOT_STEP_MINUTE != 0:
        raise HTTPException(status_code=422, detail="Choose a valid 30-minute start time.")
    if request.start_minute not in make_slots(request.booking_date, service["duration"]):
        raise HTTPException(status_code=409, detail="That time is outside business hours or has already passed.")

    current_bookings = load_day_bookings(client, request.booking_date)
    overlaps = any(
        request.start_minute < booking["start_minute"] + booking["service_duration_min"]
        and booking["start_minute"] < request.start_minute + service["duration"]
        for booking in current_bookings
    )
    if overlaps:
        raise HTTPException(status_code=409, detail="That appointment time was just booked. Please choose another.")

    access_code = secrets.token_urlsafe(18)
    record = {
        "booking_date": request.booking_date.isoformat(),
        "start_minute": request.start_minute,
        "service_id": request.service_id,
        "service_duration_min": service["duration"],
        "service_price": service["price"],
        "name": name,
        "phone": "",
        "email": email,
        "access_code_hash": access_code_hash(access_code),
        "booking_email_consent": request.booking_email_consent,
        "dog": dog,
        "breed": request.breed.strip(),
        "notes": request.notes.strip(),
        "status": "pending",
        "deposit_amount": DEPOSIT_AMOUNT,
        "paid": 0,
        "refunded": False,
        "payment_status": "unpaid",
        "payment_provider": "paypal",
        "paypal_order_id": None,
        "paypal_capture_id": None,
        "payment_expires_at": (
            datetime.now().astimezone() + timedelta(minutes=PAYMENT_RESERVATION_MINUTES)
        ).isoformat(),
    }
    try:
        response = client.table("bookings").insert(record).execute()
    except APIError as exc:
        if getattr(exc, "code", None) == "23P01":
            raise HTTPException(status_code=409, detail="That appointment time was just booked. Please choose another.") from exc
        logger.exception("Supabase could not create the booking.")
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "save the booking")) from exc
    if not response.data:
        logger.error("Supabase returned no booking after a successful insert.")
        raise HTTPException(status_code=502, detail="Supabase did not return the saved booking.")
    booking = booking_response(response.data[0])
    message = (
        f"Hello {name},\n\n"
        f"We received your Wag & Wash booking request for {dog} on "
        f"{request.booking_date:%A, %B %d} at "
        f"{request.start_minute // 60 % 12 or 12}:{request.start_minute % 60:02d} "
        f"{'AM' if request.start_minute < 720 else 'PM'}.\n\n"
        f"Your private booking code is: {access_code}\n\n"
        "Keep this code private. You can use it with your email address to access your booking. "
        "No deposit has been charged."
    )
    try:
        send_email(email, "Wag & Wash booking request and private code", message)
    except HTTPException as exc:
        logger.warning("Booking %s was saved but its confirmation email was not sent.", booking["id"])
        return {
            **booking,
            "access_code": access_code,
            "email_sent": False,
            "email_error": exc.detail,
        }
    return {**booking, "access_code": access_code, "email_sent": True, "email_error": None}


def get_booking_record(client: Client, booking_id: int) -> dict:
    try:
        response = client.table("bookings").select("*").eq("id", booking_id).execute()
    except APIError as exc:
        logger.exception("Supabase could not retrieve a booking for payment.")
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "load the booking")) from exc
    if not response.data:
        raise HTTPException(status_code=404, detail="We couldn't find this booking.")
    return response.data[0]


def get_booking_for_order(client: Client, order_id: str) -> dict | None:
    try:
        response = client.table("bookings").select("*").eq("paypal_order_id", order_id).execute()
    except APIError as exc:
        logger.exception("Supabase could not retrieve a booking for a PayPal order.")
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "verify the payment")) from exc
    return response.data[0] if response.data else None


def validate_paypal_capture(capture: dict, booking: dict) -> tuple[str, float]:
    if capture.get("status") != "COMPLETED":
        raise HTTPException(status_code=409, detail="PayPal has not completed this payment.")
    amount = capture.get("amount", {})
    try:
        paid = Decimal(amount["value"])
    except (KeyError, TypeError, ValueError, InvalidOperation) as exc:
        raise HTTPException(status_code=502, detail="PayPal returned an invalid payment amount.") from exc
    if amount.get("currency_code") != PAYMENT_CURRENCY or paid != Decimal(str(booking["deposit_amount"])):
        logger.error("PayPal capture amount or currency did not match booking %s.", booking["id"])
        raise HTTPException(status_code=409, detail="The payment amount does not match this booking deposit.")
    capture_id = capture.get("id")
    if not isinstance(capture_id, str) or not capture_id:
        raise HTTPException(status_code=502, detail="PayPal did not return a capture ID.")
    return capture_id, float(paid)


def refund_late_paypal_capture(
    client: Client,
    booking: dict,
    capture_id: str,
    paid: float,
) -> None:
    refund_key = "refund-" + sha256(capture_id.encode("utf-8")).hexdigest()[:30]
    refund = paypal_api_request(
        "POST",
        f"/v2/payments/captures/{capture_id}/refund",
        headers={"PayPal-Request-Id": refund_key},
    )
    if refund.get("status") not in {"COMPLETED", "PENDING"}:
        logger.error("PayPal did not confirm a refund for late capture %s.", capture_id)
        raise HTTPException(status_code=502, detail="PayPal could not refund a payment for an expired booking.")
    try:
        client.table("bookings").update({
            "status": "cancelled",
            "payment_status": "refunded",
            "paypal_capture_id": capture_id,
            "paid": paid,
            "refunded": True,
        }).eq("id", booking["id"]).eq("paypal_order_id", booking["paypal_order_id"]).execute()
    except APIError as exc:
        logger.exception("Could not record a PayPal refund for expired booking %s.", booking["id"])
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "record the payment refund")) from exc


def send_payment_confirmation_if_needed(client: Client, booking: dict) -> bool:
    if booking.get("payment_confirmation_email_sent"):
        return True
    if not booking.get("email"):
        return False
    booking_day = date.fromisoformat(booking["booking_date"])
    service = SERVICES[booking["service_id"]]
    message = (
        f"Hello {booking['name']},\n\n"
        f"Your ${float(booking['paid']):.2f} deposit has been received, and {booking['dog']} is booked for "
        f"{service['name']} on {booking_day:%A, %B %d} at "
        f"{booking['start_minute'] // 60 % 12 or 12}:{booking['start_minute'] % 60:02d} "
        f"{'AM' if booking['start_minute'] < 720 else 'PM'}.\n\n"
        "Thank you for booking with Wag & Wash."
    )
    try:
        send_email(booking["email"], "Your Wag & Wash appointment is confirmed", message)
    except HTTPException as exc:
        logger.warning("Could not email the payment confirmation for booking %s: %s", booking["id"], exc.detail)
        return False
    try:
        client.table("bookings").update({"payment_confirmation_email_sent": True}).eq(
            "id", booking["id"]
        ).eq("paypal_capture_id", booking["paypal_capture_id"]).execute()
    except APIError:
        logger.exception("Payment confirmation email was sent but its delivery status could not be recorded.")
    return True


def complete_paypal_payment(client: Client, order_id: str, capture: dict) -> dict:
    booking = get_booking_for_order(client, order_id)
    if booking is None:
        raise HTTPException(status_code=404, detail="No booking is linked to this PayPal order.")
    capture_id, paid = validate_paypal_capture(capture, booking)
    if booking.get("payment_status") == "paid":
        if booking.get("paypal_capture_id") != capture_id:
            raise HTTPException(status_code=409, detail="A different payment was already recorded for this booking.")
        send_payment_confirmation_if_needed(client, booking)
        return booking_response(booking)
    expires_at = booking.get("payment_expires_at")
    expired = bool(expires_at) and datetime.fromisoformat(expires_at) <= datetime.now().astimezone()
    if booking.get("status") != "pending" or expired:
        refund_late_paypal_capture(client, booking, capture_id, paid)
        return booking_response(get_booking_record(client, booking["id"]))
    try:
        updated = (
            client.table("bookings")
            .update({
                "status": "confirmed",
                "payment_status": "paid",
                "paypal_capture_id": capture_id,
                "paid": paid,
                "payment_confirmation_email_sent": False,
            })
            .eq("id", booking["id"])
            .eq("paypal_order_id", order_id)
            .eq("status", "pending")
            .eq("payment_status", "pending")
            .execute()
        )
    except APIError as exc:
        if getattr(exc, "code", None) == "23P01":
            refund_late_paypal_capture(client, booking, capture_id, paid)
            return booking_response(get_booking_record(client, booking["id"]))
        logger.exception("Supabase could not confirm booking payment.")
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "confirm the paid booking")) from exc
    if not updated.data:
        current = get_booking_record(client, booking["id"])
        if current.get("payment_status") == "paid" and current.get("paypal_capture_id") == capture_id:
            send_payment_confirmation_if_needed(client, current)
            return booking_response(current)
        refund_late_paypal_capture(client, current, capture_id, paid)
        return booking_response(get_booking_record(client, booking["id"]))
    email_sent = send_payment_confirmation_if_needed(client, updated.data[0])
    updated.data[0]["payment_confirmation_email_sent"] = email_sent
    return booking_response(updated.data[0])


@app.post("/api/bookings/{booking_id}/checkout")
def create_booking_checkout(
    booking_id: int,
    request: BookingCheckoutRequest,
    client: Client = Depends(get_supabase),
) -> dict[str, str]:
    paypal_credentials()
    booking = get_booking_record(client, booking_id)
    if not hmac.compare_digest(
        booking.get("access_code_hash", ""),
        access_code_hash(request.access_code),
    ):
        raise HTTPException(status_code=401, detail="This booking code is invalid.")
    if booking["status"] != "pending":
        raise HTTPException(status_code=409, detail="This booking is no longer awaiting payment.")
    if booking.get("payment_status") == "paid":
        raise HTTPException(status_code=409, detail="This booking has already been paid.")
    expires_at = booking.get("payment_expires_at")
    if expires_at and datetime.fromisoformat(expires_at) <= datetime.now().astimezone():
        raise HTTPException(status_code=409, detail="This payment reservation expired. Please choose another appointment.")
    if booking.get("payment_status") == "pending" and booking.get("paypal_order_id"):
        return {"order_id": booking["paypal_order_id"]}
    if booking.get("payment_status") == "initializing":
        raise HTTPException(status_code=409, detail="Payment checkout is already being prepared. Try again shortly.")
    try:
        claimed = (
            client.table("bookings")
            .update({"payment_status": "initializing"})
            .eq("id", booking_id)
            .eq("status", "pending")
            .eq("payment_status", "unpaid")
            .execute()
        )
    except APIError as exc:
        logger.exception("Could not prepare the booking for PayPal checkout.")
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "prepare checkout")) from exc
    if not claimed.data:
        raise HTTPException(status_code=409, detail="This booking is already being paid or is no longer available.")
    try:
        order_id = create_paypal_order(booking)
    except HTTPException:
        try:
            client.table("bookings").update({"payment_status": "unpaid"}).eq("id", booking_id).eq(
                "payment_status", "initializing"
            ).execute()
        except APIError:
            logger.exception("Could not reset payment state after PayPal order creation failed.")
        raise
    try:
        saved = (
            client.table("bookings")
            .update({"payment_status": "pending", "paypal_order_id": order_id})
            .eq("id", booking_id)
            .eq("payment_status", "initializing")
            .execute()
        )
    except APIError as exc:
        logger.exception("PayPal order was created but could not be linked to its booking.")
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "save checkout")) from exc
    if not saved.data:
        raise HTTPException(status_code=409, detail="This booking changed while checkout was being prepared.")
    return {"order_id": order_id}


@app.post("/api/bookings/{booking_id}/capture")
def capture_booking_payment(
    booking_id: int,
    request: BookingCaptureRequest,
    client: Client = Depends(get_supabase),
) -> dict:
    booking = get_booking_record(client, booking_id)
    if not hmac.compare_digest(
        booking.get("access_code_hash", ""),
        access_code_hash(request.access_code),
    ):
        raise HTTPException(status_code=401, detail="This booking code is invalid.")
    if booking.get("paypal_order_id") != request.order_id:
        raise HTTPException(status_code=404, detail="No PayPal payment is linked to this booking.")
    if booking.get("payment_status") == "paid":
        return booking_response(booking)
    if booking.get("payment_status") != "pending" or booking.get("status") != "pending":
        raise HTTPException(status_code=409, detail="This booking is no longer awaiting payment.")
    expires_at = booking.get("payment_expires_at")
    if expires_at and datetime.fromisoformat(expires_at) <= datetime.now().astimezone():
        raise HTTPException(status_code=409, detail="This payment reservation expired. Please choose another appointment.")
    result = paypal_api_request("POST", f"/v2/checkout/orders/{request.order_id}/capture", {})
    try:
        capture = result["purchase_units"][0]["payments"]["captures"][0]
    except (KeyError, IndexError, TypeError) as exc:
        logger.error("PayPal capture response had no capture for booking %s.", booking_id)
        raise HTTPException(status_code=502, detail="PayPal did not return a completed capture.") from exc
    paid_booking = complete_paypal_payment(client, request.order_id, capture)
    return {"booking": paid_booking}


def verify_paypal_webhook(event: dict, headers: httpx.Headers) -> bool:
    paypal_credentials()
    webhook_id = os.getenv("PAYPAL_WEBHOOK_ID", "").strip()
    required_headers = {
        "auth_algo": headers.get("paypal-auth-algo"),
        "cert_url": headers.get("paypal-cert-url"),
        "transmission_id": headers.get("paypal-transmission-id"),
        "transmission_sig": headers.get("paypal-transmission-sig"),
        "transmission_time": headers.get("paypal-transmission-time"),
    }
    if not all(required_headers.values()):
        return False
    verification = paypal_api_request(
        "POST",
        "/v1/notifications/verify-webhook-signature",
        {**required_headers, "webhook_id": webhook_id, "webhook_event": event},
    )
    return verification.get("verification_status") == "SUCCESS"


@app.post("/api/payments/paypal/webhook")
def paypal_webhook(
    event: dict,
    request: Request,
    client: Client = Depends(get_supabase),
) -> dict[str, bool]:
    if not verify_paypal_webhook(event, request.headers):
        raise HTTPException(status_code=400, detail="PayPal webhook signature is invalid.")
    if event.get("event_type") != "PAYMENT.CAPTURE.COMPLETED":
        return {"received": True}
    resource = event.get("resource")
    if not isinstance(resource, dict):
        raise HTTPException(status_code=400, detail="PayPal webhook event is invalid.")
    try:
        order_id = resource["supplementary_data"]["related_ids"]["order_id"]
    except (KeyError, TypeError):
        logger.info("Ignoring PayPal capture event without a related order ID.")
        return {"received": True}
    if not isinstance(order_id, str) or not order_id:
        return {"received": True}
    complete_paypal_payment(client, order_id, resource)
    return {"received": True}


@app.post("/api/my/bookings/send-email-code")
def send_customer_login_code(
    request: CustomerEmailRequest,
    client: Client = Depends(get_supabase),
) -> dict[str, str]:
    email = customer_email(request.email)
    now = datetime.now().astimezone()
    try:
        customer_booking_check = (
            client.table("bookings")
            .select("id")
            .eq("email", email)
            .limit(1)
            .execute()
        )
    except APIError as exc:
        logger.exception("Supabase could not check for customer bookings.")
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "check for your booking")) from exc
    if not customer_booking_check.data:
        return {"message": "If a booking exists for this email address, a sign-in code has been sent."}

    request_window = (now - timedelta(minutes=LOGIN_CODE_REQUEST_WINDOW_MINUTES)).isoformat()
    try:
        response = (
            client.table("customer_email_verification_codes")
            .select("id")
            .eq("email", email)
            .gte("created_at", request_window)
            .execute()
        )
    except APIError as exc:
        logger.exception("Supabase could not check email-code request limits.")
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "check email-code limits")) from exc
    if len(response.data) >= LOGIN_CODE_REQUEST_LIMIT:
        raise HTTPException(status_code=429, detail="Too many codes requested. Wait 15 minutes and try again.")

    code = f"{secrets.randbelow(1_000_000):06d}"
    created_at = now.isoformat()
    expires_at = (now + timedelta(minutes=LOGIN_CODE_TTL_MINUTES)).isoformat()
    try:
        inserted = (
            client.table("customer_email_verification_codes")
            .insert({
                "email": email,
                "code_hash": login_code_hash(code),
                "created_at": created_at,
                "expires_at": expires_at,
                "attempts": 0,
                "email_sent": False,
                "verified_at": None,
            })
            .execute()
        )
    except APIError as exc:
        logger.exception("Supabase could not create a customer login code.")
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "save the email code")) from exc
    if not inserted.data:
        logger.error("Supabase returned no email-code row after insert.")
        raise HTTPException(status_code=502, detail="Could not prepare the email code.")

    try:
        send_email(
            email,
            "Your Wag & Wash sign-in code",
            f"Your Wag & Wash sign-in code is {code}.\n\n"
            "It expires in 10 minutes. Do not share it with anyone.",
        )
    except HTTPException:
        logger.warning("Could not send a sign-in email.")
        try:
            (
                client.table("customer_email_verification_codes")
                .update({"expires_at": now.isoformat()})
                .eq("id", inserted.data[0]["id"])
                .execute()
            )
        except APIError:
            logger.exception("Could not invalidate an undelivered sign-in code.")
        raise
    try:
        (
            client.table("customer_email_verification_codes")
            .update({"email_sent": True})
            .eq("id", inserted.data[0]["id"])
            .execute()
        )
    except APIError as exc:
        logger.exception("Could not mark a sign-in code as sent.")
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "record email delivery")) from exc
    return {"message": "A sign-in code was emailed. It expires in 10 minutes."}


def verify_customer_email_code(
    client: Client,
    raw_email: str,
    email_code: str,
) -> str:
    email = customer_email(raw_email)
    try:
        response = (
            client.table("customer_email_verification_codes")
            .select("*")
            .eq("email", email)
            .eq("email_sent", True)
            .gte("expires_at", datetime.now().astimezone().isoformat())
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
    except APIError as exc:
        logger.exception("Supabase could not retrieve a customer sign-in code.")
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "verify the email code")) from exc
    if not response.data:
        raise HTTPException(status_code=401, detail="That sign-in code is invalid or expired. Request a new code.")
    code_record = response.data[0]
    if code_record["attempts"] >= LOGIN_CODE_MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many incorrect codes. Request a new sign-in code.")
    if not hmac.compare_digest(code_record["code_hash"], login_code_hash(email_code)):
        attempts = code_record["attempts"] + 1
        try:
            client.table("customer_email_verification_codes").update({"attempts": attempts}).eq("id", code_record["id"]).execute()
        except APIError as exc:
            logger.exception("Supabase could not record an incorrect email-code attempt.")
            raise HTTPException(status_code=503, detail=database_error_detail(exc, "record the code attempt")) from exc
        if attempts >= LOGIN_CODE_MAX_ATTEMPTS:
            raise HTTPException(status_code=429, detail="Too many incorrect codes. Request a new sign-in code.")
        raise HTTPException(status_code=401, detail="That sign-in code is incorrect.")
    if code_record.get("verified_at") is not None:
        raise HTTPException(status_code=401, detail="That sign-in code has already been used. Request a new code.")
    try:
        consumed = (
            client.table("customer_email_verification_codes")
            .update({"verified_at": datetime.now().astimezone().isoformat()})
            .eq("id", code_record["id"])
            .is_("verified_at", "null")
            .execute()
        )
    except APIError as exc:
        logger.exception("Supabase could not consume the customer sign-in code.")
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "finish sign-in")) from exc
    if not consumed.data:
        raise HTTPException(status_code=401, detail="That sign-in code has already been used. Request a new code.")
    return email


def load_customer_bookings(client: Client, email: str) -> list[dict]:
    try:
        response = (
            client.table("bookings")
            .select("*")
            .eq("email", email)
            .order("booking_date")
            .order("start_minute")
            .execute()
        )
    except APIError as exc:
        logger.exception("Supabase could not retrieve customer bookings.")
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "load your booking")) from exc
    return [booking_response(record) for record in response.data]


@app.post("/api/my/bookings/verify-email-code")
def customer_bookings(
    credentials: CustomerBookingLookup,
    client: Client = Depends(get_supabase),
) -> dict[str, object]:
    email = verify_customer_email_code(client, credentials.email, credentials.email_code)
    return {"session_token": customer_session_token(email)}


@app.post("/api/my/bookings/google")
def customer_bookings_google(
    credentials: CustomerGoogleLogin,
    client: Client = Depends(get_supabase),
) -> dict[str, object]:
    email = verify_google_id_token(credentials.credential)
    return {"session_token": customer_session_token(email)}


@app.get("/api/my/bookings")
def customer_bookings_for_session(
    authorization: Annotated[str | None, Header()] = None,
    client: Client = Depends(get_supabase),
) -> dict[str, list[dict]]:
    email = customer_session_email(authorization)
    return {"bookings": load_customer_bookings(client, email)}


@app.post("/api/my/bookings/{booking_id}/cancel")
def cancel_customer_booking(
    booking_id: int,
    authorization: Annotated[str | None, Header()] = None,
    client: Client = Depends(get_supabase),
) -> dict:
    email = customer_session_email(authorization)
    try:
        response = (
            client.table("bookings")
            .select("*")
            .eq("id", booking_id)
            .eq("email", email)
            .execute()
        )
    except APIError as exc:
        logger.exception("Supabase could not verify customer booking ownership.")
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "verify your booking")) from exc
    if not response.data:
        raise HTTPException(status_code=404, detail="We couldn't find a booking for that email address.")
    booking = response.data[0]
    if booking["status"] not in ("pending", "confirmed"):
        raise HTTPException(status_code=409, detail="This booking can no longer be cancelled online.")
    try:
        updated = (
            client.table("bookings")
            .update({"status": "cancelled"})
            .eq("id", booking_id)
            .eq("email", email)
            .in_("status", ["pending", "confirmed"])
            .execute()
        )
    except APIError as exc:
        logger.exception("Supabase could not cancel the customer booking.")
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "cancel your booking")) from exc
    if not updated.data:
        raise HTTPException(status_code=409, detail="This booking changed before it could be cancelled. Refresh and try again.")
    return booking_response(updated.data[0])


@app.get("/api/owner/bookings", dependencies=[Depends(require_owner)])
def owner_bookings(client: Client = Depends(get_supabase)) -> list[dict]:
    try:
        response = client.table("bookings").select("*").order("booking_date").order("start_minute").execute()
    except APIError as exc:
        logger.exception("Supabase could not retrieve owner bookings.")
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "load bookings")) from exc
    return [booking_response(record) for record in response.data]


@app.patch(
    "/api/owner/bookings/{booking_id}",
    dependencies=[Depends(require_owner)],
)
def update_booking(
    booking_id: int,
    update: BookingStatusUpdate,
    client: Client = Depends(get_supabase),
) -> dict:
    try:
        response = (
            client.table("bookings")
            .update({"status": update.status})
            .eq("id", booking_id)
            .execute()
        )
    except APIError as exc:
        logger.exception("Supabase could not update the booking.")
        raise HTTPException(status_code=503, detail=database_error_detail(exc, "update the booking")) from exc
    if not response.data:
        raise HTTPException(status_code=404, detail="Booking not found.")
    return booking_response(response.data[0])
