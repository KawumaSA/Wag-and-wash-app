import base64
import json
import os
import re
import unittest
from datetime import date, datetime
from hashlib import sha256
from unittest.mock import Mock, patch

import httpx
from fastapi import HTTPException
from fastapi.testclient import TestClient
from backend.app import (
    OPEN_MINUTE,
    SATURDAY_CLOSE_MINUTE,
    WEEKDAY_CLOSE_MINUTE,
    app,
    business_close,
    create_paypal_order,
    get_supabase,
    load_day_bookings,
    make_slots,
    send_email,
    verify_google_id_token,
)


class FakeResponse:
    def __init__(self, data):
        self.data = data


class FakeQuery:
    def __init__(self, client, table):
        self.client = client
        self.table_name = table
        self.operation = "select"
        self.filters = []
        self.null_filters = []
        self.greater_than = []
        self.statuses = None
        self.record = None
        self.maximum = None
        self.sort_column = None
        self.sort_descending = False

    def select(self, _columns):
        return self

    def eq(self, key, value):
        self.filters.append((key, value))
        return self

    def in_(self, key, values):
        self.statuses = (key, values)
        return self

    def gte(self, key, value):
        self.greater_than.append((key, value))
        return self

    def is_(self, key, value):
        self.null_filters.append((key, value))
        return self

    def insert(self, record):
        self.operation = "insert"
        self.record = record
        return self

    def update(self, record):
        self.operation = "update"
        self.record = record
        return self

    def order(self, column, desc=False):
        self.sort_column = column
        self.sort_descending = desc
        return self

    def limit(self, count):
        self.maximum = count
        return self

    def execute(self):
        records = self.client.tables.setdefault(self.table_name, [])
        if self.operation == "insert":
            created = {"id": len(records) + 1, **self.record}
            records.append(created)
            return FakeResponse([created])
        matching = [
            record for record in records
            if all(record.get(key) == value for key, value in self.filters)
            and (
                self.statuses is None
                or record.get(self.statuses[0]) in self.statuses[1]
            )
            and all(record.get(key, "") >= value for key, value in self.greater_than)
            and all(record.get(key) is None for key, value in self.null_filters if value == "null")
        ]
        if self.sort_column:
            matching.sort(key=lambda record: record.get(self.sort_column, ""), reverse=self.sort_descending)
        if self.maximum is not None:
            matching = matching[:self.maximum]
        if self.operation == "update":
            for record in matching:
                record.update(self.record)
        return FakeResponse(matching)


class FakeSupabase:
    def __init__(self):
        self.tables = {"bookings": []}

    @property
    def records(self):
        return self.tables["bookings"]

    def table(self, table):
        return FakeQuery(self, table)


class UnreachableSupabase:
    def table(self, _table):
        raise httpx.ConnectError("DNS lookup failed")


class BusinessHoursTests(unittest.TestCase):
    def test_weekday_hours_and_service_duration(self):
        monday = date(2026, 10, 5)
        before_business_day = datetime(2026, 10, 4, 8)

        self.assertEqual(business_close(monday), WEEKDAY_CLOSE_MINUTE)
        self.assertEqual(make_slots(monday, 60, before_business_day)[0], OPEN_MINUTE)
        self.assertEqual(make_slots(monday, 60, before_business_day)[-1], 18 * 60)
        self.assertEqual(make_slots(monday, 120, before_business_day)[-1], 17 * 60)

    def test_saturday_closes_at_four_and_sunday_is_closed(self):
        saturday = date(2026, 10, 10)
        sunday = date(2026, 10, 11)
        before_business_day = datetime(2026, 10, 4, 8)

        self.assertEqual(business_close(saturday), SATURDAY_CLOSE_MINUTE)
        self.assertEqual(make_slots(saturday, 30, before_business_day)[-1], 15 * 60 + 30)
        self.assertIsNone(business_close(sunday))
        self.assertEqual(make_slots(sunday, 30, before_business_day), [])

    def test_today_slots_must_start_in_the_future(self):
        monday = date(2026, 10, 5)
        now = datetime(2026, 10, 5, 9, 30)

        self.assertEqual(make_slots(monday, 30, now)[0], 10 * 60)


class BookingApiTests(unittest.TestCase):
    def setUp(self):
        self.database = FakeSupabase()
        app.dependency_overrides[get_supabase] = lambda: self.database
        self.environment = patch.dict(
            "os.environ",
            {
                "SUPABASE_URL": "https://example.supabase.co",
                "SUPABASE_SERVICE_ROLE_KEY": "test-server-key",
                "OWNER_EMAIL": "jess@example.com",
                "OWNER_PASSWORD": "jess-pass",
                "OWNER_SESSION_SECRET": "test-owner-session-secret-at-least-32-chars",
                "CUSTOMER_CODE_HASH_SECRET": "test-email-hash-secret",
                "GOOGLE_CLIENT_ID": "test-google-client-id",
                "PAYPAL_CLIENT_ID": "test-paypal-client-id",
                "PAYPAL_CLIENT_SECRET": "test-paypal-client-secret",
                "PAYPAL_WEBHOOK_ID": "test-paypal-webhook-id",
                "PAYPAL_MODE": "sandbox",
            },
        )
        self.environment.start()
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()
        app.dependency_overrides.clear()
        self.environment.stop()

    def owner_headers(self):
        response = self.client.post(
            "/api/owner/login",
            json={"email": "jess@example.com", "password": "jess-pass"},
        )
        self.assertEqual(response.status_code, 200)
        return {"Authorization": f"Bearer {response.json()['session_token']}"}

    def test_owner_login_requires_configured_email_and_password(self):
        wrong_email = self.client.post(
            "/api/owner/login",
            json={"email": "someone@example.com", "password": "jess-pass"},
        )
        wrong_password = self.client.post(
            "/api/owner/login",
            json={"email": "jess@example.com", "password": "wrong"},
        )

        self.assertEqual(wrong_email.status_code, 401)
        self.assertEqual(wrong_password.status_code, 401)
        self.assertEqual(wrong_email.json()["detail"], wrong_password.json()["detail"])

    def test_owner_login_returns_session_for_configured_credentials(self):
        response = self.client.post(
            "/api/owner/login",
            json={"email": " JESS@example.com ", "password": "jess-pass"},
        )

        self.assertEqual(response.status_code, 200)
        token = response.json()["session_token"]
        self.assertTrue(token)
        payload = token.split(".", 1)[0]
        payload += "=" * (-len(payload) % 4)
        session = json.loads(base64.urlsafe_b64decode(payload))
        self.assertNotIn("expires", session)

    def test_owner_login_is_disabled_without_private_configuration(self):
        with patch.dict(
            "os.environ",
            {"OWNER_EMAIL": "", "OWNER_PASSWORD": "", "OWNER_SESSION_SECRET": ""},
        ):
            response = self.client.post(
                "/api/owner/login",
                json={"email": "jess@example.com", "password": "jess-pass"},
            )

        self.assertEqual(response.status_code, 503)

    def test_homepage_is_served_from_app_folder(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("<title>Wag & Wash</title>", response.text)
        self.assertIn('id="owner-email"', response.text)
        self.assertIn('id="owner-password"', response.text)
        self.assertIn('id="google-signin-container"', response.text)
        self.assertNotIn("Owner API token", response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_availability_uses_service_duration_and_saved_bookings(self):
        self.database.records.append(
            {
                "id": 1,
                "booking_date": "2026-10-06",
                "start_minute": 540,
                "service_duration_min": 120,
                "status": "confirmed",
            }
        )

        response = self.client.get(
            "/api/availability",
            params={"date": "2026-10-06", "serviceId": "nails"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(540, response.json()["slots"])
        self.assertNotIn(570, response.json()["slots"])
        self.assertIn(660, response.json()["slots"])

    def test_health_check_confirms_database_access(self):
        response = self.client.get("/api/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["supabase"], "connected")

    def test_health_check_reports_supabase_connection_failure(self):
        app.dependency_overrides[get_supabase] = UnreachableSupabase

        response = self.client.get("/api/health")

        self.assertEqual(response.status_code, 503)
        self.assertIn("network/DNS", response.json()["detail"])

    def test_smtp_email_uses_configured_sender_and_tls_connection(self):
        with patch.dict(
            "os.environ",
            {
                "SMTP_HOST": "smtp.example.com",
                "SMTP_PORT": "465",
                "SMTP_USE_SSL": "true",
                "SMTP_USERNAME": "mailer",
                "SMTP_PASSWORD": "password",
                "SMTP_FROM_EMAIL": "bookings@example.com",
            },
        ):
            with patch("backend.app.smtplib.SMTP_SSL") as smtp_ssl:
                smtp = smtp_ssl.return_value.__enter__.return_value
                send_email("customer@example.com", "Test subject", "Test body")

        smtp_ssl.assert_called_once()
        message = smtp.send_message.call_args.args[0]
        self.assertEqual(message["To"], "customer@example.com")
        self.assertEqual(message["From"], "bookings@example.com")
        self.assertEqual(message["Subject"], "Test subject")

    def test_booking_is_saved_and_booking_code_is_sent_by_email(self):
        send_email = Mock()
        with patch("backend.app.send_email", send_email):
            response = self.client.post(
                "/api/bookings",
                json={
                    "booking_date": "2026-10-06",
                    "start_minute": 600,
                    "service_id": "bath",
                    "name": " Customer ",
                    "email": "Customer@example.com",
                    "dog": " Pup ",
                    "booking_email_consent": True,
                },
            )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["status"], "pending")
        self.assertEqual(response.json()["email"], "customer@example.com")
        self.assertTrue(response.json()["email_sent"])
        self.assertEqual(self.database.records[0]["service_price"], 45)
        self.assertEqual(self.database.records[0]["paid"], 0)
        self.assertNotIn("access_code_hash", response.json())
        self.assertEqual(
            self.database.records[0]["access_code_hash"],
            sha256(response.json()["access_code"].encode()).hexdigest(),
        )
        self.assertIn(response.json()["access_code"], send_email.call_args.args[2])

    def test_customer_can_use_one_time_email_code_to_find_bookings(self):
        created = self.client.post(
            "/api/bookings",
            json={
                "booking_date": "2026-10-06",
                "start_minute": 600,
                "service_id": "bath",
                "name": "Customer",
                "email": "customer@example.com",
                "dog": "Pup",
                "booking_email_consent": True,
            },
        ).json()
        self.database.records.append(
            {
                "id": created["id"] + 1,
                "booking_date": "2026-10-07",
                "start_minute": 600,
                "service_id": "bath",
                "service_duration_min": 60,
                "service_price": 45,
                "name": "Other Customer",
                "phone": "",
                "email": "other@example.com",
                "dog": "Other Pup",
                "breed": "",
                "notes": "",
                "sms_consent": False,
                "status": "pending",
                "deposit_amount": 25,
                "paid": 0,
                "refunded": False,
            }
        )
        send_email = Mock()
        with patch("backend.app.send_email", send_email):
            sent = self.client.post(
                "/api/my/bookings/send-email-code",
                json={"email": " Customer@example.com "},
            )
        code = re.search(r"\b(\d{6})\b", send_email.call_args.args[2]).group(1)
        result = self.client.post(
            "/api/my/bookings/verify-email-code",
            json={"email": "customer@example.com", "email_code": code},
        )

        self.assertEqual(sent.status_code, 200)
        self.assertEqual(result.status_code, 200)
        self.assertNotIn("bookings", result.json())
        self.assertTrue(result.json()["session_token"])
        self.assertTrue(self.database.tables["customer_email_verification_codes"][0]["verified_at"])
        self.assertNotEqual(self.database.tables["customer_email_verification_codes"][0]["code_hash"], code)
        bookings = self.client.get(
            "/api/my/bookings",
            headers={"Authorization": f"Bearer {result.json()['session_token']}"},
        )
        self.assertEqual([booking["id"] for booking in bookings.json()["bookings"]], [created["id"]])
        self.assertNotIn("access_code_hash", bookings.json()["bookings"][0])
        other_customer_booking = self.client.post(
            f"/api/my/bookings/{created['id'] + 1}/cancel",
            headers={"Authorization": f"Bearer {result.json()['session_token']}"},
        )
        self.assertEqual(other_customer_booking.status_code, 404)
        self.assertEqual(self.database.records[1]["status"], "pending")

        reused = self.client.post(
            "/api/my/bookings/verify-email-code",
            json={"email": "customer@example.com", "email_code": code},
        )
        self.assertEqual(reused.status_code, 401)

    def test_public_config_exposes_only_google_client_id(self):
        response = self.client.get("/api/public-config")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "google_client_id": "test-google-client-id",
                "paypal_client_id": "test-paypal-client-id",
                "paypal_currency": "USD",
            },
        )

    def test_checkout_requires_the_booking_private_code_and_uses_server_deposit(self):
        with patch("backend.app.send_email"):
            booking = self.client.post(
                "/api/bookings",
                json={
                    "booking_date": "2026-10-06",
                    "start_minute": 600,
                    "service_id": "bath",
                    "name": "Customer",
                    "email": "customer@example.com",
                    "dog": "Pup",
                    "booking_email_consent": True,
                },
            ).json()
        wrong_code = self.client.post(
            f"/api/bookings/{booking['id']}/checkout",
            json={"access_code": "not-the-booking-code"},
        )

        with patch("backend.app.create_paypal_order", return_value="ORDER-123") as create_order:
            checkout = self.client.post(
                f"/api/bookings/{booking['id']}/checkout",
                json={"access_code": booking["access_code"]},
            )

        self.assertEqual(wrong_code.status_code, 401)
        self.assertEqual(checkout.status_code, 200)
        self.assertEqual(checkout.json(), {"order_id": "ORDER-123"})
        self.assertEqual(create_order.call_args.args[0]["deposit_amount"], 25)
        self.assertEqual(self.database.records[0]["payment_status"], "pending")
        self.assertEqual(self.database.records[0]["paypal_order_id"], "ORDER-123")

    def test_paypal_order_uses_the_fixed_usd_deposit(self):
        booking = {"id": 7, "dog": "Pup", "deposit_amount": 25}
        with patch("backend.app.paypal_api_request", return_value={"id": "ORDER-123"}) as api_request:
            order_id = create_paypal_order(booking)

        self.assertEqual(order_id, "ORDER-123")
        payload = api_request.call_args.args[2]
        self.assertEqual(payload["intent"], "CAPTURE")
        self.assertEqual(
            payload["purchase_units"][0]["amount"],
            {"currency_code": "USD", "value": "25.00"},
        )

    def test_completed_paypal_capture_confirms_booking(self):
        with patch("backend.app.send_email"):
            booking = self.client.post(
                "/api/bookings",
                json={
                    "booking_date": "2026-10-06",
                    "start_minute": 600,
                    "service_id": "bath",
                    "name": "Customer",
                    "email": "customer@example.com",
                    "dog": "Pup",
                    "booking_email_consent": True,
                },
            ).json()
        with patch("backend.app.create_paypal_order", return_value="ORDER-123"):
            checkout = self.client.post(
                f"/api/bookings/{booking['id']}/checkout",
                json={"access_code": booking["access_code"]},
            )
        invalid_code = self.client.post(
            f"/api/bookings/{booking['id']}/capture",
            json={"order_id": checkout.json()["order_id"], "access_code": "wrong-code"},
        )
        capture = {
            "id": "CAPTURE-123",
            "status": "COMPLETED",
            "amount": {"currency_code": "USD", "value": "25.00"},
        }
        with patch("backend.app.send_email") as confirmation_email, patch(
            "backend.app.paypal_api_request",
            return_value={"purchase_units": [{"payments": {"captures": [capture]}}]},
        ):
            response = self.client.post(
                f"/api/bookings/{booking['id']}/capture",
                json={"order_id": checkout.json()["order_id"], "access_code": booking["access_code"]},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(invalid_code.status_code, 401)
        self.assertEqual(response.json()["booking"]["status"], "confirmed")
        self.assertEqual(response.json()["booking"]["payment_status"], "paid")
        self.assertEqual(response.json()["booking"]["paid"], 25)
        confirmation_email.assert_called_once()
        self.assertTrue(self.database.records[0]["payment_confirmation_email_sent"])

    def test_capture_with_wrong_currency_or_amount_does_not_confirm_booking(self):
        with patch("backend.app.send_email"):
            booking = self.client.post(
                "/api/bookings",
                json={
                    "booking_date": "2026-10-06",
                    "start_minute": 600,
                    "service_id": "bath",
                    "name": "Customer",
                    "email": "customer@example.com",
                    "dog": "Pup",
                    "booking_email_consent": True,
                },
            ).json()
        with patch("backend.app.create_paypal_order", return_value="ORDER-123"):
            checkout = self.client.post(
                f"/api/bookings/{booking['id']}/checkout",
                json={"access_code": booking["access_code"]},
            )
        wrong_capture = {
            "id": "CAPTURE-123",
            "status": "COMPLETED",
            "amount": {"currency_code": "USD", "value": "85.00"},
        }
        with patch(
            "backend.app.paypal_api_request",
            return_value={"purchase_units": [{"payments": {"captures": [wrong_capture]}}]},
        ):
            response = self.client.post(
                f"/api/bookings/{booking['id']}/capture",
                json={"order_id": checkout.json()["order_id"], "access_code": booking["access_code"]},
            )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.database.records[0]["status"], "pending")
        self.assertEqual(self.database.records[0]["payment_status"], "pending")

    def test_paypal_webhook_is_idempotent_and_confirms_booking(self):
        with patch("backend.app.send_email"):
            booking = self.client.post(
                "/api/bookings",
                json={
                    "booking_date": "2026-10-06",
                    "start_minute": 600,
                    "service_id": "bath",
                    "name": "Customer",
                    "email": "customer@example.com",
                    "dog": "Pup",
                    "booking_email_consent": True,
                },
            ).json()
        with patch("backend.app.create_paypal_order", return_value="ORDER-123"):
            self.client.post(
                f"/api/bookings/{booking['id']}/checkout",
                json={"access_code": booking["access_code"]},
            )
        event = {
            "event_type": "PAYMENT.CAPTURE.COMPLETED",
            "resource": {
                "id": "CAPTURE-123",
                "status": "COMPLETED",
                "amount": {"currency_code": "USD", "value": "25.00"},
                "supplementary_data": {"related_ids": {"order_id": "ORDER-123"}},
            },
        }
        with patch("backend.app.verify_paypal_webhook", return_value=True), patch(
            "backend.app.send_email"
        ) as confirmation_email:
            first = self.client.post("/api/payments/paypal/webhook", json=event)
            repeated = self.client.post("/api/payments/paypal/webhook", json=event)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(repeated.status_code, 200)
        self.assertEqual(self.database.records[0]["payment_status"], "paid")
        self.assertEqual(self.database.records[0]["status"], "confirmed")
        confirmation_email.assert_called_once()

    def test_late_completed_capture_is_refunded_and_releases_the_slot(self):
        with patch("backend.app.send_email"):
            booking = self.client.post(
                "/api/bookings",
                json={
                    "booking_date": "2026-10-06",
                    "start_minute": 600,
                    "service_id": "bath",
                    "name": "Customer",
                    "email": "customer@example.com",
                    "dog": "Pup",
                    "booking_email_consent": True,
                },
            ).json()
        with patch("backend.app.create_paypal_order", return_value="ORDER-123"):
            self.client.post(
                f"/api/bookings/{booking['id']}/checkout",
                json={"access_code": booking["access_code"]},
            )
        self.database.records[0]["payment_expires_at"] = "2000-01-01T00:00:00+00:00"
        event = {
            "event_type": "PAYMENT.CAPTURE.COMPLETED",
            "resource": {
                "id": "CAPTURE-LATE",
                "status": "COMPLETED",
                "amount": {"currency_code": "USD", "value": "25.00"},
                "supplementary_data": {"related_ids": {"order_id": "ORDER-123"}},
            },
        }
        with patch("backend.app.verify_paypal_webhook", return_value=True), patch(
            "backend.app.paypal_api_request", return_value={"status": "COMPLETED"}
        ) as refund:
            response = self.client.post("/api/payments/paypal/webhook", json=event)

        self.assertEqual(response.status_code, 200)
        self.assertIn("/v2/payments/captures/CAPTURE-LATE/refund", refund.call_args.args[1])
        self.assertEqual(self.database.records[0]["status"], "cancelled")
        self.assertEqual(self.database.records[0]["payment_status"], "refunded")
        self.assertTrue(self.database.records[0]["refunded"])

    def test_invalid_paypal_webhook_signature_is_rejected(self):
        with patch("backend.app.verify_paypal_webhook", return_value=False):
            response = self.client.post(
                "/api/payments/paypal/webhook",
                json={"event_type": "PAYMENT.CAPTURE.COMPLETED", "resource": {}},
            )

        self.assertEqual(response.status_code, 400)

    def test_expired_payment_reservation_releases_appointment_slot(self):
        self.database.records.append(
            {
                "id": 1,
                "booking_date": "2026-10-06",
                "start_minute": 600,
                "service_duration_min": 60,
                "status": "pending",
                "payment_status": "unpaid",
                "payment_expires_at": "2000-01-01T00:00:00+00:00",
            }
        )

        bookings = load_day_bookings(self.database, date(2026, 10, 6))

        self.assertEqual(bookings, [])
        self.assertEqual(self.database.records[0]["status"], "cancelled")
        self.assertEqual(self.database.records[0]["payment_status"], "expired")

    def test_google_id_token_verification_checks_audience_and_verified_email(self):
        with patch(
            "backend.app.id_token.verify_oauth2_token",
            return_value={"email": " Customer@example.com ", "email_verified": True},
        ) as verify_token:
            email = verify_google_id_token("token")

        self.assertEqual(email, "customer@example.com")
        self.assertEqual(verify_token.call_args.args[0], "token")
        self.assertEqual(verify_token.call_args.args[2], "test-google-client-id")

        with patch(
            "backend.app.id_token.verify_oauth2_token",
            return_value={"email": "customer@example.com", "email_verified": False},
        ):
            response = self.client.post(
                "/api/my/bookings/google",
                json={"credential": "unverified-google-token"},
            )

        self.assertEqual(response.status_code, 401)

    def test_customer_can_sign_in_with_verified_google_email(self):
        self.database.records.append(
            {
                "id": 1,
                "booking_date": "2026-10-06",
                "start_minute": 600,
                "service_id": "bath",
                "service_duration_min": 60,
                "service_price": 45,
                "name": "Customer",
                "phone": "",
                "email": "customer@example.com",
                "dog": "Pup",
                "breed": "",
                "notes": "",
                "sms_consent": False,
                "status": "pending",
                "deposit_amount": 25,
                "paid": 0,
                "refunded": False,
            }
        )
        self.database.records.append(
            {
                "id": 2,
                "booking_date": "2026-10-07",
                "start_minute": 600,
                "service_id": "bath",
                "service_duration_min": 60,
                "service_price": 45,
                "name": "Other Customer",
                "phone": "",
                "email": "other@example.com",
                "dog": "Other Pup",
                "breed": "",
                "notes": "",
                "sms_consent": False,
                "status": "pending",
                "deposit_amount": 25,
                "paid": 0,
                "refunded": False,
            }
        )
        with patch("backend.app.verify_google_id_token", return_value="customer@example.com"):
            response = self.client.post(
                "/api/my/bookings/google",
                json={"credential": "verified-google-token"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("bookings", response.json())
        self.assertTrue(response.json()["session_token"])
        bookings = self.client.get(
            "/api/my/bookings",
            headers={"Authorization": f"Bearer {response.json()['session_token']}"},
        )
        self.assertEqual([booking["id"] for booking in bookings.json()["bookings"]], [1])

    def test_google_sign_in_without_bookings_returns_empty_own_booking_list(self):
        with patch("backend.app.verify_google_id_token", return_value="customer@example.com"):
            response = self.client.post(
                "/api/my/bookings/google",
                json={"credential": "verified-google-token"},
            )

        self.assertEqual(response.status_code, 200)
        bookings = self.client.get(
            "/api/my/bookings",
            headers={"Authorization": f"Bearer {response.json()['session_token']}"},
        )
        self.assertEqual(bookings.status_code, 200)
        self.assertEqual(bookings.json()["bookings"], [])

    def test_login_code_is_rate_limited_and_bad_codes_count_as_attempts(self):
        self.database.records.append({"id": 1, "email": "customer@example.com"})
        send_email = Mock()
        with patch("backend.app.send_email", send_email):
            for _ in range(3):
                self.assertEqual(
                    self.client.post("/api/my/bookings/send-email-code", json={"email": "customer@example.com"}).status_code,
                    200,
                )
            limited = self.client.post("/api/my/bookings/send-email-code", json={"email": "customer@example.com"})
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(send_email.call_count, 3)

        bad = self.client.post(
            "/api/my/bookings/verify-email-code",
            json={"email": "customer@example.com", "email_code": "000000"},
        )
        self.assertEqual(bad.status_code, 401)
        self.assertEqual(
            sum(record["attempts"] for record in self.database.tables["customer_email_verification_codes"]),
            1,
        )

    def test_booking_requires_transactional_email_consent(self):
        response = self.client.post(
            "/api/bookings",
            json={
                "booking_date": "2026-10-06",
                "start_minute": 600,
                "service_id": "bath",
                "name": "Customer",
                "email": "customer@example.com",
                "dog": "Pup",
                "booking_email_consent": False,
            },
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(self.database.records, [])

    def test_booking_is_preserved_when_confirmation_email_fails(self):
        with patch("backend.app.send_email", side_effect=HTTPException(status_code=503, detail="Email is not configured.")):
            response = self.client.post(
                "/api/bookings",
                json={
                    "booking_date": "2026-10-06",
                    "start_minute": 600,
                    "service_id": "bath",
                    "name": "Customer",
                    "email": "customer@example.com",
                    "dog": "Pup",
                    "booking_email_consent": True,
                },
            )

        self.assertEqual(response.status_code, 201)
        self.assertFalse(response.json()["email_sent"])
        self.assertTrue(response.json()["access_code"])
        self.assertEqual(len(self.database.records), 1)

    def test_customer_can_cancel_only_their_own_active_booking(self):
        response = self.client.post(
            "/api/bookings",
            json={
                "booking_date": "2026-10-06",
                "start_minute": 600,
                "service_id": "bath",
                "name": "Customer",
                "email": "customer@example.com",
                "dog": "Pup",
                "booking_email_consent": True,
            },
        )
        created = response.json()
        send_email = Mock()
        with patch("backend.app.send_email", send_email):
            self.client.post("/api/my/bookings/send-email-code", json={"email": "customer@example.com"})
        code = re.search(r"\b(\d{6})\b", send_email.call_args.args[2]).group(1)
        login = self.client.post(
            "/api/my/bookings/verify-email-code",
            json={"email": "customer@example.com", "email_code": code},
        )
        self.assertEqual(login.status_code, 200)
        token = login.json()["session_token"]

        response = self.client.post(
            f"/api/my/bookings/{created['id']}/cancel",
            headers={"Authorization": f"Bearer {token}"},
        )
        repeated = self.client.post(
            f"/api/my/bookings/{created['id']}/cancel",
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "cancelled")
        self.assertEqual(repeated.status_code, 409)

    def test_customer_session_token_is_required_to_cancel(self):
        response = self.client.post(
            f"/api/my/bookings/1/cancel",
            headers={"Authorization": "Bearer forged.token"},
        )
        self.assertEqual(response.status_code, 401)

    def test_customer_session_token_is_required_to_list_bookings(self):
        response = self.client.get("/api/my/bookings")

        self.assertEqual(response.status_code, 401)

    def test_overlapping_booking_is_rejected(self):
        self.database.records.append(
            {
                "id": 1,
                "booking_date": "2026-10-06",
                "start_minute": 540,
                "service_duration_min": 120,
                "status": "confirmed",
            }
        )

        response = self.client.post(
            "/api/bookings",
            json={
                "booking_date": "2026-10-06",
                "start_minute": 600,
                "service_id": "nails",
                "name": "Customer",
                "email": "customer@example.com",
                "dog": "Pup",
                "booking_email_consent": True,
            },
        )

        self.assertEqual(response.status_code, 409)

    def test_owner_bookings_requires_owner_session(self):
        unauthorized = self.client.get("/api/owner/bookings")
        authorized = self.client.get("/api/owner/bookings", headers=self.owner_headers())
        invalid = self.client.get(
            "/api/owner/bookings",
            headers={"Authorization": "Bearer invalid"},
        )

        self.assertEqual(unauthorized.status_code, 401)
        self.assertEqual(authorized.status_code, 200)
        self.assertEqual(invalid.status_code, 401)

    def test_owner_bookings_reports_supabase_connection_failure(self):
        app.dependency_overrides[get_supabase] = UnreachableSupabase

        response = self.client.get(
            "/api/owner/bookings",
            headers=self.owner_headers(),
        )

        self.assertEqual(response.status_code, 503)
        self.assertIn("network/DNS", response.json()["detail"])

if __name__ == "__main__":
    unittest.main()
