# Wag & Wash

## Run the Supabase-backed app locally

1. Create and activate the project virtual environment in PowerShell:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

2. Install the Python dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

3. Edit the local `.env` file (or copy `.env.example` to `.env` if it is
   missing). In the Supabase project dashboard, copy the project URL and
   server-side service-role key into `SUPABASE_URL` and
   `SUPABASE_SERVICE_ROLE_KEY`. Configure Jess's private `OWNER_EMAIL` and
   `OWNER_PASSWORD`, and set `OWNER_SESSION_SECRET` and
   `CUSTOMER_CODE_HASH_SECRET` to separate random secrets at least 32 characters
   long. Use a unique owner password. Never put credentials in the HTML or
   commit `.env`.

4. In the Supabase dashboard's SQL Editor, run [`supabase/schema.sql`](./supabase/schema.sql).
   It creates or upgrades the bookings table, enables row-level security,
   prevents overlapping pending or confirmed appointments, and adds booking
   email, payment tracking, and short-lived email verification-code storage. Re-run
   this file after updating the app.

5. To enable email, configure your email provider's SMTP settings in `.env`:

   - Set `SMTP_HOST`, `SMTP_PORT`, and `SMTP_USE_SSL` using the provider's SMTP
     instructions. Port 465 commonly uses SSL; port 587 commonly uses STARTTLS
     (`SMTP_USE_SSL=false`).
   - Set `SMTP_USERNAME`, `SMTP_PASSWORD`, and `SMTP_FROM_EMAIL`. Some providers
     require an app-specific password or verified sender address.

   Keep email credentials server-side and out of chat, HTML, and source control.
   The booking confirmation email includes the private booking code. **My
   bookings** uses a separate six-digit code that expires in 10 minutes; after
   verification, a signed customer session remains valid for 30 minutes in the
   current page only. Login codes are hashed in Supabase, single-use, limited
   to three sends per email in 15 minutes, and allow at most five verification
   attempts. If a booking email cannot be delivered, the booking is still saved
   and the private code remains visible on the confirmation page.

   To enable Google sign-in on the public **My bookings** page, create a Google
   OAuth client ID for a Web application. Add your deployed website origin and
   local development origin (for example, `http://127.0.0.1:8001`) to its
   authorized JavaScript origins, then set `GOOGLE_CLIENT_ID` in `.env`.
   Google sign-in verifies the account with Google and only displays bookings
   associated with that verified email address. Email-code sign-in remains
   available as an alternative.

6. To enable online deposits, create a PayPal Business app in the PayPal
   Developer Dashboard. Copy its client ID and secret to `PAYPAL_CLIENT_ID` and
   `PAYPAL_CLIENT_SECRET` in `.env`. Start in sandbox mode with
   `PAYPAL_MODE=sandbox` and test using PayPal sandbox buyer credentials.
   Register a webhook at
   `https://your-domain.example/api/payments/paypal/webhook` for the
   `PAYMENT.CAPTURE.COMPLETED` event and set the webhook ID in
   `PAYPAL_WEBHOOK_ID`. For production, configure the live app credentials,
   register the production webhook, and set `PAYPAL_MODE=live`.

   Checkout uses PayPal's hosted SDK for the existing $25 USD deposit and
   enables its card funding button. Eligible customers can pay with PayPal or
   debit/credit cards, including Visa where supported, and regionally available
   PayPal methods. Card availability depends on PayPal account and buyer
   eligibility. The remaining service balance is due at pickup. An
   appointment is held for 30 minutes and becomes confirmed only after the
   server verifies a completed PayPal capture or signed webhook. Unpaid
   reservations expire and release their appointment slot. Payment credentials
   stay server-side; the app never handles or stores card numbers. A captured
   payment arriving after its reservation expires is automatically refunded.
   Customer cancellations do not automatically refund a paid deposit. Test
   payment confirmation and expired-reservation refunds in sandbox before
   enabling live payments.

7. Run the frontend JavaScript syntax check with Node.js:

   ```powershell
   npm.cmd run check:frontend
   ```

   Node.js is used for frontend development checks; it does not serve the
   website or handle bookings. FastAPI serves the page and API from one origin.

8. Start the app:

   ```powershell
   .\.venv\Scripts\python.exe -m uvicorn backend.app:app --reload --port 8001
   ```

   Open <http://127.0.0.1:8001>. The website HTML is in `app/` and is served by
   this API so its booking requests use the same origin.

Restart the server after changing `.env`.

The public API provides availability checks and booking requests. Jess signs in
to her dashboard with `OWNER_EMAIL` and `OWNER_PASSWORD` from `.env`. There is
no public owner sign-up. Her signed-in session is kept in memory only; refreshing
or closing the page signs her out. Changing `OWNER_SESSION_SECRET` invalidates
previously issued sessions. Check the Supabase connection at
<http://127.0.0.1:8001/api/health>.
If a Supabase network/DNS failure occurs, the API returns HTTP 503; verify
`SUPABASE_URL` and that this computer can reach the internet.

New requests are reserved as `pending` and become `confirmed` after the $25
deposit is verified by PayPal. Customers must consent to a booking email before
submitting. The booking code is stored as a SHA-256 hash and cannot be recovered
if lost. Customers sign in to **My bookings** with
a one-time email code sent to the address entered at booking, or with Google.
The booking list is loaded through a signed customer session and filtered to
the verified email address, so customers only see bookings for their own
account. Bookings made
before email support was added do not yet have an email address and will not
appear in email-based **My bookings**.
