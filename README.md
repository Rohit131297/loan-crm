# Loan CRM v4.0 – OTP + Central Database

This version adds a real server-side central database and OTP authentication API to the CRM.

## What is included
- Mobile-number OTP login
- OTP verification
- JWT session
- Central SQLite database on the server
- Leads shared across browsers/devices
- Lead status: New, Login, Sanction, Disbursed, Rejected
- Loan Amount, Sanction Amount, Actual Disbursement Amount
- Loan Account Number
- Clickable lead fields / Update Lead
- Dashboard counts and amount totals
- Payout + Connector Payment in one module
- Payment records and pending/paid status
- Payment receipt generation remains in the browser

## Important
`OTP_MODE=console` is for testing: the OTP is printed in the server console. It does NOT send SMS.

For real SMS OTP, use a compliant SMS provider such as Twilio and set `OTP_MODE=twilio` plus the credentials in `.env`.

## Run
1. Install Node.js 20+.
2. Copy `.env.example` to `.env`.
3. Run `npm install`.
4. Run `npm start`.
5. Open `http://localhost:3000`.

The database file `loancrm.sqlite` is created automatically.

## Production
Deploy the Node server on a hosting service and use a managed database for production scale. Do not expose the SQLite file publicly. Set a strong JWT_SECRET and use HTTPS.


## IMPORTANT: Persistent Leads
Leads are stored in PostgreSQL using the `DATABASE_URL` environment variable.
For Render + Supabase, set `DATABASE_URL` to the Supabase PostgreSQL connection string.
Do NOT use SQLite or an in-memory/local browser store for production.
Logout only removes the JWT session token; it does not delete leads.
The frontend also no longer logs the user out automatically on temporary database/network errors.
