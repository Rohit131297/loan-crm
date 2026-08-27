# Loan CRM v4.0

Loan CRM with a server-side central database, leads, dashboard, disbursement and connector payout/payment tracking.

## What is included
- Username + password login
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

## Login
Mobile OTP login has been removed.

Set these environment variables before deployment:

```env
JWT_SECRET=use-a-long-random-secret
ADMIN_USERNAME=admin
ADMIN_PASSWORD=use-a-strong-password
```

If `ADMIN_USERNAME` and `ADMIN_PASSWORD` are not set, the development defaults are `admin` / `admin123`. Change them for production.

## Run
1. Install Node.js 20+.
2. Copy `.env.example` to `.env`.
3. Run `npm install`.
4. Run `npm start`.
5. Open `http://localhost:3000`.

The database file `loancrm.sqlite` is created automatically.

## Production
Deploy the Node server on a hosting service and use a managed database for production scale. Do not expose the SQLite file publicly. Set a strong JWT_SECRET and use HTTPS.
