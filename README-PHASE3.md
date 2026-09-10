# JajiGo Phase 3 — Real Marketplace Data + Secure Orders

This phase keeps the existing JajiGo UI and moves the core marketplace flow onto the PostgreSQL backend when `JAJIGO_MARKETPLACE_API` is configured.

## Included
- Backend-backed provider/product catalog loading.
- Provider product create, edit, availability toggle and delete APIs.
- Provider order-status updates through the backend.
- Customer checkout creates orders through the backend.
- Server-side product price validation and stock locking/decrement.
- Server-side delivery-fee calculation.
- Server-side commission configuration (`COMMISSION_RATE`, `COMMISSION_ON_DELIVERY`).
- Customer bootstrap is scoped to the logged-in customer; admin can see all customers/orders.
- Provider bootstrap returns only that provider's orders.

## Database update
Run the full `schema.sql` against PostgreSQL. It contains a safe `ALTER TABLE ... ADD COLUMN IF NOT EXISTS icon` for databases created in Phase 1.

## Render environment
Set:
- `DATABASE_URL`
- `JWT_SECRET`
- `CORS_ORIGINS`
- `COMMISSION_RATE=10`
- `COMMISSION_ON_DELIVERY=0`

## Frontend connection
After deploying the marketplace backend, configure the HTML once in the browser console:

`setJajiGoMarketplaceAPI('https://YOUR-MARKETPLACE-BACKEND-URL')`

Gemini remains a separate service configured by the existing AI bridge.

## Important
The backend must contain approved providers and products before customers can shop. Existing browser-local demo data is not automatically inserted into PostgreSQL.

Next production phases should add real payment verification, realtime notifications, rider/delivery workflows, OTP/password recovery, and stronger session/security controls.
