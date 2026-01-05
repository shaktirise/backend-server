# juststock Backend

Node.js/Express API with MongoDB, JWT auth, wallet tracking, and Socket.IO streaming. The backend now exposes production-safe defaults for Render and is ready for a Flutter client (mobile or web).

## Prerequisites

- Node.js 20+
- MongoDB instance (local or Atlas)
- Twilio credentials (optional; used for OTP SMS)

## Environment Variables

Copy `.env.example` to `.env` and fill in the values:

| Key | Description |
| --- | --- |
| PORT, HOST | Listening interface/port. Render injects PORT automatically. |
| CORS_ALLOWED_ORIGINS | Comma-separated HTTP origins. Leave empty for dev/mobile clients. |
| SOCKET_ALLOWED_ORIGINS | Optional override for Socket.IO origins. |
| RATE_LIMIT_WINDOW_MS / RATE_LIMIT_MAX | HTTP rate limiting configuration. |
| MONGODB_URI | MongoDB connection string. |
| JWT_SECRET | Secret used to sign access tokens. |
| OTP_EXP_MIN | Minutes before OTP expires. |
| ADMIN_OTP_EXP_MIN | Override admin OTP expiry minutes (defaults to `OTP_EXP_MIN`). |
| ADMIN_OTP_ALLOWED_PHONES | Optional comma-separated allowlist of admin phones (E.164, e.g. `+911234567890`). |
| ADMIN_SIGNUP_TOKEN | Bootstrap token for admin registration endpoint. |
| MONGOOSE_DEBUG | Set to `1` to enable query logging. |
| APP_TIMEZONE | Timezone ID for API-formatted timestamps (default `Asia/Kolkata`). |
| TWILIO_* | Twilio credentials for real SMS sending. Leave blank to log codes locally. |
| CLOUDINARY_URL | Alternative single var: `cloudinary://<api_key>:<api_secret>@<cloud_name>` |
| CLOUDINARY_CLOUD_NAME | Cloudinary cloud name for uploads. (Used if `CLOUDINARY_URL` not set) |
| CLOUDINARY_API_KEY | Cloudinary API key. (Used if `CLOUDINARY_URL` not set) |
| CLOUDINARY_API_SECRET | Cloudinary API secret (server-side signing). (Used if `CLOUDINARY_URL` not set) |
| CLOUDINARY_UPLOAD_FOLDER | Optional default folder for uploads (e.g. `admin-uploads`). |

### Referral (MLM)

- New 10×10 fixed-amount scheme (configurable):
  - Registration (₹2100): Level 1 ₹500, Level 2 ₹100, Levels 3–10 ₹50 each.
  - Renewal (₹1000): Levels 1–10 ₹50 each.
  - Company share: ₹1100 (registration), ₹500 (renewal).
- Configure in `.env`:
  - `REFERRAL_REGISTRATION_AMOUNTS` and `REFERRAL_RENEWAL_AMOUNTS` in rupees.
  - `REFERRAL_REGISTRATION_FEE_RUPEES=2100`, `REFERRAL_RENEWAL_FEE_RUPEES=1000`.
  - `REFERRAL_MIN_ACTIVATION_RUPEES=2100` (locks referral on first registration payment).
  - Optional legacy `REFERRAL_LEVEL_PERCENTAGES` still supported for non-standard top-ups.
- Behavior:
  - On top-up that matches registration/renewal fee, fixed per-level amounts are recorded in `ReferralLedger` (no wallet credit).
  - Users can request withdrawals of accumulated referral earnings via existing endpoints.
- User endpoints:
  - `GET /api/auth/referrals/tree?depth=2` downline tree by level.
  - `GET /api/auth/referrals/earnings` list referral ledger entries and totals.
  - `POST /api/auth/referrals/withdraw` request payout of pending referral earnings.
  - `GET /api/auth/referrals/withdrawals` list past withdrawal requests.
  - `GET /api/auth/referrals/pending` list users who signed up with your code but have not activated (name + phone).
  - `GET /api/auth/referrals/non-paid` or `/api/auth/referrals/nonpaid` — alias of the above for clients that use the "Non‑paid" tab name.
  - `GET /api/auth/referrals/active` list users who activated (paid registration) and count for benefits.
- Admin endpoints:
  - `POST /api/mlm/simulate` simulate distribution without payment for testing.
    - Body: `{ userId, type: 'registration' | 'renewal' }`
    - Only writes referral ledgers; no wallet balance change.
  - `GET /api/mlm/config` show current configured schedules/fees.
  - `GET /api/admin/referrals/pending` review pending entries; `PATCH /api/admin/referrals/withdrawals/:id` to mark paid/cancelled.

## Local Development

```bash
npm install
npm run dev
```

Dummy payments for QA (Razorpay not required):
- Set `DUMMY_PAYMENT_ENABLED=1` in `.env` (default for non-production).
- Call `POST /api/wallet/topups/dummy` with an auth Bearer token and body `{ "amountInRupees": 2100 }` (or `amountPaise`/`amount`).
- The request mirrors real top-ups: wallet is credited and membership/activation payload is returned for the client.

Key endpoints:
- `GET /` simple status payload for uptime checks.
- Membership: GET /api/auth/me (returns membership countdown)
- Membership backfill: POST /api/auth/membership/backfill (auth user)
- `GET /api/health` Render health check target.
- `POST /api/auth/request-otp` and `POST /api/auth/verify-otp` phone login flow.
- `POST /api/auth/admin/request-otp` and `POST /api/auth/admin/verify-otp` phone OTP auth for admins.
- `POST /api/auth/admin/login` email/password login for legacy admins.
- `GET /api/advice/latest`, `POST /api/advice`, `POST /api/advice/:id/unlock` advice lifecycle.
- `GET /api/wallet` wallet summary.
- Socket.IO emits `market:tick` demo events on the same origin.

### Push notifications (Firebase Cloud Messaging)

- Configure Firebase credentials via `GOOGLE_SERVICE_ACCOUNT_JSON` or `FIREBASE_PROJECT_ID`, `FIREBASE_CLIENT_EMAIL`, `FIREBASE_PRIVATE_KEY` in `.env`.
- `POST /api/notifications/register` (auth): save an FCM token with `segments` (stocks, nifty, banknifty, sensex, commodity) plus optional `platform`, `deviceId`, `appVersion`.
- `POST /api/notifications/segment/:segment` (admin): send a mixed `notification` + `data` payload to all tokens subscribed to that segment; server adds `segment` and default `type=segment_alert`.
- `POST /api/notifications/user/:userId` (admin): send the same mixed payload to a specific user's tokens; server adds `userId` and default `type=user_alert`.

Membership-gated content
- The following endpoints now require an authenticated, ACTIVE account. Responses include a `membership` object with countdown fields, and return HTTP 402 with `{ error: 'MEMBERSHIP_INACTIVE', membership }` when inactive:
  - `GET /api/segments`, `GET /api/segments/:segment`, `GET /api/segments/:segment/history`
  - `GET /api/trade-messages`, `GET /api/trade-messages/:category`, `GET /api/trade-messages/:category/history`
  - After payment verification (`POST /api/wallet/topups/verify`), the server returns `activation` and `membership` to update the client UI immediately.

### Images (Admin uploads to Cloudinary, users list images)

- `POST /api/images/signature` (admin): returns Cloudinary upload signature/params for direct client uploads.
  - Body: `{ folder?: string, tags?: string[] }`
  - Response: `{ cloudName, apiKey, timestamp, signature, folder, tags, uploadUrl }`
- Upload each selected file directly from the client to `uploadUrl` with multipart form fields:
  - `file` (binary or data URL), `api_key`, `timestamp`, `signature`, and optional `folder`, `tags`.
- `POST /api/images/batch` (admin): persist uploaded items to DB after successful Cloudinary upload.
  - Body: `{ items: Array<CloudinaryUploadResult> }` where each item includes `public_id`, `secure_url`, etc.
- `GET /api/images` (public): returns recent images for the user app: `{ items: [{ id, url, width, height, format, folder, createdAt }] }`.

## Deploying to Render

1. Commit these changes and push to your repository.
2. Review `render.yaml` and adjust the service name, region, and CORS origins to match your deployment.
3. In Render, pick **New > Blueprint > From repo**, select this repo, and let Render read `render.yaml`.
4. Supply values for variables marked with `sync: false` (e.g. `MONGODB_URI`, Twilio secrets) and tweak auto-generated secrets if needed.
5. Render runs `npm install` during build and `npm run start` at runtime. Health checks hit `/api/health`.
6. Add your Flutter production origin(s) to `CORS_ALLOWED_ORIGINS` (and `SOCKET_ALLOWED_ORIGINS` if websockets are hosted elsewhere). Leave them blank for native mobile apps during development.

## Connecting From Flutter

- REST: Point your HTTP client at the Render base URL (e.g. `https://trade-advice-api.onrender.com`) and attach `Authorization: Bearer <token>` once authenticated.
- Socket.IO: `io('https://trade-advice-api.onrender.com', { transports: ['websocket'] })` uses the same CORS whitelist as HTTP.
- Handle 401/403 responses by restarting the OTP flow.

## Operational Notes

- `app.set('trust proxy', 1)` keeps rate limiting/IP logging accurate behind Render's proxy.
- Graceful shutdown closes the HTTP listener and MongoDB connection on `SIGTERM/SIGINT` so instances recycle cleanly.
- When `NODE_ENV=production`, logs switch to the `combined` format for better observability.
#   b a c k e n d 
 
 
