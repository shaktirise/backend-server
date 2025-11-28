import { initializeApp, cert, getApps, getApp } from 'firebase-admin/app';
import { getMessaging } from 'firebase-admin/messaging';

let messagingClient;

function parseServiceAccount() {
  const json = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
  if (json) {
    try {
      const parsed = JSON.parse(json);
      if (parsed.private_key) {
        parsed.private_key = parsed.private_key.replace(/\\n/g, '\n');
      }
      return parsed;
    } catch (err) {
      console.error('[Push] Failed to parse GOOGLE_SERVICE_ACCOUNT_JSON', err.message || err);
      return null;
    }
  }

  const projectId =
    process.env.FCM_PROJECT_ID ||
    process.env.FIREBASE_PROJECT_ID ||
    process.env.GOOGLE_PROJECT_ID;
  const clientEmail =
    process.env.FCM_CLIENT_EMAIL ||
    process.env.FIREBASE_CLIENT_EMAIL ||
    process.env.GOOGLE_CLIENT_EMAIL;
  let privateKey =
    process.env.FCM_PRIVATE_KEY ||
    process.env.FIREBASE_PRIVATE_KEY ||
    process.env.GOOGLE_PRIVATE_KEY;

  if (privateKey) {
    privateKey = privateKey.replace(/\\n/g, '\n');
  }

  if (!projectId || !clientEmail || !privateKey) return null;

  return {
    projectId,
    clientEmail,
    privateKey,
  };
}

function ensureMessaging() {
  if (messagingClient !== undefined) return messagingClient;

  const creds = parseServiceAccount();
  if (!creds) {
    messagingClient = null;
    return messagingClient;
  }

  try {
    const app = getApps().length ? getApp() : initializeApp({ credential: cert(creds) });
    messagingClient = getMessaging(app);
    return messagingClient;
  } catch (err) {
    console.error('[Push] Failed to init Firebase Admin SDK', err.message || err);
    messagingClient = null;
    return messagingClient;
  }
}

export function isPushConfigured() {
  return !!ensureMessaging();
}

function normalizeDataPayload(data = {}) {
  const payload = {};
  Object.entries(data || {}).forEach(([key, value]) => {
    if (value === undefined || value === null) return;
    const str = typeof value === 'string' ? value : JSON.stringify(value);
    payload[key] = str;
  });
  return payload;
}

function buildMessagePayload({ title, body, data, image }) {
  const dataPayload = normalizeDataPayload(data);
  if (title && dataPayload.title === undefined) dataPayload.title = title;
  if (body && dataPayload.body === undefined) dataPayload.body = body;

  const payload = {
    notification:
      title || body
        ? {
            title: title || undefined,
            body: body || undefined,
            image: image || undefined,
          }
        : undefined,
    data: dataPayload,
    android: { priority: 'high' },
    apns: { headers: { 'apns-priority': '10' } },
  };

  if (!payload.notification) delete payload.notification;
  if (!payload.data || Object.keys(payload.data).length === 0) delete payload.data;

  return payload;
}

function chunk(list, size) {
  const output = [];
  for (let i = 0; i < list.length; i += size) {
    output.push(list.slice(i, i + size));
  }
  return output;
}

export async function sendPushToTokens({ tokens, title, body, data, image } = {}) {
  const list = Array.isArray(tokens)
    ? Array.from(new Set(tokens.map((t) => String(t || '').trim()).filter(Boolean)))
    : [];

  if (!list.length) {
    return { ok: false, error: 'no_tokens' };
  }

  const messaging = ensureMessaging();
  const message = buildMessagePayload({ title, body, data, image });

  if (!messaging) {
    console.log('[Push:DEV] Would send notification', {
      to: list.length,
      title,
      body,
      data: message.data,
    });
    return { ok: false, simulated: true, total: list.length };
  }

  let success = 0;
  let failure = 0;
  const invalidTokens = [];

  for (const batch of chunk(list, 500)) {
    const res = await messaging.sendEachForMulticast({ tokens: batch, ...message });
    success += res.successCount || 0;
    failure += res.failureCount || 0;

    res.responses.forEach((resp, idx) => {
      if (resp.success) return;
      const code = resp.error?.code;
      if (
        code === 'messaging/registration-token-not-registered' ||
        code === 'messaging/invalid-registration-token'
      ) {
        invalidTokens.push(batch[idx]);
      }
    });
  }

  return {
    ok: failure === 0,
    success,
    failure,
    invalidTokens,
    total: list.length,
  };
}
