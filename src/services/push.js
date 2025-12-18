import { cert, getApps, initializeApp } from 'firebase-admin/app';
import { getMessaging } from 'firebase-admin/messaging';

let firebaseApp = null;

function parseServiceAccount() {
  const rawJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
  if (rawJson) {
    try {
      const parsed = JSON.parse(rawJson);
      if (parsed?.private_key?.includes('\\n')) {
        parsed.private_key = parsed.private_key.replace(/\\n/g, '\n');
      }
      if (parsed?.project_id && parsed?.client_email && parsed?.private_key) {
        return parsed;
      }
    } catch (err) {
      console.warn('Invalid GOOGLE_SERVICE_ACCOUNT_JSON', err);
    }
  }

  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  let privateKey = process.env.FIREBASE_PRIVATE_KEY;

  if (privateKey?.includes('\\n')) {
    privateKey = privateKey.replace(/\\n/g, '\n');
  }

  if (projectId && clientEmail && privateKey) {
    return {
      project_id: projectId,
      client_email: clientEmail,
      private_key: privateKey,
    };
  }

  return null;
}

function ensureFirebaseApp() {
  if (firebaseApp) return firebaseApp;
  if (getApps().length) {
    [firebaseApp] = getApps();
    return firebaseApp;
  }

  const serviceAccount = parseServiceAccount();
  if (!serviceAccount) return null;

  firebaseApp = initializeApp({
    credential: cert({
      projectId: serviceAccount.project_id,
      clientEmail: serviceAccount.client_email,
      privateKey: serviceAccount.private_key,
    }),
  });

  return firebaseApp;
}

export function isPushConfigured() {
  return Boolean(ensureFirebaseApp());
}

export async function sendPushNotification({
  tokens,
  title,
  body,
  data = {},
  imageUrl,
  dryRun = false,
}) {
  const app = ensureFirebaseApp();
  if (!app) {
    return { ok: false, error: 'fcm_not_configured' };
  }

  const normalizedTokens = Array.isArray(tokens)
    ? [...new Set(tokens.map((t) => (typeof t === 'string' ? t.trim() : '')).filter(Boolean))]
    : [];

  if (!normalizedTokens.length) {
    return { ok: false, error: 'no_tokens' };
  }

  const payloadData = {};
  Object.entries(data || {}).forEach(([key, value]) => {
    if (value === undefined || value === null) return;
    payloadData[key] = typeof value === 'string' ? value : JSON.stringify(value);
  });

  const baseMessage = {
    tokens: [],
    data: payloadData,
    notification:
      title || body
        ? {
            title: title || undefined,
            body: body || undefined,
          }
        : undefined,
    android: imageUrl ? { notification: { imageUrl } } : undefined,
    apns: imageUrl
      ? {
          fcmOptions: { image: imageUrl },
          payload: { aps: { 'mutable-content': 1 } },
        }
      : undefined,
    webpush: imageUrl ? { notification: { image: imageUrl } } : undefined,
  };

  const messaging = getMessaging(app);
  const chunkSize = 500;
  let success = 0;
  let failure = 0;
  const invalidTokens = new Set();
  const responses = [];

  for (let i = 0; i < normalizedTokens.length; i += chunkSize) {
    const batch = normalizedTokens.slice(i, i + chunkSize);
    const message = { ...baseMessage, tokens: batch };
    const result = await messaging.sendEachForMulticast(message, dryRun);
    result.responses.forEach((resp, idx) => {
      const token = batch[idx];
      if (resp.success) {
        success += 1;
      } else {
        failure += 1;
        const code = resp.error?.code || 'unknown';
        if (
          code === 'messaging/registration-token-not-registered'
          || code === 'messaging/invalid-registration-token'
        ) {
          invalidTokens.add(token);
        }
        responses.push({
          token,
          error: code,
          message: resp.error?.message,
        });
      }
    });
  }

  return {
    ok: true,
    requested: normalizedTokens.length,
    success,
    failure,
    invalidTokens: Array.from(invalidTokens),
    responses,
  };
}
