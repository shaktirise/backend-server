import mongoose from 'mongoose';
import { cert, getApps, initializeApp } from 'firebase-admin/app';
import { getMessaging } from 'firebase-admin/messaging';
import NotificationToken from '../models/NotificationToken.js';
import { normalizeSegmentKey } from '../models/SegmentMessage.js';



let firebaseApp = null;
let messagingClient = null;

const DEFAULT_ANDROID_CHANNEL = process.env.FCM_ANDROID_CHANNEL_ID || 'high-priority';

function parseServiceAccount() {
  const rawJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
  if (rawJson) {
    try {
      const parsed = JSON.parse(rawJson);
      if (parsed?.private_key?.includes('\\n')) {
        parsed.private_key = parsed.private_key.replace(/\\n/g, '\n');
      }
      if (parsed?.project_id && parsed?.client_email && parsed?.private_key) {
        return {
          projectId: parsed.project_id,
          clientEmail: parsed.client_email,
          privateKey: parsed.private_key,
        };
      }
    } catch (err) {
      console.warn('Invalid GOOGLE_SERVICE_ACCOUNT_JSON', err);
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

  if (privateKey?.includes('\\n')) {
    privateKey = privateKey.replace(/\\n/g, '\n');
  }

  if (projectId && clientEmail && privateKey) {
    return { projectId, clientEmail, privateKey };
  }

  return null;
}

function ensureMessaging() {
  if (messagingClient !== null) return messagingClient;

  const creds = parseServiceAccount();
  if (!creds) {
    messagingClient = null;
    return messagingClient;
  }

  try {
    firebaseApp = getApps().length
      ? getApps()[0]
      : initializeApp({
          credential: cert({
            projectId: creds.projectId,
            clientEmail: creds.clientEmail,
            privateKey: creds.privateKey,
          }),
        });
    messagingClient = getMessaging(firebaseApp);
    return messagingClient;
  } catch (err) {
    console.error('[Push] Failed to init Firebase Admin SDK', err);
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
    payload[key] = typeof value === 'string' ? value : JSON.stringify(value);
  });
  return payload;
}

function normalizeTokens(list = []) {
  return Array.from(
    new Set(
      list
        .map((token) => (typeof token === 'string' ? token.trim() : ''))
        .filter((token) => token && token.length >= 10),
    ),
  );
}

async function fetchActiveTokens({ userIds = [], tokens = [], segments = [] } = {}) {
  const resolvedTokens = normalizeTokens(tokens);
  const orFilters = [];

  const validUserIds = Array.isArray(userIds)
    ? userIds
        .map((id) => (mongoose.Types.ObjectId.isValid(id) ? new mongoose.Types.ObjectId(id) : null))
        .filter(Boolean)
    : [];

  if (validUserIds.length) {
    orFilters.push({ userId: { $in: validUserIds }, disabled: { $ne: true } });
  }

  const normalizedSegments = Array.isArray(segments)
    ? Array.from(new Set(segments.map((seg) => normalizeSegmentKey(seg)).filter(Boolean)))
    : [];

  if (normalizedSegments.length) {
    orFilters.push({ segments: { $in: normalizedSegments }, disabled: { $ne: true } });
  }

  if (orFilters.length) {
    const docs = await NotificationToken.find(orFilters.length === 1 ? orFilters[0] : { $or: orFilters })
      .select('token')
      .lean();
    docs.forEach((doc) => {
      if (doc?.token) resolvedTokens.push(doc.token);
    });
  }

  return normalizeTokens(resolvedTokens);
}

function buildMessagePayload({ title, body, data, imageUrl }) {
  const payloadData = normalizeDataPayload(data);
  const message = {
    notification:
      title || body
        ? {
            title: title || undefined,
            body: body || undefined,
            image: imageUrl || undefined,
          }
        : undefined,
    data: payloadData,
    android: {
      priority: 'HIGH',
      notification: {
        channelId: DEFAULT_ANDROID_CHANNEL,
        sound: 'default',
        defaultSound: true,
        imageUrl: imageUrl || undefined,
        visibility: 'PUBLIC',
      },
    },
    apns: {
      headers: { 'apns-priority': '10' },
      payload: {
        aps: {
          alert: title || body ? { title: title || undefined, body: body || undefined } : undefined,
          sound: 'default',
          badge: 1,
          'content-available': 1,
        },
      },
      fcmOptions: imageUrl ? { image: imageUrl } : undefined,
    },
    webpush: imageUrl ? { notification: { image: imageUrl } } : undefined,
  };

  if (!message.notification) delete message.notification;
  if (!message.data || Object.keys(message.data).length === 0) delete message.data;
  if (message.webpush === undefined) delete message.webpush;

  return message;
}

function logNonBlockingError(prefix, err) {
  console.error(prefix, err?.message || err);
}

export async function sendPushNotification({
  userIds = [],
  tokens = [],
  segments = [],
  title,
  body,
  data = {},
  imageUrl,
  dryRun = false,
} = {}) {
  try {
    const messaging = ensureMessaging();
    if (!messaging) {
      console.warn('[Push] FCM not configured, skipping send');
      return { ok: false, error: 'fcm_not_configured' };
    }

    const targetTokens = await fetchActiveTokens({ userIds, tokens, segments });
    if (!targetTokens.length) {
      return { ok: false, error: 'no_tokens' };
    }

    const baseMessage = buildMessagePayload({ title, body, data, imageUrl });
    const chunkSize = 500;
    let success = 0;
    let failure = 0;
    const invalidTokens = new Set();
    const responses = [];

    for (let i = 0; i < targetTokens.length; i += chunkSize) {
      const batch = targetTokens.slice(i, i + chunkSize);
      try {
        const result = await messaging.sendEachForMulticast({ ...baseMessage, tokens: batch }, dryRun);
        success += result.successCount || 0;
        failure += result.failureCount || 0;
        result.responses.forEach((resp, idx) => {
          const token = batch[idx];
          if (resp.success) return;
          const code = resp.error?.code || 'unknown';
          if (
            code === 'messaging/registration-token-not-registered' ||
            code === 'messaging/invalid-registration-token'
          ) {
            invalidTokens.add(token);
          }
          responses.push({ token, error: code, message: resp.error?.message });
        });
      } catch (err) {
        logNonBlockingError('[Push] sendEachForMulticast failed', err);
        failure += batch.length;
        batch.forEach((token) => responses.push({ token, error: 'send_failure', message: err?.message }));
      }
    }

    if (invalidTokens.size) {
      NotificationToken.updateMany(
        { token: { $in: Array.from(invalidTokens) } },
        { $set: { disabled: true } },
      ).catch((err) => logNonBlockingError('[Push] Failed to mark invalid tokens', err));
    }

    return {
      ok: failure === 0,
      requested: targetTokens.length,
      success,
      failure,
      invalidTokens: Array.from(invalidTokens),
      responses,
      dryRun,
    };
  } catch (err) {
    logNonBlockingError('[Push] Unexpected send error', err);
    return { ok: false, error: 'send_failed', message: err?.message };
  }
}
