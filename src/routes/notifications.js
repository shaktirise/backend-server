import express from 'express';
<<<<<<< HEAD
import mongoose from 'mongoose';
import { auth, admin as requireAdmin } from '../middleware/auth.js';
import NotificationToken from '../models/NotificationToken.js';
import { sendPushNotification, isPushConfigured } from '../services/push.js';
import { formatLocalISO, toEpochMs } from '../utils/time.js';

const router = express.Router();

function normalizePlatform(platform) {
  const value = String(platform || '').trim().toLowerCase();
  if (['android', 'ios', 'web'].includes(value)) return value;
  return 'unknown';
}

function serializeToken(doc) {
  if (!doc) return null;
  const lastActive = doc.lastActiveAt || doc.updatedAt || doc.createdAt || null;
  return {
    id: doc._id,
    token: doc.token,
    platform: doc.platform || 'unknown',
    deviceId: doc.deviceId || null,
    appId: doc.appId || null,
    appVersion: doc.appVersion || null,
    deviceModel: doc.deviceModel || null,
    osVersion: doc.osVersion || null,
    lastActiveAt: lastActive,
    lastActiveAtLocal: lastActive ? formatLocalISO(lastActive) : null,
    lastActiveAtMs: lastActive ? toEpochMs(lastActive) : null,
    disabled: !!doc.disabled,
  };
}

router.get('/status', auth, (req, res) => {
  return res.json({ pushConfigured: isPushConfigured() });
});

router.post('/register', auth, async (req, res) => {
  try {
    const {
      token,
      platform,
      deviceId,
      appId,
      appVersion,
      deviceModel,
      osVersion,
    } = req.body || {};
    const tokenStr = typeof token === 'string' ? token.trim() : '';
    if (!tokenStr || tokenStr.length < 10) {
      return res.status(400).json({ error: 'valid_token_required' });
    }

    const update = {
      userId: req.user.id,
      platform: normalizePlatform(platform),
      deviceId: deviceId || undefined,
      appId: appId || undefined,
      appVersion: appVersion || undefined,
      deviceModel: deviceModel || undefined,
      osVersion: osVersion || undefined,
      lastActiveAt: new Date(),
      disabled: false,
    };

    const doc = await NotificationToken.findOneAndUpdate(
      { token: tokenStr },
      { $set: update, $setOnInsert: { token: tokenStr } },
      { new: true, upsert: true },
    );

    return res.json({ ok: true, token: serializeToken(doc), pushConfigured: isPushConfigured() });
  } catch (err) {
    console.error('notification register error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/unregister', auth, async (req, res) => {
  try {
    const token = typeof req.body?.token === 'string' ? req.body.token.trim() : '';
    if (!token) return res.status(400).json({ error: 'token_required' });

    const result = await NotificationToken.deleteOne({ token, userId: req.user.id });
    return res.json({ ok: true, deleted: result.deletedCount || 0 });
  } catch (err) {
    console.error('notification unregister error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/test', auth, async (req, res) => {
  try {
    const title = typeof req.body?.title === 'string' && req.body.title.trim()
      ? req.body.title.trim()
      : 'Test notification';
    const body = typeof req.body?.body === 'string' && req.body.body.trim()
      ? req.body.body.trim()
      : 'Push from server';
    const data = req.body?.data || {};
    const imageUrl = req.body?.imageUrl || undefined;
    const dryRun = req.body?.dryRun === true;

    const tokens = await NotificationToken.find({ userId: req.user.id, disabled: { $ne: true } })
      .select('token')
      .lean();

    if (!tokens.length) {
      return res.status(404).json({ error: 'no_tokens_registered' });
    }

    const tokenValues = tokens.map((t) => t.token);
    const result = await sendPushNotification({
      tokens: tokenValues,
      title,
      body,
      data,
      imageUrl,
      dryRun,
    });

    if (result.invalidTokens?.length) {
      await NotificationToken.updateMany(
        { token: { $in: result.invalidTokens } },
        { $set: { disabled: true } },
      );
    }

    return res.json({ ...result, tokens: tokenValues.length });
  } catch (err) {
    console.error('notification test error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/send', auth, requireAdmin, async (req, res) => {
  try {
    const {
      userIds = [],
      tokens: extraTokens = [],
      title,
      body,
      data,
      imageUrl,
      dryRun,
    } = req.body || {};

    const validUserIds = Array.isArray(userIds)
      ? userIds.filter((id) => mongoose.Types.ObjectId.isValid(id)).map((id) => new mongoose.Types.ObjectId(id))
      : [];

    let tokens = [];
    if (validUserIds.length) {
      const docs = await NotificationToken.find({
        userId: { $in: validUserIds },
        disabled: { $ne: true },
      })
        .select('token')
        .lean();
      tokens.push(...docs.map((doc) => doc.token));
    }

    if (Array.isArray(extraTokens) && extraTokens.length) {
      tokens.push(
        ...extraTokens
          .map((t) => (typeof t === 'string' ? t.trim() : ''))
          .filter(Boolean),
      );
    }

    const uniqueTokens = [...new Set(tokens)];
    if (!uniqueTokens.length) {
      return res.status(404).json({ error: 'no_tokens_found' });
    }

    const result = await sendPushNotification({
      tokens: uniqueTokens,
      title,
      body,
      data,
      imageUrl,
      dryRun: !!dryRun,
    });

    if (result.invalidTokens?.length) {
      await NotificationToken.updateMany(
        { token: { $in: result.invalidTokens } },
        { $set: { disabled: true } },
      );
    }

    return res.json({ ...result, tokens: uniqueTokens.length });
  } catch (err) {
    console.error('notification send error', err);
    return res.status(500).json({ error: 'server error' });
=======
import NotificationToken from '../models/NotificationToken.js';
import User from '../models/User.js';
import { normalizeSegmentKey, SEGMENT_KEYS } from '../models/SegmentMessage.js';
import { auth, admin } from '../middleware/auth.js';
import { isPushConfigured, sendPushToTokens } from '../services/pushNotifications.js';

const router = express.Router();

function normalizeSegments(list) {
  if (!Array.isArray(list)) return null;
  const normalized = list
    .map((value) => normalizeSegmentKey(value))
    .filter(Boolean);
  return Array.from(new Set(normalized));
}

function normalizePlatform(value) {
  const supported = ['android', 'ios', 'web'];
  const val = String(value || '').toLowerCase();
  return supported.includes(val) ? val : 'unknown';
}

router.post('/register', auth, async (req, res) => {
  try {
    const { fcm_token, fcmToken, token, segments, platform, deviceId, appVersion } = req.body || {};
    const resolvedToken = String(fcm_token || fcmToken || token || '').trim();
    if (!resolvedToken) return res.status(400).json({ error: 'token_required' });

    const normalizedSegments = normalizeSegments(segments);
    const now = new Date();

    const setDoc = {
      userId: req.user?.id || null,
      platform: normalizePlatform(platform),
      lastSeenAt: now,
    };

    if (typeof deviceId === 'string') {
      setDoc.deviceId = deviceId.trim().slice(0, 100);
    }
    if (typeof appVersion === 'string') {
      setDoc.appVersion = appVersion.trim().slice(0, 50);
    }
    if (normalizedSegments !== null) {
      setDoc.segments = normalizedSegments;
    }

    const update = {
      $set: setDoc,
      $setOnInsert: { token: resolvedToken },
    };

    const doc = await NotificationToken.findOneAndUpdate(
      { token: resolvedToken },
      update,
      { new: true, upsert: true, setDefaultsOnInsert: true }
    ).lean();

    return res.json({
      ok: true,
      token: doc.token,
      platform: doc.platform,
      segments: doc.segments || [],
      pushConfigured: isPushConfigured(),
    });
  } catch (err) {
    console.error('Failed to register notification token', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

router.post('/segment/:segment', auth, admin, async (req, res) => {
  try {
    const key = normalizeSegmentKey(req.params.segment);
    if (!key) return res.status(404).json({ error: 'segment_not_found', allowed: SEGMENT_KEYS });

    const { title, body, data } = req.body || {};
    if (!title || !body) return res.status(400).json({ error: 'title_and_body_required' });

    const tokens = await NotificationToken.find({ segments: key }).select('token').lean();
    const tokenList = tokens.map((t) => t.token).filter(Boolean);

    if (!tokenList.length) {
      return res.json({
        ok: true,
        segment: key,
        sent: 0,
        failed: 0,
        total: 0,
        invalidTokens: [],
        simulated: !isPushConfigured(),
        pushConfigured: isPushConfigured(),
      });
    }

    const payloadData = {
      ...((data && typeof data === 'object') ? data : {}),
      segment: key,
      type: (data && data.type) || 'segment_alert',
    };

    const result = await sendPushToTokens({
      tokens: tokenList,
      title,
      body,
      data: payloadData,
    });

    if (result.invalidTokens?.length) {
      await NotificationToken.deleteMany({ token: { $in: result.invalidTokens } });
    }

    return res.json({
      ok: result.ok !== false,
      segment: key,
      sent: result.success || 0,
      failed: result.failure || 0,
      total: result.total || tokenList.length,
      invalidTokens: result.invalidTokens || [],
      simulated: result.simulated || false,
      pushConfigured: isPushConfigured(),
    });
  } catch (err) {
    console.error('Failed to send segment notification', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

router.post('/user/:userId', auth, admin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { title, body, data } = req.body || {};
    if (!title || !body) return res.status(400).json({ error: 'title_and_body_required' });

    const user = await User.findById(userId).select('_id').lean();
    if (!user) return res.status(404).json({ error: 'user_not_found' });

    const tokens = await NotificationToken.find({ userId: user._id }).select('token').lean();
    const tokenList = tokens.map((t) => t.token).filter(Boolean);

    if (!tokenList.length) {
      return res.json({
        ok: true,
        userId,
        sent: 0,
        failed: 0,
        total: 0,
        invalidTokens: [],
        simulated: !isPushConfigured(),
        pushConfigured: isPushConfigured(),
      });
    }

    const payloadData = {
      ...((data && typeof data === 'object') ? data : {}),
      type: (data && data.type) || 'user_alert',
      userId: String(userId),
    };

    const result = await sendPushToTokens({
      tokens: tokenList,
      title,
      body,
      data: payloadData,
    });

    if (result.invalidTokens?.length) {
      await NotificationToken.deleteMany({ token: { $in: result.invalidTokens } });
    }

    return res.json({
      ok: result.ok !== false,
      userId,
      sent: result.success || 0,
      failed: result.failure || 0,
      total: result.total || tokenList.length,
      invalidTokens: result.invalidTokens || [],
      simulated: result.simulated || false,
      pushConfigured: isPushConfigured(),
    });
  } catch (err) {
    console.error('Failed to send user notification', err);
    return res.status(500).json({ error: 'server_error' });
>>>>>>> 67feb5c4e79bd31cb0e9bdce43e5f03b920a6d8a
  }
});

export default router;
