import express from 'express';
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
  }
});

export default router;
