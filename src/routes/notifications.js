import express from 'express';
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
  }
});

export default router;
