import express from 'express';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import mongoose from 'mongoose';
import User from '../models/User.js';
import ReferralLedger from '../models/ReferralLedger.js';
import ReferralWithdrawalRequest from '../models/ReferralWithdrawalRequest.js';
import { auth, admin } from '../middleware/auth.js';
import {
  ensureReferralCode,
  normalizeReferralCodeInput,
  buildReferralShareLink,
  getReferralConfig,
} from '../services/referral.js';

const router = express.Router();

const requestLimiter = rateLimit({ windowMs: 60 * 1000, max: 15 });

const ACCESS_TOKEN_TTL_SEC = parseInt(process.env.ACCESS_TOKEN_TTL_SEC || '3600', 10);
const REFRESH_TOKEN_TTL_SEC = parseInt(
  process.env.REFRESH_TOKEN_TTL_SEC || String(3 * 24 * 60 * 60),
  10,
);
const REFRESH_TOKEN_BCRYPT_ROUNDS = parseInt(
  process.env.REFRESH_TOKEN_BCRYPT_ROUNDS || '12',
  10,
);

function isValidName(name) {
  return typeof name === 'string' && name.trim().length >= 2 && name.trim().length <= 100;
}

function isValidEmail(email) {
  return typeof email === 'string' && /.+@.+\..+/.test(email.trim());
}

function isValidPassword(password) {
  return typeof password === 'string' && password.length >= 8 && password.length <= 128;
}

function signAccessToken(user) {
  const expiresAt = new Date(Date.now() + ACCESS_TOKEN_TTL_SEC * 1000);
  const payload = {
    id: user._id.toString(),
    sub: user._id.toString(),
    role: user.role,
  };
  const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: ACCESS_TOKEN_TTL_SEC });
  return { token, expiresAt };
}

async function attachRefreshToken(user) {
  const raw = crypto.randomBytes(48).toString('hex');
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_SEC * 1000);
  user.refreshTokenHash = await bcrypt.hash(raw, REFRESH_TOKEN_BCRYPT_ROUNDS);
  user.refreshTokenExpiresAt = expiresAt;
  return { refreshToken: `${user._id.toString()}.${raw}`, expiresAt };
}

async function issueAuthTokens(user) {
  const { token, expiresAt: tokenExpiresAt } = signAccessToken(user);
  const { refreshToken, expiresAt: refreshTokenExpiresAt } = await attachRefreshToken(user);
  return { token, tokenExpiresAt, refreshToken, refreshTokenExpiresAt };
}

function buildUserPayload(user) {
  return {
    id: user._id,
    name: user.name,
    email: user.email,
    phone: user.phone || null,
    role: user.role,
    walletBalance: user.walletBalance,
    referralCode: user.referralCode,
    referralShareLink: buildReferralShareLink(user.referralCode),
    referralCount: user.referralCount || 0,
    referralActivatedAt: user.referralActivatedAt || null,
    referredBy: user.referredBy ? user.referredBy.toString() : null,
    pendingReferredBy: user.pendingReferredBy ? user.pendingReferredBy.toString() : null,
    lastLoginAt: user.lastLoginAt || null,
  };
}

function serializeWithdrawalRequest(doc) {
  if (!doc) return null;
  return {
    id: doc._id,
    amountPaise: doc.amountPaise,
    amountRupees: Number.isFinite(doc.amountPaise) ? Math.floor(doc.amountPaise / 100) : 0,
    status: doc.status,
    note: doc.note || null,
    adminNote: doc.adminNote || null,
    ledgerCount: Array.isArray(doc.ledgerEntryIds) ? doc.ledgerEntryIds.length : 0,
    processedAt: doc.processedAt || null,
    processedBy: doc.processedBy ? doc.processedBy.toString() : null,
    createdAt: doc.createdAt,
    updatedAt: doc.updatedAt,
  };
}

async function finalizeAuthSuccess(user, req) {
  await ensureReferralCode(user);
  user.lastLoginAt = new Date();
  user.lastLoginIp = req.ip;
  user.loginCount = (user.loginCount || 0) + 1;
  const tokens = await issueAuthTokens(user);
  await user.save();
  return tokens;
}

router.post('/signup', requestLimiter, async (req, res) => {
  try {
    const { name, email, password, confirmPassword, referralId } = req.body || {};
    const referralInput = normalizeReferralCodeInput(
      req.body?.referralCode || req.body?.referral || req.body?.refCode || referralId || '',
    );

    if (!isValidName(name)) {
      return res.status(400).json({ error: 'valid name required' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'valid email required' });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ error: 'password must be 8-128 chars' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'passwords do not match' });
    }

    const emailNorm = String(email).trim().toLowerCase();
    const existing = await User.findOne({ email: emailNorm });
    if (existing) {
      return res.status(409).json({ error: 'email already registered' });
    }

    let referer = null;
    if (referralInput) {
      referer = await User.findOne({ referralCode: referralInput }).select('_id referralCode');
      if (!referer) {
        return res.status(400).json({ error: 'invalid referral code' });
      }
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = new User({
      name: String(name).trim(),
      email: emailNorm,
      passwordHash,
    });

    if (referer) {
      user.pendingReferredBy = referer._id;
    }

    await ensureReferralCode(user);
    await user.save();

    const tokens = await finalizeAuthSuccess(user, req);

    return res.status(201).json({
      token: tokens.token,
      tokenExpiresAt: tokens.tokenExpiresAt,
      refreshToken: tokens.refreshToken,
      refreshTokenExpiresAt: tokens.refreshTokenExpiresAt,
      user: buildUserPayload(user),
    });
  } catch (err) {
    console.error('signup error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/login', requestLimiter, async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!isValidEmail(email) || !password) {
      return res.status(400).json({ error: 'email and password required' });
    }

    const user = await User.findOne({ email });
    if (!user || !user.passwordHash || user.role !== 'user') {
      return res.status(401).json({ error: 'invalid credentials' });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(401).json({ error: 'invalid credentials' });
    }

    const tokens = await finalizeAuthSuccess(user, req);

    return res.json({
      token: tokens.token,
      tokenExpiresAt: tokens.tokenExpiresAt,
      refreshToken: tokens.refreshToken,
      refreshTokenExpiresAt: tokens.refreshTokenExpiresAt,
      user: buildUserPayload(user),
    });
  } catch (err) {
    console.error('login error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/admin/signup', requestLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    const confirmPassword =
      req.body?.confirmPassword ?? req.body?.confirmPass ?? req.body?.confirmpass;
    if (!isValidName(name)) {
      return res.status(400).json({ error: 'valid name required' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'valid email required' });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ error: 'password must be 8-128 chars' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'passwords do not match' });
    }

    const emailNorm = String(email).trim().toLowerCase();
    const exists = await User.findOne({ email: emailNorm });
    if (exists) {
      return res.status(409).json({ error: 'email already registered' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = new User({
      name: String(name).trim(),
      email: emailNorm,
      passwordHash,
      role: 'admin',
    });

    await user.save();

    const tokens = await finalizeAuthSuccess(user, req);

    return res.status(201).json({
      token: tokens.token,
      tokenExpiresAt: tokens.tokenExpiresAt,
      refreshToken: tokens.refreshToken,
      refreshTokenExpiresAt: tokens.refreshTokenExpiresAt,
      user: buildUserPayload(user),
    });
  } catch (err) {
    console.error('admin signup error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/admin/login', requestLimiter, async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!isValidEmail(email) || !password) {
      return res.status(400).json({ error: 'email and password required' });
    }

    const user = await User.findOne({ email });
    if (!user || !user.passwordHash || user.role !== 'admin') {
      return res.status(401).json({ error: 'invalid credentials' });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(401).json({ error: 'invalid credentials' });
    }

    const tokens = await finalizeAuthSuccess(user, req);

    return res.json({
      token: tokens.token,
      tokenExpiresAt: tokens.tokenExpiresAt,
      refreshToken: tokens.refreshToken,
      refreshTokenExpiresAt: tokens.refreshTokenExpiresAt,
      user: buildUserPayload(user),
    });
  } catch (err) {
    console.error('admin login error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/refresh-token', async (req, res) => {
  try {
    const provided = req.body?.refreshToken;
    if (typeof provided !== 'string' || !provided.length) {
      return res.status(400).json({ error: 'refreshToken required' });
    }

    const [userId, raw] = provided.split('.');
    if (!userId || !raw) {
      return res.status(400).json({ error: 'invalid refresh token' });
    }

    const user = await User.findById(userId);
    if (
      !user
      || !user.refreshTokenHash
      || !user.refreshTokenExpiresAt
      || user.refreshTokenExpiresAt.getTime() < Date.now()
    ) {
      return res.status(401).json({ error: 'invalid refresh token' });
    }

    const ok = await bcrypt.compare(raw, user.refreshTokenHash);
    if (!ok) {
      return res.status(401).json({ error: 'invalid refresh token' });
    }

    await ensureReferralCode(user);

    const tokens = await issueAuthTokens(user);
    await user.save();

    return res.json({
      token: tokens.token,
      tokenExpiresAt: tokens.tokenExpiresAt,
      refreshToken: tokens.refreshToken,
      refreshTokenExpiresAt: tokens.refreshTokenExpiresAt,
      user: buildUserPayload(user),
    });
  } catch (err) {
    console.error('refresh-token error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/logout', async (req, res) => {
  try {
    const provided = req.body?.refreshToken;
    if (typeof provided !== 'string' || !provided.length) {
      return res.status(400).json({ error: 'refreshToken required' });
    }
    const [userId, raw] = provided.split('.');
    if (!userId || !raw) {
      return res.status(400).json({ error: 'invalid refresh token' });
    }

    const user = await User.findById(userId);
    if (!user || !user.refreshTokenHash) {
      return res.json({ ok: true });
    }

    const ok = await bcrypt.compare(raw, user.refreshTokenHash);
    if (ok) {
      user.refreshTokenHash = undefined;
      user.refreshTokenExpiresAt = undefined;
      await user.save();
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error('logout error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'not found' });

    const hadCode = Boolean(user.referralCode);
    await ensureReferralCode(user);
    if (!hadCode && user.referralCode) {
      await user.save();
    }

    return res.json({ user: buildUserPayload(user) });
  } catch (err) {
    console.error('me error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.put('/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'not found' });

    if (typeof req.body?.name === 'string' && isValidName(req.body.name)) {
      user.name = req.body.name.trim();
    }

    await ensureReferralCode(user);
    await user.save();

    return res.json({ user: buildUserPayload(user) });
  } catch (err) {
    console.error('update me error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/referrals', auth, async (req, res) => {
  try {
    const limitRaw = parseInt(req.query?.limit ?? '50', 10);
    const offsetRaw = parseInt(req.query?.offset ?? '0', 10);
    const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 200) : 50;
    const offset = Number.isFinite(offsetRaw) && offsetRaw > 0 ? offsetRaw : 0;

    const [finalRefs, pendingRefs, totalFinal, totalPending] = await Promise.all([
      User.find({ referredBy: req.user.id })
        .sort({ createdAt: -1 })
        .skip(offset)
        .limit(limit)
        .select('_id name email referralCode referralActivatedAt createdAt loginCount'),
      User.find({ pendingReferredBy: req.user.id })
        .sort({ createdAt: -1 })
        .limit(limit)
        .select('_id name email referralCode createdAt'),
      User.countDocuments({ referredBy: req.user.id }),
      User.countDocuments({ pendingReferredBy: req.user.id }),
    ]);

    return res.json({
      total: totalFinal,
      pendingTotal: totalPending,
      offset,
      limit,
      referrals: finalRefs.map((ref) => ({
        id: ref._id,
        name: ref.name,
        email: ref.email,
        referralCode: ref.referralCode,
        referralShareLink: buildReferralShareLink(ref.referralCode),
        createdAt: ref.createdAt,
        referralActivatedAt: ref.referralActivatedAt,
        loginCount: ref.loginCount || 0,
      })),
      pendingReferrals: pendingRefs.map((ref) => ({
        id: ref._id,
        name: ref.name,
        email: ref.email,
        referralCode: ref.referralCode,
        referralShareLink: buildReferralShareLink(ref.referralCode),
        createdAt: ref.createdAt,
      })),
    });
  } catch (err) {
    console.error('referrals error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/referrals/tree', auth, async (req, res) => {
  try {
    const config = getReferralConfig();
    const depthRaw = parseInt(req.query?.depth ?? `${config.maxDepth}`, 10);
    const depth = Number.isFinite(depthRaw) && depthRaw > 0
      ? Math.min(depthRaw, config.maxDepth)
      : config.maxDepth;

    const levels = [];
    let currentLevel = [req.user.id];

    for (let level = 1; level <= depth && currentLevel.length; level += 1) {
      const nextLevelUsers = await User.find({ referredBy: { $in: currentLevel } })
        .select('_id name email referralCode referredBy referralActivatedAt createdAt loginCount')
        .lean();

      if (!nextLevelUsers.length) break;

      levels.push({
        level,
        users: nextLevelUsers.map((u) => ({
          id: u._id,
          name: u.name,
          email: u.email,
          referralCode: u.referralCode,
          referralShareLink: buildReferralShareLink(u.referralCode),
          referredBy: u.referredBy ? u.referredBy.toString() : null,
          referralActivatedAt: u.referralActivatedAt,
          createdAt: u.createdAt,
          loginCount: u.loginCount || 0,
        })),
      });

      currentLevel = nextLevelUsers.map((u) => u._id);
    }

    return res.json({ depth: levels.length, levels });
  } catch (err) {
    console.error('referral tree error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/referrals/earnings', auth, async (req, res) => {
  try {
    const entries = await ReferralLedger.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .select('amountPaise note createdAt status level sourceUserId topupExtRef withdrawalRequestId')
      .lean();

    const totals = entries.reduce(
      (acc, entry) => {
        const amount = entry.amountPaise || 0;
        if (entry.status === 'paid') {
          acc.paid += amount;
        } else if (entry.status === 'cancelled') {
          acc.cancelled += amount;
        } else {
          acc.pending += amount;
        }
        return acc;
      },
      { pending: 0, paid: 0, cancelled: 0 },
    );

    return res.json({
      totalEarnedPaise: totals.pending + totals.paid,
      totalPendingPaise: totals.pending,
      totalPaidPaise: totals.paid,
      totalCancelledPaise: totals.cancelled,
      entries: entries.map((entry) => ({
        id: entry._id,
        amountPaise: entry.amountPaise,
        amount: entry.amountPaise,
        note: entry.note,
        status: entry.status,
        level: entry.level,
        sourceUserId: entry.sourceUserId ? entry.sourceUserId.toString() : null,
        createdAt: entry.createdAt,
        topupExtRef: entry.topupExtRef || null,
        withdrawalRequestId: entry.withdrawalRequestId || null,
      })),
    });
  } catch (err) {
    console.error('referral earnings error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/referrals/withdraw', auth, async (req, res) => {
  const userId = req.user.id;
  const note = typeof req.body?.note === 'string' && req.body.note.trim() ? req.body.note.trim() : undefined;
  try {
    const existing = await ReferralWithdrawalRequest.findOne({ userId, status: 'pending' }).lean();
    if (existing) {
      return res.status(409).json({
        error: 'withdrawal_pending',
        requestId: existing._id,
      });
    }

    const session = await mongoose.startSession();
    let createdRequest = null;
    try {
      await session.withTransaction(async () => {
        const pendingEntries = await ReferralLedger.find({ userId, status: 'pending' })
          .session(session)
          .select('_id amountPaise')
          .lean();

        if (!pendingEntries.length) {
          const err = new Error('NO_PENDING_COMMISSIONS');
          err.code = 'NO_PENDING_COMMISSIONS';
          throw err;
        }

        const amountPaise = pendingEntries.reduce((sum, entry) => sum + (entry.amountPaise || 0), 0);
        if (amountPaise <= 0) {
          const err = new Error('NO_PENDING_COMMISSIONS');
          err.code = 'NO_PENDING_COMMISSIONS';
          throw err;
        }

        const ledgerEntryIds = pendingEntries.map((entry) => entry._id);

        const [requestDoc] = await ReferralWithdrawalRequest.create(
          [
            {
              userId,
              amountPaise,
              note,
              ledgerEntryIds,
            },
          ],
          { session },
        );

        await ReferralLedger.updateMany(
          { _id: { $in: ledgerEntryIds } },
          { $set: { status: 'requested', withdrawalRequestId: requestDoc._id } },
          { session },
        );

        createdRequest = requestDoc.toObject();
      });
    } catch (err) {
      if (err?.code === 'NO_PENDING_COMMISSIONS') {
        return res.status(400).json({ error: 'no_commission_available' });
      }
      throw err;
    } finally {
      await session.endSession();
    }

    return res.status(201).json({ request: serializeWithdrawalRequest(createdRequest) });
  } catch (err) {
    console.error('referral withdraw error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/referrals/withdrawals', auth, async (req, res) => {
  try {
    const limitRaw = Number.parseInt(req.query?.limit ?? '20', 10);
    const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 100) : 20;
    const requests = await ReferralWithdrawalRequest.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .limit(limit)
      .lean();
    return res.json({
      items: requests.map(serializeWithdrawalRequest),
    });
  } catch (err) {
    console.error('referral withdrawals list error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/referrals/config', auth, (req, res) => {
  try {
    const config = getReferralConfig();
    return res.json({
      levelPercentages: config.levelPercentages,
      maxDepth: config.maxDepth,
      minActivationPaise: config.minActivationPaise,
      shareBaseUrl: config.shareBaseUrl,
    });
  } catch (err) {
    console.error('referral config error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.patch('/admin/referrals/:entryId/status', auth, admin, async (req, res) => {
  try {
    const { entryId } = req.params;
    const { status } = req.body || {};

    const allowed = new Set(['pending', 'paid', 'cancelled']);
    if (!allowed.has(status)) {
      return res.status(400).json({ error: 'invalid status' });
    }

    if (!mongoose.Types.ObjectId.isValid(entryId)) {
      return res.status(400).json({ error: 'invalid entry id' });
    }

    const updateOps = { $set: { status } };
    if (status === 'pending') {
      updateOps.$unset = { withdrawalRequestId: '' };
    }

    const entry = await ReferralLedger.findByIdAndUpdate(entryId, updateOps, { new: true }).lean();

    if (!entry) {
      return res.status(404).json({ error: 'not found' });
    }

    return res.json({
      entry: {
        id: entry._id,
        amountPaise: entry.amountPaise,
        note: entry.note,
        status: entry.status,
        level: entry.level,
        sourceUserId: entry.sourceUserId ? entry.sourceUserId.toString() : null,
        topupExtRef: entry.topupExtRef || null,
        updatedAt: entry.updatedAt,
        createdAt: entry.createdAt,
      },
    });
  } catch (err) {
    console.error('admin referral status error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/admin/me', auth, admin, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'not found' });
    const hadCode = Boolean(user.referralCode);
    await ensureReferralCode(user);
    if (!hadCode && user.referralCode) {
      await user.save();
    }
    return res.json({ user: buildUserPayload(user) });
  } catch (err) {
    console.error('admin me error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

export default router;
