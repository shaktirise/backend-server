import express from 'express';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { OAuth2Client } from 'google-auth-library';
import User from '../models/User.js';
import Wallet from '../models/Wallet.js';
import WalletLedger from '../models/WalletLedger.js';
import { auth, admin } from '../middleware/auth.js';
import {
  ensureReferralCode,
  normalizeReferralCodeInput,
  buildReferralShareLink,
  getReferralConfig,
} from '../services/referral.js';

const router = express.Router();

const requestLimiter = rateLimit({ windowMs: 60 * 1000, max: 10 });

const ACCESS_TOKEN_TTL_SEC_RAW = Number.parseInt(process.env.ACCESS_TOKEN_TTL_SEC ?? '0', 10);
const ACCESS_TOKEN_TTL_SEC = Number.isFinite(ACCESS_TOKEN_TTL_SEC_RAW) && ACCESS_TOKEN_TTL_SEC_RAW > 0
  ? ACCESS_TOKEN_TTL_SEC_RAW
  : null;
const REFRESH_TOKEN_TTL_SEC_RAW = Number.parseInt(process.env.REFRESH_TOKEN_TTL_SEC ?? '0', 10);
const REFRESH_TOKEN_TTL_SEC = Number.isFinite(REFRESH_TOKEN_TTL_SEC_RAW) && REFRESH_TOKEN_TTL_SEC_RAW > 0
  ? REFRESH_TOKEN_TTL_SEC_RAW
  : null;
const REFRESH_TOKEN_BCRYPT_ROUNDS = parseInt(process.env.REFRESH_TOKEN_BCRYPT_ROUNDS || '10', 10);

const REFERRAL_CONFIG = getReferralConfig();
const FALLBACK_TREE_DEPTH = Math.max(1, REFERRAL_CONFIG.maxDepth || 3);

function signAccessToken(user) {
  const token = jwt.sign(
    { id: user._id.toString(), role: user.role },
    process.env.JWT_SECRET,
    ACCESS_TOKEN_TTL_SEC ? { expiresIn: ACCESS_TOKEN_TTL_SEC } : undefined,
  );
  const expiresAt = ACCESS_TOKEN_TTL_SEC
    ? new Date(Date.now() + ACCESS_TOKEN_TTL_SEC * 1000)
    : null;
  return { token, expiresAt };
}

async function attachRefreshToken(user) {
  const raw = crypto.randomBytes(48).toString('hex');
  const expiresAt = REFRESH_TOKEN_TTL_SEC
    ? new Date(Date.now() + REFRESH_TOKEN_TTL_SEC * 1000)
    : null;
  user.refreshTokenHash = await bcrypt.hash(raw, REFRESH_TOKEN_BCRYPT_ROUNDS);
  user.refreshTokenExpiresAt = expiresAt || undefined;
  return { refreshToken: `${user._id.toString()}.${raw}`, expiresAt };
}

async function issueAuthTokens(user) {
  const { token, expiresAt: tokenExpiresAt } = signAccessToken(user);
  const { refreshToken, expiresAt: refreshTokenExpiresAt } = await attachRefreshToken(user);
  return { token, tokenExpiresAt, refreshToken, refreshTokenExpiresAt };
}

function isValidName(n) {
  return typeof n === 'string' && n.trim().length >= 2 && n.trim().length <= 100;
}

function isValidEmail(e) {
  return typeof e === 'string' && /.+@.+\..+/.test(e.trim());
}

function isValidPassword(p) {
  return typeof p === 'string' && p.length >= 6 && p.length <= 100;
}

function buildUserPayload(user) {
  return {
    id: user._id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    role: user.role,
    walletBalance: user.walletBalance,
    accountStatus: user.accountStatus,
    accountActiveUntil: user.accountActiveUntil || null,
    referralCode: user.referralCode,
    referralShareLink: buildReferralShareLink(user.referralCode),
    referralCount: user.referralCount || 0,
    referralActivatedAt: user.referralActivatedAt || null,
    referredBy: user.referredBy ? user.referredBy.toString() : null,
  };
}

function resolveActivityStatus(user) {
  if (!user) return { isActive: null, activityStatus: null };
  const accountStatus = user.accountStatus || null;
  const blocked = accountStatus === 'SUSPENDED' || accountStatus === 'DEACTIVATED';
  const untilMs = user.accountActiveUntil ? new Date(user.accountActiveUntil).getTime() : 0;
  const isActive = !blocked && untilMs > Date.now();
  return { isActive, activityStatus: isActive ? 'ACTIVE' : 'INACTIVE' };
}

async function finalizeAuthSuccess(user, req) {
  const t0 = Date.now();
  user.lastLoginAt = new Date();
  user.lastLoginIp = req.ip;
  user.loginCount = (user.loginCount || 0) + 1;
  await ensureReferralCode(user);
  // Auto-sync membership status based on expiry
  if (user.accountStatus !== 'SUSPENDED' && user.accountStatus !== 'DEACTIVATED') {
    const until = user.accountActiveUntil ? user.accountActiveUntil.getTime() : 0;
    if (until > Date.now()) {
      user.accountStatus = 'ACTIVE';
    } else {
      user.accountStatus = 'INACTIVE';
    }
  }
  const t1 = Date.now();
  await user.save();
  const t2 = Date.now();
  const tokens = await issueAuthTokens(user);
  const t3 = Date.now();
  if (process.env.AUTH_TIMING_LOG === '1') {
    console.log(`auth timing(simple): ensureCode+save=${t2 - t0}ms issueTokens=${t3 - t2}ms total=${t3 - t0}ms`);
  }
  return tokens;
}

// SIGNUP with optional referral code
router.post('/signup', requestLimiter, async (req, res) => {
  try {
    const { name, email, password, confirmPassword } = req.body || {};
    const referralCodeInput = normalizeReferralCodeInput(
      req.body?.referralCode || req.body?.referral || req.body?.refCode || ''
    );

    if (!isValidName(name)) return res.status(400).json({ error: 'valid name required' });
    if (!isValidEmail(email)) return res.status(400).json({ error: 'valid email required' });
    if (!isValidPassword(password)) return res.status(400).json({ error: 'password must be 6-100 chars' });
    if (password !== confirmPassword) return res.status(400).json({ error: 'passwords do not match' });

    const emailNorm = String(email).trim().toLowerCase();
    const exists = await User.findOne({ email: emailNorm });
    if (exists) return res.status(409).json({ error: 'email already in use' });

    let referer = null;
    if (referralCodeInput) {
      referer = await User.findOne({ referralCode: referralCodeInput }).select('_id');
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
      user.referredBy = referer._id;
      user.referralActivatedAt = new Date();
    }

    await user.save();

    if (referer) {
      await User.updateOne({ _id: referer._id }, { $inc: { referralCount: 1 } });
    }

    const tokens = await finalizeAuthSuccess(user, req);

    return res.json({
      token: tokens.token,
      tokenExpiresAt: tokens.tokenExpiresAt,
      refreshToken: tokens.refreshToken,
      refreshTokenExpiresAt: tokens.refreshTokenExpiresAt,
      user: buildUserPayload(user),
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

// LOGIN with email + password
router.post('/login', requestLimiter, async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!isValidEmail(email) || !password) return res.status(400).json({ error: 'email and password required' });

    const user = await User.findOne({ email });
    if (!user || !user.passwordHash) return res.status(401).json({ error: 'invalid credentials' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });

    const tokens = await finalizeAuthSuccess(user, req);

    return res.json({
      token: tokens.token,
      tokenExpiresAt: tokens.tokenExpiresAt,
      refreshToken: tokens.refreshToken,
      refreshTokenExpiresAt: tokens.refreshTokenExpiresAt,
      user: buildUserPayload(user),
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

// GOOGLE login: expects { idToken, referralCode? }
const googleClientId = process.env.GOOGLE_CLIENT_ID || '';
const googleClient = googleClientId ? new OAuth2Client(googleClientId) : null;

router.post('/google', requestLimiter, async (req, res) => {
  try {
    const idToken = req.body?.idToken || req.body?.credential;
    const referralCodeInput = normalizeReferralCodeInput(
      req.body?.referralCode || req.body?.referral || req.body?.refCode || ''
    );

    if (!googleClient) return res.status(500).json({ error: 'google login not configured' });
    if (!idToken || typeof idToken !== 'string') return res.status(400).json({ error: 'idToken required' });

    const ticket = await googleClient.verifyIdToken({ idToken, audience: googleClientId });
    const payload = ticket.getPayload();
    const email = String(payload.email || '').toLowerCase();
    const emailVerified = Boolean(payload.email_verified);
    const name = payload.name || payload.given_name || 'User';

    if (!email || !emailVerified) return res.status(401).json({ error: 'google email not verified' });

    let user = await User.findOne({ email });
    let referer = null;
    const isNew = !user;

    if (!user) {
      user = new User({ email, name });
      if (referralCodeInput) {
        referer = await User.findOne({ referralCode: referralCodeInput }).select('_id');
        if (referer && !referer._id.equals(user._id)) {
          user.referredBy = referer._id;
          user.referralActivatedAt = new Date();
        }
      }
      await user.save();
      if (referer) {
        await User.updateOne({ _id: referer._id }, { $inc: { referralCount: 1 } });
      }
    }

    const tokens = await finalizeAuthSuccess(user, req);

    return res.json({
      token: tokens.token,
      tokenExpiresAt: tokens.tokenExpiresAt,
      refreshToken: tokens.refreshToken,
      refreshTokenExpiresAt: tokens.refreshTokenExpiresAt,
      user: buildUserPayload(user),
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

// Refresh token
router.post('/refresh-token', async (req, res) => {
  try {
    const provided = req.body?.refreshToken;
    if (typeof provided !== 'string' || !provided.length) return res.status(400).json({ error: 'refreshToken required' });

    const [userId, raw] = provided.split('.');
    if (!userId || !raw) return res.status(400).json({ error: 'invalid refresh token' });

    const user = await User.findById(userId);
    if (!user || !user.refreshTokenHash) return res.status(401).json({ error: 'invalid refresh token' });

    if (user.refreshTokenExpiresAt && user.refreshTokenExpiresAt.getTime() < Date.now()) {
      user.refreshTokenHash = undefined;
      user.refreshTokenExpiresAt = undefined;
      await user.save();
      return res.status(401).json({ error: 'refresh token expired' });
    }

    const ok = await bcrypt.compare(raw, user.refreshTokenHash);
    if (!ok) return res.status(401).json({ error: 'invalid refresh token' });

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
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'user not found' });
    await ensureReferralCode(user);
    return res.json({ user: buildUserPayload(user) });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

router.put(['/me', '/profile'], auth, async (req, res) => {
  try {
    const { name, email } = req.body || {};
    const update = {};
    if (typeof name === 'string') update.name = name.trim();
    if (typeof email === 'string') update.email = email.trim().toLowerCase();
    if (Object.keys(update).length === 0) return res.status(400).json({ error: 'no updatable fields' });

    const user = await User.findByIdAndUpdate(req.user.id, { $set: update }, { new: true });
    if (!user) return res.status(404).json({ error: 'user not found' });
    await ensureReferralCode(user);

    return res.json({ user: buildUserPayload(user) });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/referrals', auth, async (req, res) => {
  try {
    const limitRaw = parseInt(req.query?.limit ?? '50', 10);
    const offsetRaw = parseInt(req.query?.offset ?? '0', 10);
    const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 200) : 50;
    const offset = Number.isFinite(offsetRaw) && offsetRaw > 0 ? offsetRaw : 0;

    const query = { referredBy: req.user.id };

    const [referrals, total] = await Promise.all([
      User.find(query)
        .sort({ createdAt: -1 })
        .skip(offset)
        .limit(limit)
        .select('_id name email phone referralCode createdAt referralActivatedAt loginCount'),
      User.countDocuments(query),
    ]);

    return res.json({
      total,
      offset,
      limit,
      referrals: referrals.map((ref) => ({
        id: ref._id,
        name: ref.name,
        email: ref.email,
        phone: ref.phone,
        referralCode: ref.referralCode,
        referralShareLink: buildReferralShareLink(ref.referralCode),
        createdAt: ref.createdAt,
        referralActivatedAt: ref.referralActivatedAt,
        loginCount: ref.loginCount || 0,
      })),
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/referrals/tree', auth, async (req, res) => {
  try {
    const depthRaw = parseInt(req.query?.depth ?? `${FALLBACK_TREE_DEPTH}`, 10);
    const depth = Number.isFinite(depthRaw) && depthRaw > 0 ? Math.min(depthRaw, 5) : FALLBACK_TREE_DEPTH;

    const levels = [];
    let currentLevel = [req.user.id];

    for (let level = 1; level <= depth && currentLevel.length; level += 1) {
      const nextLevelUsers = await User.find({ referredBy: { $in: currentLevel } })
        .select('_id name email phone referralCode referredBy referralActivatedAt createdAt loginCount accountStatus accountActiveUntil')
        .lean();

      if (!nextLevelUsers.length) break;

      levels.push({
        level,
        users: nextLevelUsers.map((u) => ({
          ...resolveActivityStatus(u),
          id: u._id,
          name: u.name,
          email: u.email,
          phone: u.phone,
          referralCode: u.referralCode,
          referralShareLink: buildReferralShareLink(u.referralCode),
          referralActivatedAt: u.referralActivatedAt,
          referredBy: u.referredBy ? u.referredBy.toString() : null,
          createdAt: u.createdAt,
          loginCount: u.loginCount || 0,
        })),
      });

      currentLevel = nextLevelUsers.map((u) => u._id);
    }

    return res.json({ depth: levels.length, levels });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/referrals/earnings', auth, async (req, res) => {
  try {
    const wallet = await Wallet.findOne({ userId: req.user.id }).lean();
    if (!wallet) {
      return res.json({ totalEarnedPaise: 0, entries: [] });
    }

    const entries = await WalletLedger.find({ walletId: wallet._id, extRef: { $regex: '^refTopup:' } })
      .sort({ createdAt: -1 })
      .select('amount note createdAt extRef')
      .lean();

    const totalEarnedPaise = entries.reduce((sum, entry) => sum + (entry.amount || 0), 0);

    return res.json({
      totalEarnedPaise,
      entries: entries.map((entry) => ({
        amount: entry.amount,
        note: entry.note,
        createdAt: entry.createdAt,
        extRef: entry.extRef,
      })),
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/admin/me', auth, admin, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'not found' });
    await ensureReferralCode(user);
    return res.json({ user: buildUserPayload(user) });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

export default router;
