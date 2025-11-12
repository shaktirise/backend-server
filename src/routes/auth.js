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
import { formatLocalISO, toEpochMs } from '../utils/time.js';
import { backfillUserMembership } from '../services/membership.js';
import {
  ensureReferralCode,
  normalizeReferralCodeInput,
  buildReferralShareLink,
  getReferralConfig,
} from '../services/referral.js';

const router = express.Router();

const requestLimiter = rateLimit({ windowMs: 60 * 1000, max: 15 });

const ACCESS_TOKEN_TTL_SEC_RAW = Number.parseInt(
  process.env.ACCESS_TOKEN_TTL_SEC ?? '0',
  10,
);
const ACCESS_TOKEN_TTL_SEC = Number.isFinite(ACCESS_TOKEN_TTL_SEC_RAW)
  && ACCESS_TOKEN_TTL_SEC_RAW > 0
  ? ACCESS_TOKEN_TTL_SEC_RAW
  : null;
const REFRESH_TOKEN_TTL_SEC_RAW = Number.parseInt(
  process.env.REFRESH_TOKEN_TTL_SEC ?? '0',
  10,
);
const REFRESH_TOKEN_TTL_SEC = Number.isFinite(REFRESH_TOKEN_TTL_SEC_RAW)
  && REFRESH_TOKEN_TTL_SEC_RAW > 0
  ? REFRESH_TOKEN_TTL_SEC_RAW
  : null;
// Lower default rounds to 10 to reduce login latency on small instances.
const REFRESH_TOKEN_BCRYPT_ROUNDS = parseInt(
  process.env.REFRESH_TOKEN_BCRYPT_ROUNDS || '10',
  10,
);

// Password reset config
const RESET_TOKEN_TTL_MIN = parseInt(process.env.RESET_TOKEN_TTL_MIN || '15', 10);
const EXPOSE_RESET_TOKEN =
  (process.env.EXPOSE_RESET_TOKEN === '1') || (process.env.NODE_ENV !== 'production');

function isValidName(name) {
  return typeof name === 'string' && name.trim().length >= 2 && name.trim().length <= 100;
}

function isValidEmail(email) {
  return typeof email === 'string' && /.+@.+\..+/.test(email.trim());
}

function isValidPassword(password) {
  return typeof password === 'string' && password.length >= 8 && password.length <= 128;
}

// Normalize mobile numbers to E.164 format.
// Defaults 10-digit numbers to +91 (India) for Indian users.
function toE164IndianDefault(phone) {
  if (!phone) return null;
  const raw = String(phone).replace(/\s|-/g, '');
  if (raw.startsWith('+')) return raw;
  if (/^\d{10}$/.test(raw)) return `+91${raw}`;
  if (/^\d{11,15}$/.test(raw)) return `+${raw}`;
  return null;
}

function signAccessToken(user) {
  const payload = {
    id: user._id.toString(),
    sub: user._id.toString(),
    role: user.role,
  };
  const token = jwt.sign(
    payload,
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

function buildUserPayload(user) {
  return {
    id: user._id,
    name: user.name,
    email: user.email,
    phone: user.phone || null,
    role: user.role,
    walletBalance: user.walletBalance,
    accountStatus: user.accountStatus,
    accountActiveUntil: user.accountActiveUntil || null,
    accountActiveUntilLocal: user.accountActiveUntil ? formatLocalISO(user.accountActiveUntil) : null,
    accountActiveUntilMs: user.accountActiveUntil ? toEpochMs(user.accountActiveUntil) : null,
    referralCode: user.referralCode,
    referralShareLink: buildReferralShareLink(user.referralCode),
    referralCount: user.referralCount || 0,
    referralActivatedAt: user.referralActivatedAt || null,
    referralActivatedAtLocal: user.referralActivatedAt ? formatLocalISO(user.referralActivatedAt) : null,
    referralActivatedAtMs: user.referralActivatedAt ? toEpochMs(user.referralActivatedAt) : null,
    referredBy: user.referredBy ? user.referredBy.toString() : null,
    pendingReferredBy: user.pendingReferredBy ? user.pendingReferredBy.toString() : null,
    lastLoginAt: user.lastLoginAt || null,
  };
}

function buildMembershipPayload(user) {
  const now = Date.now();
  const activatedAt = user.accountActivatedAt || null;
  const activeUntil = user.accountActiveUntil || null;
  const untilMs = activeUntil ? activeUntil.getTime() : 0;
  const remainingMs = Math.max(0, untilMs - now);
  const isActive = untilMs > now;
  return {
    status: user.accountStatus || 'INACTIVE',
    isActive,
    nowMs: now,
    activatedAt,
    activatedAtLocal: activatedAt ? formatLocalISO(activatedAt) : null,
    activatedAtMs: activatedAt ? toEpochMs(activatedAt) : null,
    activeUntil,
    activeUntilLocal: activeUntil ? formatLocalISO(activeUntil) : null,
    activeUntilMs: activeUntil ? untilMs : null,
    remainingMs,
    remainingSeconds: Math.floor(remainingMs / 1000),
    remainingDays: activeUntil ? Math.ceil(remainingMs / (24 * 60 * 60 * 1000)) : 0,
  };
}

function syncAccountStatus(user) {
  // Manage only ACTIVE/INACTIVE automatically; respect SUSPENDED/DEACTIVATED
  if (user.accountStatus === 'SUSPENDED' || user.accountStatus === 'DEACTIVATED') return false;
  const now = Date.now();
  const until = user.accountActiveUntil ? user.accountActiveUntil.getTime() : 0;
  let changed = false;
  if (until > now) {
    if (user.accountStatus !== 'ACTIVE') {
      user.accountStatus = 'ACTIVE';
      changed = true;
    }
  } else {
    if (user.accountStatus !== 'INACTIVE') {
      user.accountStatus = 'INACTIVE';
      changed = true;
    }
  }
  return changed;
}

function serializeWithdrawalRequest(doc) {
  if (!doc) return null;
  return {
    id: doc._id,
    amountPaise: doc.amountPaise,
    amountRupees: Number.isFinite(doc.amountPaise) ? Math.floor(doc.amountPaise / 100) : 0,
    method: doc.method || null,
    upiId: doc.upiId || null,
    bank: {
      accountName: doc.bankAccountName || null,
      accountNumber: doc.bankAccountNumber || null,
      ifsc: doc.bankIfsc || null,
      bankName: doc.bankName || null,
    },
    contactName: doc.contactName || null,
    contactMobile: doc.contactMobile || null,
    status: doc.status,
    paymentRef: doc.paymentRef || null,
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
  const t0 = Date.now();
  if (!user.referralCode) {
    await ensureReferralCode(user);
  }
  const t1 = Date.now();
  user.lastLoginAt = new Date();
  user.lastLoginIp = req.ip;
  user.loginCount = (user.loginCount || 0) + 1;
  // Auto-sync membership status based on expiry
  syncAccountStatus(user);
  const tokens = await issueAuthTokens(user);
  const t2 = Date.now();
  await user.save();
  const t3 = Date.now();
  if (process.env.AUTH_TIMING_LOG === '1') {
    console.log(
      `auth timing: ensureCode=${t1 - t0}ms issueTokens=${t2 - t1}ms save=${t3 - t2}ms total=${t3 - t0}ms`
    );
  }
  return tokens;
}

router.post('/signup', requestLimiter, async (req, res) => {
  try {
    const { name, email, password, confirmPassword, referralId } = req.body || {};
    // Optional mobile number; normalize to E.164 (+91 default for 10-digit input)
    const rawPhone = (req.body?.phone || req.body?.mobile || req.body?.mobileNumber || '')
      .toString()
      .trim();
    const phone = rawPhone ? toE164IndianDefault(rawPhone) : null;
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
    if (rawPhone && !phone) {
      return res.status(400).json({ error: 'valid Indian mobile required' });
    }

    const emailNorm = String(email).trim().toLowerCase();
    const existing = await User.findOne({ email: emailNorm });
    if (existing) {
      return res.status(409).json({ error: 'email already registered' });
    }

    if (phone) {
      const phoneExists = await User.findOne({ phone });
      if (phoneExists) {
        return res.status(409).json({ error: 'phone already registered' });
      }
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
      ...(phone ? { phone } : {}),
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
      membership: buildMembershipPayload(user),
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
      membership: buildMembershipPayload(user),
    });
  } catch (err) {
    console.error('login error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

// Request password reset token
router.post('/forgot-password', requestLimiter, async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'valid email required' });
    }

    // Always respond 200 to avoid user enumeration
    const user = await User.findOne({ email });
    let resetTokenToExpose = null;
    if (user && user.passwordHash) {
      const raw = crypto.randomBytes(24).toString('hex');
      const hash = await bcrypt.hash(raw, REFRESH_TOKEN_BCRYPT_ROUNDS);
      user.resetPasswordTokenHash = hash;
      user.resetPasswordExpiresAt = new Date(Date.now() + Math.max(1, RESET_TOKEN_TTL_MIN) * 60 * 1000);
      await user.save();
      if (EXPOSE_RESET_TOKEN) resetTokenToExpose = raw;
      // In production, you should email/SMS the token or a link containing it.
    }

    return res.json({ ok: true, ...(resetTokenToExpose ? { resetToken: resetTokenToExpose } : {}) });
  } catch (err) {
    console.error('forgot-password error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

// Reset password using token
router.post('/reset-password', requestLimiter, async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const token = String(req.body?.token || '').trim();
    const password = String(req.body?.password || '');
    const confirmPassword =
      req.body?.confirmPassword ?? req.body?.confirmPass ?? req.body?.confirmpass;

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'valid email required' });
    }
    if (!token) {
      return res.status(400).json({ error: 'token required' });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ error: 'password must be 8-128 chars' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'passwords do not match' });
    }

    const user = await User.findOne({ email });
    if (!user || !user.resetPasswordTokenHash || !user.resetPasswordExpiresAt) {
      return res.status(400).json({ error: 'invalid_or_expired_token' });
    }

    if (user.resetPasswordExpiresAt.getTime() < Date.now()) {
      return res.status(400).json({ error: 'invalid_or_expired_token' });
    }

    const ok = await bcrypt.compare(token, user.resetPasswordTokenHash);
    if (!ok) {
      return res.status(400).json({ error: 'invalid_or_expired_token' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    user.passwordHash = passwordHash;
    user.resetPasswordTokenHash = undefined;
    user.resetPasswordExpiresAt = undefined;
    // Invalidate any existing refresh token on password reset
    user.refreshTokenHash = undefined;
    user.refreshTokenExpiresAt = undefined;
    await user.save();

    return res.json({ ok: true });
  } catch (err) {
    console.error('reset-password error', err);
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
    if (!user || !user.refreshTokenHash) {
      return res.status(401).json({ error: 'invalid refresh token' });
    }

    if (
      user.refreshTokenExpiresAt
      && user.refreshTokenExpiresAt.getTime() < Date.now()
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
    let changed = false;
    if (syncAccountStatus(user)) changed = true;
    if ((!hadCode && user.referralCode) || changed) {
      await user.save();
    }

    return res.json({ user: buildUserPayload(user), membership: buildMembershipPayload(user) });
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

    // Allow users to set/update their mobile number (info-only)
    if (
      typeof (req.body?.phone ?? req.body?.mobile ?? req.body?.mobileNumber) !== 'undefined'
    ) {
      const rawPhone = (req.body?.phone || req.body?.mobile || req.body?.mobileNumber || '')
        .toString()
        .trim();
      const phone = rawPhone ? toE164IndianDefault(rawPhone) : null;
      if (rawPhone && !phone) {
        return res.status(400).json({ error: 'valid Indian mobile required' });
      }
      if (phone && phone !== user.phone) {
        const exists = await User.findOne({ phone });
        if (exists && exists._id.toString() !== user._id.toString()) {
          return res.status(409).json({ error: 'phone already registered' });
        }
        user.phone = phone;
      }
    }

    await ensureReferralCode(user);
    await user.save();

    return res.json({ user: buildUserPayload(user), membership: buildMembershipPayload(user) });
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
        .select('_id name email phone referralCode createdAt'),
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
        phone: ref.phone || null,
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

// Check level-1 commission entries for a specific downline
router.get('/referrals/level1', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const downlineId = String(req.query?.downlineId || '').trim();

    if (!downlineId || !mongoose.Types.ObjectId.isValid(downlineId)) {
      return res.status(400).json({ error: 'invalid downlineId' });
    }

    const entries = await ReferralLedger.find({
      userId,
      level: 1,
      sourceUserId: downlineId,
    })
      .sort({ createdAt: -1 })
      .select('amountPaise note createdAt status level sourceUserId topupExtRef withdrawalRequestId')
      .lean();

    const totals = entries.reduce(
      (acc, entry) => {
        const amount = entry.amountPaise || 0;
        if (entry.status === 'paid') acc.paid += amount;
        else if (entry.status === 'cancelled') acc.cancelled += amount;
        else acc.pending += amount;
        return acc;
      },
      { pending: 0, paid: 0, cancelled: 0 },
    );

    return res.json({
      downlineId,
      count: entries.length,
      totalEarnedPaise: totals.pending + totals.paid,
      totalPendingPaise: totals.pending,
      totalPaidPaise: totals.paid,
      totalCancelledPaise: totals.cancelled,
      entries: entries.map((e) => ({
        id: e._id,
        amountPaise: e.amountPaise,
        status: e.status,
        createdAt: e.createdAt,
        note: e.note,
        topupExtRef: e.topupExtRef || null,
        withdrawalRequestId: e.withdrawalRequestId || null,
      })),
    });
  } catch (err) {
    console.error('referral level1 check error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/referrals/withdraw', auth, async (req, res) => {
  const userId = req.user.id;
  const note = typeof req.body?.note === 'string' && req.body.note.trim() ? req.body.note.trim() : undefined;
  // capture payout details (optional)
  const methodRaw = (req.body?.method || '').toString().trim().toUpperCase();
  const method = methodRaw === 'BANK' ? 'BANK' : 'UPI';
  const upiId = req.body?.upiId || undefined;
  const bankAccountName = req.body?.bankAccountName || undefined;
  const bankAccountNumber = req.body?.bankAccountNumber || undefined;
  const bankIfsc = req.body?.bankIfsc || undefined;
  const bankName = req.body?.bankName || undefined;
  const contactName = req.body?.name || req.body?.contactName || undefined;
  const contactMobile = req.body?.mobile || req.body?.contactMobile || undefined;
  try {
    // Block demo users from withdrawing referral amounts
    const u = await User.findById(userId).select('isDemo').lean();
    if (u?.isDemo) {
      return res.status(403).json({ error: 'demo_accounts_cannot_withdraw' });
    }

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
              method,
              upiId,
              bankAccountName,
              bankAccountNumber,
              bankIfsc,
              bankName,
              contactName,
              contactMobile,
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
      registrationAmountsPaise: config.registrationAmountsPaise,
      renewalAmountsPaise: config.renewalAmountsPaise,
      registrationFeePaise: config.registrationFeePaise,
      renewalFeePaise: config.renewalFeePaise,
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
    let changed = false;
    if (syncAccountStatus(user)) changed = true;
    if ((!hadCode && user.referralCode) || changed) {
      await user.save();
    }
    return res.json({ user: buildUserPayload(user), membership: buildMembershipPayload(user) });
  } catch (err) {
    console.error('admin me error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

// Pending (non-activated) referrals: users who signed up with your code but haven't paid the ₹2100 activation
// GET /api/auth/referrals/pending?limit=50&offset=0
router.get('/referrals/pending', auth, async (req, res) => {
  try {
    const limitRaw = parseInt(req.query?.limit ?? '50', 10);
    const offsetRaw = parseInt(req.query?.offset ?? '0', 10);
    const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 200) : 50;
    const offset = Number.isFinite(offsetRaw) && offsetRaw > 0 ? offsetRaw : 0;

    const [items, total] = await Promise.all([
      User.find({ pendingReferredBy: req.user.id })
        .sort({ createdAt: -1 })
        .skip(offset)
        .limit(limit)
        .select('_id name email phone referralCode createdAt')
        .lean(),
      User.countDocuments({ pendingReferredBy: req.user.id }),
    ]);

    return res.json({
      total,
      offset,
      limit,
      items: items.map((u) => ({
        id: u._id,
        name: u.name || null,
        phone: u.phone || null,
        email: u.email || null,
        referralCode: u.referralCode || null,
        referralShareLink: buildReferralShareLink(u.referralCode),
        createdAt: u.createdAt,
      })),
    });
  } catch (err) {
    console.error('pending referrals error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

// Active referrals (activated by paying the registration amount)
// GET /api/auth/referrals/active?limit=50&offset=0
router.get('/referrals/active', auth, async (req, res) => {
  try {
    const limitRaw = parseInt(req.query?.limit ?? '50', 10);
    const offsetRaw = parseInt(req.query?.offset ?? '0', 10);
    const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 200) : 50;
    const offset = Number.isFinite(offsetRaw) && offsetRaw > 0 ? offsetRaw : 0;

    const [items, total] = await Promise.all([
      User.find({ referredBy: req.user.id })
        .sort({ createdAt: -1 })
        .skip(offset)
        .limit(limit)
        .select('_id name email phone referralCode referralActivatedAt createdAt loginCount')
        .lean(),
      User.countDocuments({ referredBy: req.user.id }),
    ]);

    return res.json({
      total,
      offset,
      limit,
      items: items.map((u) => ({
        id: u._id,
        name: u.name || null,
        phone: u.phone || null,
        email: u.email || null,
        referralCode: u.referralCode || null,
        referralShareLink: buildReferralShareLink(u.referralCode),
        createdAt: u.createdAt,
        referralActivatedAt: u.referralActivatedAt || null,
        loginCount: u.loginCount || 0,
      })),
    });
  } catch (err) {
    console.error('active referrals error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

// Backfill membership for the current user based on historical activation/top-up events.
// POST /api/auth/membership/backfill { dryRun?: boolean }
router.post('/membership/backfill', auth, async (req, res) => {
  try {
    const dryRun = req.body?.dryRun === true || String(req.query?.dryRun || req.query?.dry || '').toLowerCase() === 'true';
    const result = await backfillUserMembership(req.user.id, { save: !dryRun });
    const user = await User.findById(req.user.id);
    return res.json({
      ok: true,
      dryRun: !!dryRun,
      updated: result.updated && !dryRun,
      membership: buildMembershipPayload(user),
    });
  } catch (err) {
    console.error('membership backfill error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

export default router;
