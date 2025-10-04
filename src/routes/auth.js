import express from 'express';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import User from '../models/User.js';
import { sendOtpSms } from '../services/sms.js';
import { auth, admin } from '../middleware/auth.js';

const router = express.Router();

const requestLimiter = rateLimit({ windowMs: 60 * 1000, max: 5 });

const ACCESS_TOKEN_TTL_SEC = parseInt(process.env.ACCESS_TOKEN_TTL_SEC || '3600', 10); // 1 hour default
const REFRESH_TOKEN_TTL_SEC = parseInt(process.env.REFRESH_TOKEN_TTL_SEC || String(3 * 24 * 60 * 60), 10); // 3 days default
const REFRESH_TOKEN_BCRYPT_ROUNDS = parseInt(process.env.REFRESH_TOKEN_BCRYPT_ROUNDS || '12', 10);

function buildUserPayload(user) {
  return {
    id: user._id,
    phone: user.phone,
    name: user.name,
    email: user.email,
    role: user.role,
    walletBalance: user.walletBalance,
  };
}

function signAccessToken(user) {
  const expiresAt = new Date(Date.now() + ACCESS_TOKEN_TTL_SEC * 1000);
  const token = jwt.sign(
    { id: user._id.toString(), role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_TTL_SEC }
  );
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

function genOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// Minimal, loose E.164 normalizer: keeps leading + and digits only
function normalizeE164Loose(input = '') {
  const s = String(input).trim();
  const kept = s.replace(/[^\d+]/g, '');
  // If it starts with 0 or doesn't include country code, you may add your own logic.
  return kept;
}

function isValidPhoneLoose(p) {
  // Accepts + and 8-15 digits overall (rough E.164 bounds)
  return /^\+?[1-9]\d{7,14}$/.test(p);
}

function isValidName(n) {
  return typeof n === 'string' && n.trim().length >= 2 && n.trim().length <= 100;
}

const adminOtpAllowedPhones = String(process.env.ADMIN_OTP_ALLOWED_PHONES || '')
  .split(',')
  .map((value) => normalizeE164Loose(value))
  .filter((value) => isValidPhoneLoose(value));

const adminOtpAllowedSet = new Set(adminOtpAllowedPhones);
const restrictAdminOtp = adminOtpAllowedSet.size > 0;

function isAdminPhoneAllowed(phone) {
  if (!restrictAdminOtp) return true;
  return adminOtpAllowedSet.has(phone);
}

function getAdminOtpExpiryMinutes() {
  const raw = process.env.ADMIN_OTP_EXP_MIN || process.env.OTP_EXP_MIN || '10';
  const parsed = parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 10;
}

// Accept both /request-otp and /requestOtp
// CHANGE: now requires BOTH name and phone to send OTP.
// We persist name immediately (create-or-update) with the phone.
router.post(['/request-otp', '/requestOtp'], requestLimiter, async (req, res) => {
  try {
    const rawPhone = req.body?.phone ?? '';
    const rawName = req.body?.name ?? '';
    const phoneStr = normalizeE164Loose(rawPhone);
    const name = String(rawName).trim();

    if (!isValidName(name)) {
      return res.status(400).json({ error: 'valid name (2-100 chars) required' });
    }
    if (!isValidPhoneLoose(phoneStr)) {
      return res.status(400).json({ error: 'valid phone required (E.164, e.g., +9198xxxxxx)' });
    }

    let user = await User.findOne({ phone: phoneStr });
    if (!user) {
      user = await User.create({ phone: phoneStr, name });
    } else {
      user.name = name;
    }

    const otp = genOtp();
    const hash = await bcrypt.hash(otp, 10);
    const expMin = parseInt(process.env.OTP_EXP_MIN || '10', 10);

    user.otpHash = hash;
    user.otpExpiresAt = new Date(Date.now() + expMin * 60 * 1000);
    user.lastOtpAt = new Date();
    user.lastOtpIp = req.ip;
    await user.save();

    const sent = await sendOtpSms(phoneStr, otp);
    if (!sent) {
      
      console.log(`[OTP][DEV] Phone=${phoneStr} Code=${otp}`);
    }

    return res.json({ ok: true, message: 'OTP sent' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post(['/admin/request-otp', '/admin/requestOtp'], requestLimiter, async (req, res) => {
  try {
    const rawPhone = req.body?.phone ?? '';
    const rawName = req.body?.name ?? '';
    const phoneStr = normalizeE164Loose(rawPhone);
    const name = String(rawName).trim();

    if (!isValidName(name)) {
      return res.status(400).json({ error: 'valid name (2-100 chars) required' });
    }
    if (!isValidPhoneLoose(phoneStr)) {
      return res.status(400).json({ error: 'valid phone required (E.164, e.g., +9198xxxxxx)' });
    }
    if (!isAdminPhoneAllowed(phoneStr)) {
      return res.status(403).json({ error: 'phone not authorized for admin access' });
    }

    let user = await User.findOne({ phone: phoneStr });
    if (!user) {
      user = await User.create({ phone: phoneStr, name, role: 'admin' });
    } else {
      user.name = name;
      if (user.role !== 'admin') {
        user.role = 'admin';
      }
    }

    const otp = genOtp();
    const hash = await bcrypt.hash(otp, 10);
    const expMin = getAdminOtpExpiryMinutes();

    user.otpHash = hash;
    user.otpExpiresAt = new Date(Date.now() + expMin * 60 * 1000);
    user.lastOtpAt = new Date();
    user.lastOtpIp = req.ip;
    await user.save();

    const sent = await sendOtpSms(phoneStr, otp);
    if (!sent) {
      console.log(`[ADMIN OTP][DEV] Phone=${phoneStr} Code=${otp}`);
    }

    return res.json({ ok: true, message: 'OTP sent' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post(['/verify-otp', '/verifyOtp'], async (req, res) => {
  try {
    const phoneStr = normalizeE164Loose(req.body?.phone ?? '');
    const otpStr = String(req.body?.otp ?? '').trim();

    if (!isValidPhoneLoose(phoneStr) || !otpStr) {
      return res.status(400).json({ error: 'phone and otp required' });
    }

    const user = await User.findOne({ phone: phoneStr });
    if (!user || !user.otpHash || !user.otpExpiresAt) {
      return res.status(400).json({ error: 'invalid request' });
    }
    if (user.otpExpiresAt.getTime() < Date.now()) {
      return res.status(400).json({ error: 'otp expired' });
    }

    const ok = await bcrypt.compare(otpStr, user.otpHash);
    if (!ok) return res.status(400).json({ error: 'invalid otp' });

    // Clear OTP state and finalize login
    user.otpHash = undefined;
    user.otpExpiresAt = undefined;
    user.lastLoginAt = new Date();
    user.lastLoginIp = req.ip;
    user.loginCount = (user.loginCount || 0) + 1;

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

// Admin: verify OTP
router.post(['/admin/verify-otp', '/admin/verifyOtp'], async (req, res) => {
  try {
    const phoneStr = normalizeE164Loose(req.body?.phone ?? '');
    const otpStr = String(req.body?.otp ?? '').trim();

    if (!isValidPhoneLoose(phoneStr) || !otpStr) {
      return res.status(400).json({ error: 'phone and otp required' });
    }
    if (!isAdminPhoneAllowed(phoneStr)) {
      return res.status(403).json({ error: 'phone not authorized for admin access' });
    }

    const user = await User.findOne({ phone: phoneStr });
    if (!user || !user.otpHash || !user.otpExpiresAt) {
      return res.status(400).json({ error: 'invalid request' });
    }
    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'not an admin account' });
    }
    if (user.otpExpiresAt.getTime() < Date.now()) {
      return res.status(400).json({ error: 'otp expired' });
    }

    const ok = await bcrypt.compare(otpStr, user.otpHash);
    if (!ok) return res.status(400).json({ error: 'invalid otp' });

    user.otpHash = undefined;
    user.otpExpiresAt = undefined;
    user.role = 'admin';
    user.lastLoginAt = new Date();
    user.lastLoginIp = req.ip;
    user.loginCount = (user.loginCount || 0) + 1;

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
    if (!user || !user.refreshTokenHash || !user.refreshTokenExpiresAt) {
      return res.status(401).json({ error: 'invalid refresh token' });
    }

    if (user.refreshTokenExpiresAt.getTime() < Date.now()) {
      user.refreshTokenHash = undefined;
      user.refreshTokenExpiresAt = undefined;
      await user.save();
      return res.status(401).json({ error: 'refresh token expired' });
    }

    const ok = await bcrypt.compare(raw, user.refreshTokenHash);
    if (!ok) {
      return res.status(401).json({ error: 'invalid refresh token' });
    }

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


router.get('/admin/me', auth, admin, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'not found' });
    return res.json({
      user: { id: user._id, name: user.name, email: user.email, role: user.role, walletBalance: user.walletBalance }
    });
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
    if (Object.keys(update).length === 0) {
      return res.status(400).json({ error: 'no updatable fields' });
    }

    const user = await User.findByIdAndUpdate(req.user.id, { $set: update }, { new: true });
    if (!user) return res.status(404).json({ error: 'user not found' });

    return res.json({
      user: { id: user._id, phone: user.phone, name: user.name, email: user.email, role: user.role, walletBalance: user.walletBalance }
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

export default router;
