import crypto from 'crypto';
import User from '../models/User.js';
import Wallet from '../models/Wallet.js';
import WalletLedger from '../models/WalletLedger.js';
import { ensureWallet } from './wallet.js';

const REFERRAL_CODE_ALPHABET = process.env.REFERRAL_CODE_ALPHABET || 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

const REFERRAL_CODE_LENGTH = (() => {
  const raw = parseInt(process.env.REFERRAL_CODE_LENGTH || '8', 10);
  if (Number.isFinite(raw) && raw >= 4 && raw <= 16) return raw;
  return 8;
})();

const DEFAULT_LEVEL_PERCENTAGES = [10, 5, 2];

function generateReferralCode() {
  const bytes = crypto.randomBytes(REFERRAL_CODE_LENGTH);
  let result = '';
  for (let i = 0; i < REFERRAL_CODE_LENGTH; i += 1) {
    const idx = bytes[i] % REFERRAL_CODE_ALPHABET.length;
    result += REFERRAL_CODE_ALPHABET[idx];
  }
  return result;
}

export function normalizeReferralCodeInput(value) {
  return String(value || '')
    .trim()
    .toUpperCase();
}

function parseLevelPercentages() {
  const raw = String(process.env.REFERRAL_LEVEL_PERCENTAGES || '')
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);

  const percentNumbers = raw
    .map((part) => Number.parseFloat(part))
    .filter((num) => Number.isFinite(num) && num > 0);

  const source = percentNumbers.length ? percentNumbers : DEFAULT_LEVEL_PERCENTAGES;
  return source.map((value) => value / 100);
}

function parseMinActivationPaise() {
  const raw = Number.parseInt(process.env.REFERRAL_MIN_ACTIVATION_RUPEES || '1000', 10);
  if (!Number.isFinite(raw) || raw < 0) return 1000 * 100;
  return raw * 100;
}

export function getReferralConfig() {
  const levelPercentages = parseLevelPercentages();
  const maxDepthEnv = Number.parseInt(process.env.REFERRAL_MAX_DEPTH || `${levelPercentages.length}`, 10);
  const maxDepth = Number.isFinite(maxDepthEnv) && maxDepthEnv > 0
    ? Math.min(maxDepthEnv, levelPercentages.length)
    : levelPercentages.length;

  const shareBaseUrl = process.env.REFERRAL_SHARE_BASE_URL || process.env.APP_DOWNLOAD_URL || '';

  return {
    levelPercentages,
    maxDepth,
    minActivationPaise: parseMinActivationPaise(),
    shareBaseUrl,
  };
}

export function buildReferralShareLink(code) {
  if (!code) return null;
  const { shareBaseUrl } = getReferralConfig();
  if (!shareBaseUrl) return null;
  try {
    if (shareBaseUrl.includes('{{code}}')) {
      return shareBaseUrl.replace(/{{code}}/g, code);
    }
    const url = new URL(shareBaseUrl);
    url.searchParams.set('ref', code);
    return url.toString();
  } catch (err) {
    return null;
  }
}

export async function ensureReferralCode(user) {
  if (!user) throw new Error('user required to ensure referral code');
  if (user.referralCode) return user.referralCode;

  for (let attempt = 0; attempt < 10; attempt += 1) {
    const candidate = generateReferralCode();
    const exists = await User.exists({ referralCode: candidate });
    if (!exists) {
      user.referralCode = candidate;
      return candidate;
    }
  }

  throw new Error('failed to allocate referral code');
}

async function loadAncestorChain(startUserId, depth, session) {
  const ancestors = [];
  let currentId = startUserId;

  for (let level = 0; level < depth && currentId; level += 1) {
    const query = User.findById(currentId).select('_id name email referralCode referredBy');
    if (session) query.session(session);
    const doc = await query.exec();
    if (!doc) break;
    ancestors.push(doc);
    currentId = doc.referredBy;
  }

  return ancestors;
}

export async function handleReferralTopupPayout({
  userId,
  topupAmountPaise,
  sourceLedger,
  session,
}) {
  if (!userId || !sourceLedger) return { payouts: [], activated: false };
  if (!Number.isFinite(topupAmountPaise) || topupAmountPaise <= 0) return { payouts: [], activated: false };

  const config = getReferralConfig();
  const depth = Math.min(config.maxDepth, config.levelPercentages.length);
  if (!depth) return { payouts: [], activated: false };

  const query = User.findById(userId).select(
    '_id name email referralCode pendingReferredBy referredBy referralActivatedAt',
  );
  if (session) query.session(session);
  const user = await query.exec();
  if (!user) return { payouts: [], activated: false };

  const hadCode = Boolean(user.referralCode);
  await ensureReferralCode(user);

  let mutated = !hadCode && Boolean(user.referralCode);
  let activated = false;

  if (!user.referredBy && user.pendingReferredBy && topupAmountPaise >= config.minActivationPaise) {
    user.referredBy = user.pendingReferredBy;
    user.pendingReferredBy = undefined;
    user.referralActivatedAt = user.referralActivatedAt || new Date();
    mutated = true;
    activated = true;
  }

  if (mutated) {
    await user.save({ session });
  }

  if (activated) {
    await User.updateOne(
      { _id: user.referredBy },
      { $inc: { referralCount: 1 } },
      { session },
    );
  }

  if (!user.referredBy) return { payouts: [], activated };

  const ancestors = await loadAncestorChain(user.referredBy, depth, session);
  if (!ancestors.length) return { payouts: [], activated };

  const baseRef = sourceLedger.extRef || sourceLedger._id.toString();
  const payouts = [];

  for (let level = 0; level < ancestors.length; level += 1) {
    const percentage = config.levelPercentages[level] || 0;
    if (percentage <= 0) continue;

    const creditAmount = Math.floor(topupAmountPaise * percentage);
    if (creditAmount <= 0) continue;

    const ancestor = ancestors[level];
    const wallet = await ensureWallet(ancestor._id, session);
    const extRef = `ref:${baseRef}:L${level + 1}`;

    try {
      await Wallet.updateOne(
        { _id: wallet._id },
        { $inc: { balance: creditAmount } },
        { session },
      );

      await WalletLedger.create(
        [{
          walletId: wallet._id,
          type: 'REFERRAL',
          amount: creditAmount,
          note: `Referral level ${level + 1} earnings from ${user._id}`,
          extRef,
          metadata: {
            sourceUserId: user._id,
            level: level + 1,
            topupLedgerId: sourceLedger._id,
            topupExtRef: sourceLedger.extRef || null,
          },
        }],
        { session },
      );

      payouts.push({
        level: level + 1,
        userId: ancestor._id,
        amount: creditAmount,
      });
    } catch (err) {
      if (err?.code === 11000) {
        continue;
      }
      throw err;
    }
  }

  return { payouts, activated };
}

