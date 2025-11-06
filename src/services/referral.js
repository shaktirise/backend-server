import crypto from 'crypto';
import User from '../models/User.js';
import ReferralLedger from '../models/ReferralLedger.js';
import ActivationEvent from '../models/ActivationEvent.js';
import ReferralClosure from '../models/ReferralClosure.js';
import BonusPayout from '../models/BonusPayout.js';

const REFERRAL_CODE_ALPHABET = process.env.REFERRAL_CODE_ALPHABET || 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

const REFERRAL_CODE_LENGTH = (() => {
  const raw = parseInt(process.env.REFERRAL_CODE_LENGTH || '8', 10);
  if (Number.isFinite(raw) && raw >= 4 && raw <= 16) return raw;
  return 8;
})();

// Default commission percentages by level (as whole-number percents)
// Example: [10, 7, 5, 4, 2, 2, 2] =>
//   10% for level 1, 7% for level 2, 5% for level 3,
//   4% for level 4, and 2% for levels 5 to 7
const DEFAULT_LEVEL_PERCENTAGES = [10, 7, 5, 4, 2, 2, 2];

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
  // Default activation on ₹2100 registration
  const raw = Number.parseInt(process.env.REFERRAL_MIN_ACTIVATION_RUPEES || '2100', 10);
  if (!Number.isFinite(raw) || raw < 0) return 1000 * 100;
  return raw * 100;
}

export function getReferralConfig() {
  const levelPercentages = parseLevelPercentages();

  // New fixed amount schedules (in paise)
  const registrationAmountsPaise = (() => {
    const raw = String(process.env.REFERRAL_REGISTRATION_AMOUNTS || '')
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean)
      .map((p) => Number.parseFloat(p))
      .filter((n) => Number.isFinite(n) && n >= 0)
      .map((n) => Math.round(n * 100));
    if (raw.length) return raw;
    // Default: [500, 100, 50 x 8]
    return [500, 100, 50, 50, 50, 50, 50, 50, 50, 50].map((n) => n * 100);
  })();

  const renewalAmountsPaise = (() => {
    const raw = String(process.env.REFERRAL_RENEWAL_AMOUNTS || '')
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean)
      .map((p) => Number.parseFloat(p))
      .filter((n) => Number.isFinite(n) && n >= 0)
      .map((n) => Math.round(n * 100));
    if (raw.length) return raw;
    // Default: [50 x 10]
    return [50, 50, 50, 50, 50, 50, 50, 50, 50, 50].map((n) => n * 100);
  })();

  const registrationFeePaise = Math.round(
    (Number.parseInt(process.env.REFERRAL_REGISTRATION_FEE_RUPEES || '2100', 10) || 2100) * 100,
  );
  const renewalFeePaise = Math.round(
    (Number.parseInt(process.env.REFERRAL_RENEWAL_FEE_RUPEES || '1000', 10) || 1000) * 100,
  );

  const fixedDepth = Math.max(registrationAmountsPaise.length, renewalAmountsPaise.length) || 0;
  const defaultDepth = fixedDepth || levelPercentages.length;
  const maxDepthEnv = Number.parseInt(process.env.REFERRAL_MAX_DEPTH || `${defaultDepth}`, 10);
  const maxDepth = Number.isFinite(maxDepthEnv) && maxDepthEnv > 0
    ? Math.min(maxDepthEnv, defaultDepth)
    : defaultDepth;

  const shareBaseUrl = process.env.REFERRAL_SHARE_BASE_URL || process.env.APP_DOWNLOAD_URL || '';

  return {
    levelPercentages,
    maxDepth,
    minActivationPaise: parseMinActivationPaise(),
    shareBaseUrl,
    registrationAmountsPaise,
    renewalAmountsPaise,
    registrationFeePaise,
    renewalFeePaise,
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

async function upsertReferralClosureLinks(descendantId, ancestors, session) {
  if (!descendantId || !Array.isArray(ancestors) || ancestors.length === 0) {
    return;
  }

  const now = new Date();
  const ops = ancestors.map((ancestor, idx) => ({
    updateOne: {
      filter: {
        ancestorId: ancestor._id,
        descendantId,
      },
      update: {
        $set: {
          depth: idx + 1,
          updatedAt: now,
        },
        $setOnInsert: {
          createdAt: now,
        },
      },
      upsert: true,
    },
  }));

  if (ops.length) {
    await ReferralClosure.bulkWrite(ops, {
      session,
      ordered: false,
    });
  }
}

export async function handleReferralTopupPayout({
  userId,
  topupAmountPaise,
  sourceLedger,
  session,
  // Optional hint to force a schedule: 'REGISTRATION' | 'RENEWAL'
  kind,
}) {
  if (!userId || !sourceLedger) return { payouts: [], activated: false };
  if (!Number.isFinite(topupAmountPaise) || topupAmountPaise <= 0) return { payouts: [], activated: false };

  const config = getReferralConfig();
  const depth = Math.min(
    config.maxDepth,
    Math.max(
      config.registrationAmountsPaise.length,
      config.renewalAmountsPaise.length,
      config.levelPercentages.length,
    ),
  );
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

  if (!user.referredBy) {
    return { payouts: [], activated };
  }

  const ancestors = await loadAncestorChain(user.referredBy, depth, session);
  if (!ancestors.length) return { payouts: [], activated };
  await upsertReferralClosureLinks(user._id, ancestors, session);

  let activationEvent = null;
  try {
    if (sourceLedger?._id) {
      activationEvent = await ActivationEvent.findOneAndUpdate(
        { sourceLedgerId: sourceLedger._id },
        {
          $setOnInsert: {
            userId,
            sourceUserId: user.referredBy || null,
            amountPaise: topupAmountPaise,
            occurredAt: sourceLedger?.createdAt || new Date(),
            type: 'TOPUP',
          },
          $set: {
            status: 'SUCCEEDED',
            metadata: {
              ...(sourceLedger?.metadata || {}),
              ledgerId: sourceLedger._id,
              extRef: sourceLedger?.extRef || null,
            },
          },
        },
        {
          upsert: true,
          new: true,
          setDefaultsOnInsert: true,
          session,
        },
      );
    } else {
      const [createdEvent] = await ActivationEvent.create(
        [
          {
            userId,
            sourceUserId: user.referredBy || null,
            amountPaise: topupAmountPaise,
            status: 'SUCCEEDED',
            type: 'TOPUP',
            occurredAt: new Date(),
            metadata: {
              ledgerId: sourceLedger?._id || null,
              extRef: sourceLedger?.extRef || null,
            },
          },
        ],
        { session },
      );
      activationEvent = createdEvent;
    }
  } catch (eventErr) {
    console.warn('activation event sync failed', eventErr);
  }

  const baseRef = sourceLedger?.extRef || (sourceLedger?._id ? String(sourceLedger._id) : `${user._id}:${Date.now()}`);
  const payouts = [];
  const bonusDocs = [];

  // Decide amounts by level
  let amountsByLevel = [];
  const near = (a, b) => Math.abs(a - b) <= 100; // ₹1 tolerance
  const isRegistration = kind === 'REGISTRATION' || near(topupAmountPaise, config.registrationFeePaise);
  const isRenewal = kind === 'RENEWAL' || near(topupAmountPaise, config.renewalFeePaise);
  if (isRegistration) {
    amountsByLevel = config.registrationAmountsPaise;
  } else if (isRenewal) {
    amountsByLevel = config.renewalAmountsPaise;
  } else {
    // Fallback to percentage schedule for any other top-up amount
    amountsByLevel = config.levelPercentages.map((p) => Math.floor(topupAmountPaise * p));
  }

  for (let level = 0; level < ancestors.length; level += 1) {
    const creditAmount = Math.floor(amountsByLevel[level] || 0);
    if (creditAmount <= 0) continue;

    const ancestor = ancestors[level];
    const ledgerDoc = {
      userId: ancestor._id,
      sourceUserId: user._id,
      level: level + 1,
      amountPaise: creditAmount,
      note: `Referral level ${level + 1} earnings from ${user._id}`,
      status: 'pending',
      topupLedgerId: sourceLedger?._id || null,
      topupExtRef: baseRef || null,
    };

    try {
      const [referralDoc] = await ReferralLedger.create([ledgerDoc], { session });
      payouts.push({
        level: level + 1,
        userId: ancestor._id,
        uplineUserId: ancestor._id,
        downlineUserId: user._id,
        amountPaise: creditAmount,
        status: 'pending',
      });
      bonusDocs.push({
        uplineUserId: ancestor._id,
        downlineUserId: user._id,
        activationEventId: activationEvent?._id || null,
        level: level + 1,
        amountPaise: creditAmount,
        status: 'PENDING',
        note: ledgerDoc.note,
        metadata: {
          referralLedgerId: referralDoc?._id || null,
          topupLedgerId: sourceLedger?._id || null,
          topupExtRef: baseRef || null,
        },
      });
    } catch (err) {
      if (err?.code === 11000) {
        continue;
      }
      throw err;
    }
  }

  if (bonusDocs.length) {
    const now = new Date();
    try {
      await BonusPayout.bulkWrite(
        bonusDocs.map((doc) => ({
          updateOne: {
            filter: {
              activationEventId: doc.activationEventId || null,
              uplineUserId: doc.uplineUserId,
              downlineUserId: doc.downlineUserId,
              level: doc.level,
            },
            update: {
              // Avoid path conflicts: only set metadata via $set
              $setOnInsert: {
                createdAt: now,
                uplineUserId: doc.uplineUserId,
                downlineUserId: doc.downlineUserId,
                activationEventId: doc.activationEventId || null,
                level: doc.level,
                amountPaise: doc.amountPaise,
                status: doc.status,
                note: doc.note,
                processedAt: null,
                processedBy: null,
              },
              $set: {
                updatedAt: now,
                metadata: {
                  ...(doc.metadata || {}),
                },
              },
            },
            upsert: true,
          },
        })),
        { session, ordered: false },
      );
    } catch (bonusErr) {
      console.warn('bonus payout sync failed', bonusErr);
    }
  }

  return { payouts, activated, activationEventId: activationEvent?._id || null };
}
