import express from 'express';
import Razorpay from 'razorpay';
import crypto from 'crypto';
import mongoose from 'mongoose';
import { auth, admin } from '../middleware/auth.js';
import Wallet from '../models/Wallet.js';
import User from '../models/User.js';
import WalletLedger from '../models/WalletLedger.js';
import { WALLET_LEDGER_TYPES } from '../constants/walletLedger.js';
import { ensureWallet } from '../services/wallet.js';
import { formatLocalISO, toEpochMs } from '../utils/time.js';
import { handleReferralTopupPayout, getReferralConfig } from '../services/referral.js';
import Purchase from '../models/Purchase.js';
import WalletWithdrawalRequest from '../models/WalletWithdrawalRequest.js';

const router = express.Router();

// Lazy init Razorpay client so server can boot without keys
let razorpayInstance = null;
function getRazorpay() {
  if (razorpayInstance) return razorpayInstance;
  const key_id = process.env.RAZORPAY_KEY_ID;
  const key_secret = process.env.RAZORPAY_KEY_SECRET;
  if (!key_id || !key_secret) {
    const err = new Error('RZP_KEYS_MISSING');
    err.code = 'RZP_KEYS_MISSING';
    throw err;
  }
  // Add a conservative timeout to avoid long hangs on Razorpay API calls
  // (library supports passing timeout in ms)
  try {
    razorpayInstance = new Razorpay({ key_id, key_secret, timeout: 5000 });
  } catch (_) {
    // Fallback for older SDKs without timeout support
    razorpayInstance = new Razorpay({ key_id, key_secret });
  }
  return razorpayInstance;
}

function buildShortReceipt(userId) {
  const uid = String(userId || '').slice(-8);
  const ts = Date.now().toString(36);
  const rand = crypto.randomBytes(3).toString('hex');
  const receipt = `tu_${uid}_${ts}_${rand}`;
  return receipt.slice(0, 40);
}

// Minimum top-up rupees floor (optional). If set, it acts as a floor over dynamic rules.
const STATIC_MIN_TOPUP_RUPEES = (() => {
  const raw = Number.parseInt(process.env.MIN_TOPUP_RUPEES || '0', 10);
  return Number.isFinite(raw) && raw > 0 ? raw : 0;
})();

// New env-configurable amounts
const FIRST_TOPUP_REQUIRED_RUPEES = (() => {
  const envVal = Number.parseInt(
    process.env.FIRST_TOPUP_REQUIRED_RUPEES || process.env.REFERRAL_REGISTRATION_FEE_RUPEES || '2100',
    10,
  );
  return Number.isFinite(envVal) && envVal > 0 ? envVal : 2100;
})();
const MIN_TOPUP_RUPEES_AFTER_ACTIVATION = (() => {
  const envVal = Number.parseInt(
    process.env.MIN_TOPUP_RUPEES_AFTER_ACTIVATION || process.env.REFERRAL_RENEWAL_FEE_RUPEES || '1000',
    10,
  );
  return Number.isFinite(envVal) && envVal > 0 ? envVal : 1000;
})();

const AMOUNT_TOLERANCE_PAISE = 100; // ±₹1 tolerance

const DUMMY_PAYMENT_ENABLED = (() => {
  const raw = String(process.env.DUMMY_PAYMENT_ENABLED || '').trim().toLowerCase();
  if (!raw && process.env.NODE_ENV !== 'production') {
    // Make dummy payments available by default in non-production for QA flows
    return true;
  }
  return raw === '1' || raw === 'true' || raw === 'yes';
})();

async function computeDynamicMinRupees(userId) {
  const cfg = getReferralConfig();

  // 1) Fast path: if user already activated (from referrals), treat as renewal
  try {
    const u = await User.findById(userId).select('_id referralActivatedAt').lean().exec();
    if (u?.referralActivatedAt) {
      const dyn = Math.round(cfg.renewalFeePaise / 100);
      return Math.max(dyn, STATIC_MIN_TOPUP_RUPEES);
    }
  } catch (err) {
    // ignore and continue
  }

  // 2) Activation events (>= activation threshold) also mark as not-new
  try {
    const ActivationEvent = (await import('../models/ActivationEvent.js')).default;
    const hasActivation = await ActivationEvent.exists({
      userId,
      status: 'SUCCEEDED',
      amountPaise: { $gte: getReferralConfig().minActivationPaise },
    });
    if (hasActivation) {
      const dyn = Math.round(cfg.renewalFeePaise / 100);
      return Math.max(dyn, STATIC_MIN_TOPUP_RUPEES);
    }
  } catch (err) {
    // ignore and continue
  }

  // 3) Legacy/new deposit check: any single qualifying deposit (>= registration fee)
  const qualifyingDeposit = await WalletLedger.exists({
    userId,
    amount: { $gte: cfg.registrationFeePaise },
    $or: [
      { normalizedType: WALLET_LEDGER_TYPES.DEPOSIT },
      { type: { $in: [WALLET_LEDGER_TYPES.DEPOSIT, 'TOPUP'] } }, // include legacy
    ],
  });

  if (qualifyingDeposit) {
    const dyn = Math.round(cfg.renewalFeePaise / 100);
    return Math.max(dyn, STATIC_MIN_TOPUP_RUPEES);
  }

  // Default: registration minimum for first activation
  const dyn = Math.round(cfg.registrationFeePaise / 100);
  return Math.max(dyn, STATIC_MIN_TOPUP_RUPEES);
}

async function isFirstTopup(userId) {
  // First top-up if no deposit/top-up ledger entries exist yet
  const exists = await WalletLedger.exists({
    userId,
    $or: [
      { normalizedType: WALLET_LEDGER_TYPES.DEPOSIT },
      { type: { $in: [WALLET_LEDGER_TYPES.DEPOSIT, 'TOPUP'] } },
    ],
  });
  return !exists;
}

const GST_RATE = (() => {
  const raw = Number.parseFloat(process.env.GST_RATE || '0.18');
  return Number.isFinite(raw) && raw >= 0 ? raw : 0.18;
})();
const GST_PERCENT = Math.round(GST_RATE * 100);

// Membership validity durations (days)
const ACCOUNT_REGISTRATION_VALID_DAYS = parseInt(
  process.env.ACCOUNT_REGISTRATION_VALID_DAYS || '60',
  10,
);
const ACCOUNT_RENEWAL_VALID_DAYS = parseInt(
  process.env.ACCOUNT_RENEWAL_VALID_DAYS || '30',
  10,
);

function parsePagination(query) {
  const limitRaw = Number.parseInt(query?.limit ?? '25', 10);
  const pageRaw = Number.parseInt(query?.page ?? '1', 10);
  const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 200) : 25;
  const page = Number.isFinite(pageRaw) && pageRaw > 0 ? pageRaw : 1;
  return { limit, page, skip: (page - 1) * limit };
}

function parseAmountPaiseFromBody(body) {
  const amtPaise = Number(body?.amountPaise);
  if (Number.isFinite(amtPaise)) return Math.round(amtPaise);
  const amtRupees = Number(body?.amountInRupees ?? body?.amount);
  if (Number.isFinite(amtRupees)) return Math.round(amtRupees * 100);
  return null;
}

async function buildActivationSnapshot(userId) {
  const latestUser = await User.findById(userId)
    .select('accountStatus accountActivatedAt accountActiveUntil')
    .lean();

  const activation = latestUser
    ? {
        accountStatus: latestUser.accountStatus || null,
        accountActivatedAt: latestUser.accountActivatedAt || null,
        accountActivatedAtLocal: latestUser.accountActivatedAt
          ? formatLocalISO(latestUser.accountActivatedAt)
          : null,
        accountActivatedAtMs: latestUser.accountActivatedAt
          ? toEpochMs(latestUser.accountActivatedAt)
          : null,
        accountActiveUntil: latestUser.accountActiveUntil || null,
        accountActiveUntilLocal: latestUser.accountActiveUntil
          ? formatLocalISO(latestUser.accountActiveUntil)
          : null,
        accountActiveUntilMs: latestUser.accountActiveUntil
          ? toEpochMs(latestUser.accountActiveUntil)
          : null,
      }
    : null;

  const now = Date.now();
  const untilMs = latestUser?.accountActiveUntil ? new Date(latestUser.accountActiveUntil).getTime() : 0;
  const remainingMs = Math.max(0, untilMs - now);
  const membership = latestUser
    ? {
        status: latestUser.accountStatus || 'INACTIVE',
        isActive: untilMs > now,
        nowMs: now,
        activeUntilMs: untilMs || null,
        activeUntilLocal: untilMs ? formatLocalISO(latestUser.accountActiveUntil) : null,
        remainingMs,
        remainingSeconds: Math.floor(remainingMs / 1000),
        remainingDays: untilMs ? Math.ceil(remainingMs / (24 * 60 * 60 * 1000)) : 0,
      }
    : null;

  return { activation, membership };
}

async function applyTopupCredit({ userId, creditAmount, extRef, note, metadata }) {
  const session = await mongoose.startSession();
  let referralResult = { payouts: [], activated: false };
  try {
    await session.withTransaction(async () => {
      const wallet = await ensureWallet(userId, session);

      await Wallet.updateOne(
        { _id: wallet._id },
        { $inc: { balance: creditAmount } },
        { session },
      );

      const [ledgerEntry] = await WalletLedger.create(
        [
          {
            walletId: wallet._id,
            userId: wallet.userId || userId,
            type: WALLET_LEDGER_TYPES.DEPOSIT,
            amount: creditAmount,
            note,
            extRef,
            metadata,
          },
        ],
        { session },
      );

      const cfg = getReferralConfig();
      const near = (a, b) => Math.abs(a - b) <= 100; // 1 rupee tolerance
      const kind = near(creditAmount, cfg.registrationFeePaise)
        ? 'REGISTRATION'
        : near(creditAmount, cfg.renewalFeePaise)
          ? 'RENEWAL'
          : undefined;

      // Update membership validity for qualifying top-ups
      // Registration: only when amount ~ registration fee
      // Renewal: on any amount >= renewal fee
      {
        const regFeePaise = getReferralConfig().registrationFeePaise;
        const renFeePaise = getReferralConfig().renewalFeePaise;
        const isRegistration = kind === 'REGISTRATION';
        const isRenewal = kind === 'RENEWAL' || (!isRegistration && creditAmount >= renFeePaise);
        const addDays = isRegistration
          ? ACCOUNT_REGISTRATION_VALID_DAYS
          : isRenewal
            ? ACCOUNT_RENEWAL_VALID_DAYS
            : 0;
        if (addDays > 0) {
          const userDoc = await User.findById(userId).session(session);
          if (userDoc) {
            const nowDt = new Date();
            const baseDt = (userDoc.accountActiveUntil && userDoc.accountActiveUntil.getTime() > nowDt.getTime())
              ? userDoc.accountActiveUntil
              : nowDt;
            const newUntil = new Date(baseDt.getTime() + Math.max(1, addDays) * 24 * 60 * 60 * 1000);
            userDoc.accountActivatedAt = nowDt;
            userDoc.accountActiveUntil = newUntil;
            if (userDoc.accountStatus !== 'SUSPENDED' && userDoc.accountStatus !== 'DEACTIVATED') {
              userDoc.accountStatus = 'ACTIVE';
            }
            await userDoc.save({ session });
          }
        }
      }

      referralResult = await handleReferralTopupPayout({
        userId,
        topupAmountPaise: creditAmount,
        sourceLedger: ledgerEntry,
        session,
        kind,
      });
    });
  } finally {
    session.endSession();
  }

  const { activation, membership } = await buildActivationSnapshot(userId);
  return { referralResult, activation, membership };
}

router.use(auth);

router.post('/topups/create-order', async (req, res) => {
  try {
    const userId = req.user.sub;
    // Accept amount as amountInRupees (preferred) or amount (rupees) or amountPaise
    const rawAmountInRupees =
      req.body?.amountInRupees ??
      (req.body?.amountPaise != null ? Number(req.body.amountPaise) / 100 : req.body?.amount);
    const amountInRupees = Number.parseFloat(rawAmountInRupees);

    const firstTopup = await isFirstTopup(userId);

    if (!Number.isFinite(amountInRupees)) {
      return res.status(400).json({ error: 'invalid_amount' });
    }

    if (firstTopup) {
      const requiredPaise = Math.round(FIRST_TOPUP_REQUIRED_RUPEES * 100);
      const candidatePaise = Math.round(amountInRupees * 100);
      if (Math.abs(candidatePaise - requiredPaise) > AMOUNT_TOLERANCE_PAISE) {
        return res.status(400).json({
          error: 'first_topup_must_equal',
          requiredRupees: FIRST_TOPUP_REQUIRED_RUPEES,
        });
      }
    } else {
      const dynamicMin = await computeDynamicMinRupees(userId);
      const floorMin = Math.max(dynamicMin, MIN_TOPUP_RUPEES_AFTER_ACTIVATION, STATIC_MIN_TOPUP_RUPEES);
      if (amountInRupees < floorMin) {
        return res.status(400).json({
          error: 'amount_below_minimum',
          minimumRupees: floorMin,
        });
      }
    }

    const amount = Math.round(amountInRupees * 100); // to paise
    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: 'invalid amount' });
    }

    let rzp;
    try {
      rzp = getRazorpay();
    } catch (keyErr) {
      if (keyErr?.code === 'RZP_KEYS_MISSING') {
        return res.status(500).json({ error: 'razorpay_keys_missing' });
      }
      throw keyErr;
    }

    const order = await rzp.orders.create({
      amount,
      currency: 'INR',
      receipt: buildShortReceipt(userId),
      notes: { userId: String(userId) },
    });

    const response = {
      key: process.env.RAZORPAY_KEY_ID,
      order_id: order.id,
      amount: order.amount,
      currency: order.currency,
    };
    if (firstTopup) {
      response.firstTopupRequiredRupees = FIRST_TOPUP_REQUIRED_RUPEES;
    } else {
      response.minimumRupees = Math.max(
        await computeDynamicMinRupees(userId),
        MIN_TOPUP_RUPEES_AFTER_ACTIVATION,
        STATIC_MIN_TOPUP_RUPEES,
      );
    }

    return res.json(response);
  } catch (e) {
    console.error('create-order error', e);
    if (process.env.NODE_ENV !== 'production') {
      const code = e?.error?.code || e?.code;
      const description = e?.error?.description || e?.message;
      return res.status(500).json({ error: 'failed_to_create_order', code, description });
    }
    return res.status(500).json({ error: 'failed_to_create_order' });
  }
});

router.post('/topups/verify', async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body || {};
  try {
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({ error: 'missing_fields' });
    }

    const body = `${razorpay_order_id}|${razorpay_payment_id}`;
    const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(body).digest('hex');
    if (expected !== String(razorpay_signature)) {
      return res.status(400).json({ error: 'signature_mismatch' });
    }

    const existing = await WalletLedger.findOne({ extRef: razorpay_payment_id }).lean();
    if (existing) return res.json({ ok: true });

    // Attempt to fetch payment from Razorpay with a strict timeout to prevent long waits.
    let paymentAmount = null;
    try {
      const rzp = getRazorpay();
      const fetchWithTimeout = (promise, ms) =>
        Promise.race([
          promise,
          new Promise((_, reject) => setTimeout(() => reject(new Error('rzp_fetch_timeout')), ms)),
        ]);
      const pmt = await fetchWithTimeout(rzp.payments.fetch(razorpay_payment_id), 4000);
      if (!['captured', 'authorized'].includes(pmt.status)) {
        return res.status(400).json({ error: 'payment_not_captured' });
      }
      paymentAmount = Number(pmt.amount);
    } catch (fetchErr) {
      console.warn('payments.fetch failed or timed out; using fallback amount if provided');
    }

    // Fallback amount in paise if payment fetch is unavailable
    const fallbackAmountPaise = (() => {
      const amtPaise = Number(req.body?.amountPaise);
      if (Number.isFinite(amtPaise)) return Math.round(amtPaise);
      const amtRupees = Number(req.body?.amountInRupees ?? req.body?.amount);
      if (Number.isFinite(amtRupees)) return Math.round(amtRupees * 100);
      return null;
    })();
    const creditAmount = Number.isFinite(paymentAmount) ? paymentAmount : fallbackAmountPaise;
    if (!Number.isFinite(creditAmount) || creditAmount <= 0) {
      // We could not fetch from Razorpay and client did not provide amount.
      // Ask client to resend with amountPaise/amount to avoid server-side network fetch.
      return res.status(400).json({ error: 'amount_required', message: 'Include amountPaise or amount in verify call' });
    }
    const firstTopup = await isFirstTopup(req.user.sub);
    if (firstTopup) {
      const requiredPaise = Math.round(FIRST_TOPUP_REQUIRED_RUPEES * 100);
      if (Math.abs(creditAmount - requiredPaise) > AMOUNT_TOLERANCE_PAISE) {
        return res.status(400).json({
          error: 'first_topup_must_equal',
          requiredPaise,
          requiredRupees: FIRST_TOPUP_REQUIRED_RUPEES,
        });
      }
    } else {
      const dynamicMin = await computeDynamicMinRupees(req.user.sub);
      const floorMin = Math.max(dynamicMin, MIN_TOPUP_RUPEES_AFTER_ACTIVATION, STATIC_MIN_TOPUP_RUPEES);
      const minPaise = floorMin * 100;
      if (creditAmount < minPaise) {
        return res.status(400).json({
          error: 'amount_below_minimum',
          minimumPaise: minPaise,
          minimumRupees: floorMin,
        });
      }
    }

    const { referralResult, activation, membership } = await applyTopupCredit({
      userId: req.user.sub,
      creditAmount,
      extRef: razorpay_payment_id,
      note: 'Razorpay top-up',
      metadata: { orderId: razorpay_order_id },
    });

    return res.json({
      ok: true,
      creditedPaise: creditAmount,
      referral: referralResult,
      activation,
      membership,
    });
  } catch (e) {
    console.error('topups/verify error', e);
    if (e?.code === 11000) {
      return res.json({ ok: true });
    }
    return res.status(500).json({ error: 'verification_failed' });
  }
});

router.post('/topups/dummy', async (req, res) => {
  try {
    if (!DUMMY_PAYMENT_ENABLED) {
      return res.status(403).json({ error: 'dummy_payments_disabled' });
    }

    const userId = req.user.sub;
    const creditAmount = parseAmountPaiseFromBody(req.body);
    if (!Number.isFinite(creditAmount)) {
      return res.status(400).json({ error: 'amount_required' });
    }
    if (creditAmount <= 0) {
      return res.status(400).json({ error: 'invalid_amount' });
    }

    const firstTopup = await isFirstTopup(userId);
    if (firstTopup) {
      const requiredPaise = Math.round(FIRST_TOPUP_REQUIRED_RUPEES * 100);
      if (Math.abs(creditAmount - requiredPaise) > AMOUNT_TOLERANCE_PAISE) {
        return res.status(400).json({
          error: 'first_topup_must_equal',
          requiredPaise,
          requiredRupees: FIRST_TOPUP_REQUIRED_RUPEES,
        });
      }
    } else {
      const dynamicMin = await computeDynamicMinRupees(userId);
      const floorMin = Math.max(dynamicMin, MIN_TOPUP_RUPEES_AFTER_ACTIVATION, STATIC_MIN_TOPUP_RUPEES);
      const minPaise = floorMin * 100;
      if (creditAmount < minPaise) {
        return res.status(400).json({
          error: 'amount_below_minimum',
          minimumPaise: minPaise,
          minimumRupees: floorMin,
        });
      }
    }

    const rawRef =
      req.body?.paymentRef ??
      req.body?.payment_id ??
      req.body?.dummy_payment_id ??
      req.body?.razorpay_payment_id;
    const paymentRef = rawRef != null && String(rawRef).trim()
      ? String(rawRef).trim()
      : `dummy_${req.user.sub}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;

    const existing = await WalletLedger.findOne({ extRef: paymentRef }).lean();
    if (existing) return res.json({ ok: true });

    const rawOrderId = req.body?.order_id ?? req.body?.orderId ?? req.body?.razorpay_order_id;
    const metadata = { source: 'dummy' };
    if (rawOrderId != null && String(rawOrderId).trim()) {
      metadata.orderId = String(rawOrderId).trim();
    }

    const { referralResult, activation, membership } = await applyTopupCredit({
      userId,
      creditAmount,
      extRef: paymentRef,
      note: 'Dummy top-up',
      metadata,
    });

    return res.json({
      ok: true,
      creditedPaise: creditAmount,
      paymentRef,
      referral: referralResult,
      activation,
      membership,
    });
  } catch (e) {
    console.error('topups/dummy error', e);
    if (e?.code === 11000) {
      return res.json({ ok: true });
    }
    return res.status(500).json({ error: 'dummy_topup_failed' });
  }
});

router.post('/debit', async (req, res) => {
  try {
    const amountInRupees = Number.isFinite(req.body?.amountInRupees)
      ? Number(req.body.amountInRupees)
      : 100;
    let note = typeof req.body?.note === 'string' ? req.body.note : 'Advice purchase';

    const baseAmountPaise = Math.round(amountInRupees * 100);
    if (!Number.isFinite(baseAmountPaise) || baseAmountPaise <= 0) {
      return res.status(400).json({ error: 'invalid_amount' });
    }

    const gstAmountPaise = Math.round(baseAmountPaise * GST_RATE);
    const totalDebitPaise = baseAmountPaise + gstAmountPaise;

    const userId = req.user.sub;
    const wallet = await ensureWallet(userId);
    if ((wallet.balance || 0) < totalDebitPaise) {
      return res.status(402).json({ error: 'INSUFFICIENT_FUNDS', topupRequired: true });
    }

    const rawCall =
      (req.body && typeof req.body.call === 'object' && req.body.call !== null && req.body.call) ||
      (req.body && typeof req.body.purchase === 'object' && req.body.purchase !== null && req.body.purchase) ||
      null;

    let adviceObjectId = null;
    let callMetadata = null;
    if (rawCall) {
      if (typeof rawCall.note === 'string' && rawCall.note.trim()) {
        note = rawCall.note.trim();
      }
      callMetadata = {};
      const adviceIdCandidate = rawCall.adviceId || rawCall.id;
      if (adviceIdCandidate && mongoose.Types.ObjectId.isValid(adviceIdCandidate)) {
        adviceObjectId = new mongoose.Types.ObjectId(adviceIdCandidate);
        callMetadata.adviceId = adviceObjectId.toString();
      } else if (adviceIdCandidate) {
        callMetadata.adviceId = String(adviceIdCandidate);
      }
      if (rawCall.title || rawCall.name) {
        callMetadata.title = String(rawCall.title || rawCall.name);
      }
      if (rawCall.category || rawCall.segment) {
        callMetadata.category = String(rawCall.category || rawCall.segment);
      }
      if (rawCall.pricePaise !== undefined) {
        const pricePaise = Number(rawCall.pricePaise);
        if (Number.isFinite(pricePaise)) {
          callMetadata.pricePaise = Math.round(pricePaise);
        }
      } else if (rawCall.price !== undefined) {
        const price = Number(rawCall.price);
        if (Number.isFinite(price)) {
          callMetadata.pricePaise = Math.round(price * 100);
        }
      }
      if (rawCall.metadata && typeof rawCall.metadata === 'object') {
        callMetadata.details = rawCall.metadata;
      }
      if (Object.keys(callMetadata).length === 0) {
        callMetadata = null;
      }
    }

    const session = await mongoose.startSession();
    let newBalance = wallet.balance;
    let createdPurchase = null;
    try {
      await session.withTransaction(async () => {
        const fresh = await Wallet.findById(wallet._id).session(session).exec();
        if (!fresh || fresh.balance < totalDebitPaise) {
          throw Object.assign(new Error('insufficient_funds'), { code: 'INSUFFICIENT_FUNDS' });
        }
        newBalance = fresh.balance - totalDebitPaise;
        await Wallet.updateOne(
          { _id: wallet._id },
          { $inc: { balance: -totalDebitPaise } },
          { session },
        );
        const ledgerMetadata = {
          baseAmountPaise,
          gstAmountPaise,
          gstRate: GST_RATE,
        };
        if (callMetadata) {
          ledgerMetadata.call = callMetadata;
        }

        const [ledgerEntry] = await WalletLedger.create(
          [
            {
              walletId: wallet._id,
              userId,
              type: 'PURCHASE',
              amount: -totalDebitPaise,
              note: `${note} (incl. GST ${GST_PERCENT}%)`,
              metadata: ledgerMetadata,
            },
          ],
          { session },
        );

        const purchaseDoc = {
          user: userId,
          advice: adviceObjectId || undefined,
          amount: Math.round(totalDebitPaise / 100),
          amountPaise: totalDebitPaise,
          note,
          category: callMetadata?.category,
          title: callMetadata?.title,
          walletLedgerId: ledgerEntry._id,
          metadata: {
            baseAmountPaise,
            gstAmountPaise,
            gstPercent: GST_PERCENT,
            ledgerId: ledgerEntry._id,
            call: callMetadata || undefined,
          },
        };
        if (!purchaseDoc.category && rawCall?.category) {
          purchaseDoc.category = String(rawCall.category);
        }
        if (!purchaseDoc.title && rawCall?.name) {
          purchaseDoc.title = String(rawCall.name);
        }

        const [purchaseEntry] = await Purchase.create([purchaseDoc], { session });
        createdPurchase = purchaseEntry;
      });
    } catch (txErr) {
      if (txErr?.code === 'INSUFFICIENT_FUNDS') {
        return res.status(402).json({ error: 'INSUFFICIENT_FUNDS', topupRequired: true });
      }
      throw txErr;
    } finally {
      session.endSession();
    }

    return res.json({
      ok: true,
      newBalancePaise: newBalance,
      debitedPaise: totalDebitPaise,
      baseAmountPaise,
      gstAmountPaise,
      gstPercent: GST_PERCENT,
      purchaseId: createdPurchase?._id || null,
    });
  } catch (e) {
    console.error('debit error', e);
    return res.status(500).json({ error: 'debit_failed' });
  }
});

router.get('/history', async (req, res) => {
  try {
    const userId = req.user.sub;
    const { limit, page, skip } = parsePagination(req.query);

    const [itemsRaw, total] = await Promise.all([
      Purchase.find({ user: userId })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate('advice', 'category price createdAt text')
        .lean(),
      Purchase.countDocuments({ user: userId }),
    ]);

    const items = itemsRaw.map((purchase) => {
      const amountPaise = Number.isFinite(purchase.amountPaise)
        ? purchase.amountPaise
        : Number.isFinite(purchase.amount)
          ? Math.round(purchase.amount * 100)
          : 0;
      return {
        id: purchase._id,
        createdAt: purchase.createdAt,
        amountPaise,
        amountRupees: Math.floor(amountPaise / 100),
        note: purchase.note || null,
        category: purchase.category || purchase.advice?.category || null,
        title: purchase.title || purchase.advice?.text || null,
        adviceId: purchase.advice?._id || purchase.advice || null,
        metadata: purchase.metadata || null,
      };
    });

    return res.json({
      page,
      limit,
      total,
      items,
    });
  } catch (err) {
    console.error('wallet history error', err);
    return res.status(500).json({ error: 'history_failed' });
  }
});

router.get('/balance', async (req, res) => {
  try {
    const userId = req.user.sub;
    const wallet = await ensureWallet(userId);
    return res.json({ balancePaise: wallet.balance || 0 });
  } catch (e) {
    console.error('balance error', e);
    return res.status(500).json({ error: 'failed_to_fetch_balance' });
  }
});

// Create a withdrawal request (UPI or Bank). Minimal validation; stores info for admin processing.
// POST /api/wallet/withdrawals
// Body: {
//   amountInRupees?: number, amountPaise?: number,
//   method: 'UPI' | 'BANK',
//   upiId?: string,
//   bankAccountName?: string, bankAccountNumber?: string, bankIfsc?: string, bankName?: string,
//   name?: string, mobile?: string, note?: string
// }
router.post('/withdrawals', async (req, res) => {
  try {
    const userId = req.user.sub;
    const amountPaise = (() => {
      if (Number.isFinite(req.body?.amountPaise)) return Math.round(Number(req.body.amountPaise));
      if (Number.isFinite(req.body?.amountInRupees)) return Math.round(Number(req.body.amountInRupees) * 100);
      if (Number.isFinite(req.body?.amount)) return Math.round(Number(req.body.amount) * 100);
      return null;
    })();

    if (!Number.isFinite(amountPaise) || amountPaise <= 0) {
      return res.status(400).json({ error: 'amount_required' });
    }

    const methodRaw = (req.body?.method || '').toString().trim().toUpperCase();
    const method = methodRaw === 'UPI' ? 'UPI' : methodRaw === 'BANK' ? 'BANK' : null;
    if (!method) {
      return res.status(400).json({ error: 'method_required' });
    }

    const doc = await WalletWithdrawalRequest.create({
      userId,
      amountPaise,
      method,
      upiId: req.body?.upiId || undefined,
      bankAccountName: req.body?.bankAccountName || undefined,
      bankAccountNumber: req.body?.bankAccountNumber || undefined,
      bankIfsc: req.body?.bankIfsc || undefined,
      bankName: req.body?.bankName || undefined,
      contactName: req.body?.name || req.body?.contactName || undefined,
      contactMobile: req.body?.mobile || req.body?.contactMobile || undefined,
      note: req.body?.note || undefined,
      status: 'pending',
    });

    return res.status(201).json({
      request: {
        id: doc._id,
        amountPaise: doc.amountPaise,
        amountRupees: Math.floor(doc.amountPaise / 100),
        method: doc.method,
        upiId: doc.upiId || null,
        bank: {
          accountName: doc.bankAccountName || null,
          accountNumber: doc.bankAccountNumber || null,
          ifsc: doc.bankIfsc || null,
          bankName: doc.bankName || null,
        },
        contactName: doc.contactName || null,
        contactMobile: doc.contactMobile || null,
        note: doc.note || null,
        status: doc.status,
        createdAt: doc.createdAt,
      },
    });
  } catch (e) {
    console.error('withdrawals create error', e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// List user's own withdrawal requests
router.get('/withdrawals', async (req, res) => {
  try {
    const items = await WalletWithdrawalRequest.find({ userId: req.user.sub })
      .sort({ createdAt: -1 })
      .limit(100)
      .lean();
    return res.json({
      items: items.map((doc) => ({
        id: doc._id,
        amountPaise: doc.amountPaise,
        amountRupees: Math.floor((doc.amountPaise || 0) / 100),
        method: doc.method,
        upiId: doc.upiId || null,
        bank: {
          accountName: doc.bankAccountName || null,
          accountNumber: doc.bankAccountNumber || null,
          ifsc: doc.bankIfsc || null,
          bankName: doc.bankName || null,
        },
        contactName: doc.contactName || null,
        contactMobile: doc.contactMobile || null,
        note: doc.note || null,
        status: doc.status,
        paymentRef: doc.paymentRef || null,
        processedAt: doc.processedAt || null,
        createdAt: doc.createdAt,
      })),
    });
  } catch (e) {
    console.error('withdrawals list error', e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Admin: list all withdrawal requests (optional status filter)
router.get('/withdrawals/all', admin, async (req, res) => {
  try {
    const status = (req.query?.status || '').toString().trim();
    const query = status ? { status } : {};
    const items = await WalletWithdrawalRequest.find(query)
      .sort({ createdAt: -1 })
      .limit(200)
      .populate('userId', 'name email phone role')
      .lean();
    return res.json({
      items: items.map((doc) => ({
        id: doc._id,
        user: doc.userId?._id || doc.userId,
        userName: doc.userId?.name || null,
        userEmail: doc.userId?.email || null,
        userPhone: doc.userId?.phone || null,
        amountPaise: doc.amountPaise,
        amountRupees: Math.floor((doc.amountPaise || 0) / 100),
        method: doc.method,
        upiId: doc.upiId || null,
        bank: {
          accountName: doc.bankAccountName || null,
          accountNumber: doc.bankAccountNumber || null,
          ifsc: doc.bankIfsc || null,
          bankName: doc.bankName || null,
        },
        contactName: doc.contactName || null,
        contactMobile: doc.contactMobile || null,
        note: doc.note || null,
        status: doc.status,
        paymentRef: doc.paymentRef || null,
        processedBy: doc.processedBy || null,
        processedAt: doc.processedAt || null,
        createdAt: doc.createdAt,
      })),
    });
  } catch (e) {
    console.error('withdrawals admin list error', e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Admin: export all withdrawal requests as CSV (auto-fresh on each call)
router.get('/withdrawals/export.csv', admin, async (req, res) => {
  try {
    const query = {};
    // Default: include all statuses. Use ?status=pending|paid|cancelled to filter, or status=all for no filter.
    const status = (req.query?.status || '').toString().trim().toLowerCase();
    if (status && status !== 'all') {
      const allowed = new Set(['pending', 'paid', 'cancelled']);
      if (!allowed.has(status)) {
        return res.status(400).json({ error: 'invalid_status' });
      }
      query.status = status;
    }

    const userIdRaw = (req.query?.userId || '').toString().trim();
    if (userIdRaw && mongoose.Types.ObjectId.isValid(userIdRaw)) {
      query.userId = userIdRaw;
    }

    const requests = await WalletWithdrawalRequest.find(query)
      .sort({ createdAt: -1 })
      .populate('userId', 'name email phone role')
      .populate('processedBy', 'name email phone role')
      .lean();

    const header = [
      'id',
      'userName',
      'userEmail',
      'userPhone',
      'amountPaise',
      'amountRupees',
      'method',
      'upiId',
      'bankAccountName',
      'bankAccountNumber',
      'bankIfsc',
      'bankName',
      'contactName',
      'contactMobile',
      'note',
      'status',
      'paymentRef',
      'createdAt',
      'processedAt',
      'processedByName',
    ];

    const rows = [header];
    const toCsvValue = (v) => {
      if (v === null || v === undefined) return '';
      const str = String(v);
      if (str.includes(',') || str.includes('"') || str.includes('\n')) {
        return `"${str.replace(/"/g, '""')}"`;
      }
      return str;
    };

    requests.forEach((doc) => {
      const user = doc.userId || {};
      const processedBy = doc.processedBy || {};
      const row = [
        doc._id,
        user.name || '',
        user.email || '',
        user.phone || '',
        doc.amountPaise || 0,
        Math.floor((doc.amountPaise || 0) / 100),
        doc.method || '',
        doc.upiId || '',
        doc.bankAccountName || '',
        doc.bankAccountNumber || '',
        doc.bankIfsc || '',
        doc.bankName || '',
        doc.contactName || '',
        doc.contactMobile || '',
        doc.note || '',
        doc.status || '',
        doc.paymentRef || '',
        doc.createdAt ? new Date(doc.createdAt).toISOString() : '',
        doc.processedAt ? new Date(doc.processedAt).toISOString() : '',
        processedBy.name || (processedBy._id ? String(processedBy._id) : ''),
      ];
      rows.push(row.map(toCsvValue).join(','));
    });

    const csv = rows.map((r) => (Array.isArray(r) ? r.join(',') : r)).join('\n');
    const filename = `wallet_withdrawals_${new Date().toISOString().slice(0, 10)}.csv`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    return res.status(200).send(csv);
  } catch (e) {
    console.error('withdrawals export csv error', e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Admin: mark a withdrawal as paid and debit wallet
// PATCH /api/wallet/withdrawals/:id/mark-paid
// Body: { paymentRef?: string }
router.patch('/withdrawals/:id/mark-paid', admin, async (req, res) => {
  const id = req.params.id;
  try {
    const request = await WalletWithdrawalRequest.findById(id);
    if (!request) return res.status(404).json({ error: 'not_found' });
    if (request.status !== 'pending') {
      return res.status(400).json({ error: 'already_processed' });
    }

    const session = await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        const wallet = await ensureWallet(request.userId, session);
        const balance = wallet.balance || 0;
        const settleFullBalance = req.body?.settleFullBalance === true || req.body?.settle === 'full';
        const debitAmountPaise = settleFullBalance ? balance : request.amountPaise;
        if (debitAmountPaise <= 0) {
          throw Object.assign(new Error('no_balance'), { code: 'NO_BALANCE' });
        }
        if (!settleFullBalance && balance < debitAmountPaise) {
          throw Object.assign(new Error('insufficient_funds'), { code: 'INSUFFICIENT_FUNDS' });
        }

        await Wallet.updateOne(
          { _id: wallet._id },
          { $inc: { balance: -debitAmountPaise } },
          { session },
        );

        await WalletLedger.create([
          {
            walletId: wallet._id,
            userId: wallet.userId || request.userId,
            type: WALLET_LEDGER_TYPES.WITHDRAWAL,
            amount: -debitAmountPaise,
            note: settleFullBalance ? 'Wallet withdrawal payout (full settlement)' : 'Wallet withdrawal payout',
            metadata: { requestId: request._id, settleFullBalance: !!settleFullBalance, originalRequestAmountPaise: request.amountPaise },
          },
        ], { session });

        request.status = 'paid';
        request.paymentRef = req.body?.paymentRef || request.paymentRef;
        if (settleFullBalance && request.amountPaise !== debitAmountPaise) {
          // Update recorded payout amount to reflect full settlement
          request.amountPaise = debitAmountPaise;
          request.metadata = Object.assign({}, request.metadata, { settledAmountPaise: debitAmountPaise, settleFullBalance: true });
        }
        request.processedBy = req.user.sub;
        request.processedAt = new Date();
        await request.save({ session });
      });
    } catch (err) {
      if (err?.code === 'INSUFFICIENT_FUNDS') {
        return res.status(402).json({ error: 'INSUFFICIENT_FUNDS' });
      }
      if (err?.code === 'NO_BALANCE') {
        return res.status(400).json({ error: 'NO_BALANCE' });
      }
      throw err;
    } finally {
      session.endSession();
    }

    // Return latest wallet balance after debit
    const latestWallet = await Wallet.findOne({ userId: request.userId }).lean();
    return res.json({
      ok: true,
      id: request._id,
      status: request.status,
      paymentRef: request.paymentRef,
      debitedPaise: request.amountPaise,
      newBalancePaise: latestWallet?.balance || 0,
    });
  } catch (e) {
    console.error('withdrawals mark-paid error', e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Admin: cancel a withdrawal request
router.patch('/withdrawals/:id/cancel', admin, async (req, res) => {
  const id = req.params.id;
  try {
    const request = await WalletWithdrawalRequest.findById(id);
    if (!request) return res.status(404).json({ error: 'not_found' });
    if (request.status !== 'pending') {
      return res.status(400).json({ error: 'already_processed' });
    }
    request.status = 'cancelled';
    request.processedBy = req.user.sub;
    request.processedAt = new Date();
    await request.save();
    return res.json({ ok: true, id: request._id, status: request.status });
  } catch (e) {
    console.error('withdrawals cancel error', e);
    return res.status(500).json({ error: 'server_error' });
  }
});

export default router;
