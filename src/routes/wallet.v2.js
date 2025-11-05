import express from 'express';
import Razorpay from 'razorpay';
import crypto from 'crypto';
import mongoose from 'mongoose';
import { auth } from '../middleware/auth.js';
import Wallet from '../models/Wallet.js';
import User from '../models/User.js';
import WalletLedger from '../models/WalletLedger.js';
import { WALLET_LEDGER_TYPES } from '../constants/walletLedger.js';
import { ensureWallet } from '../services/wallet.js';
import { handleReferralTopupPayout, getReferralConfig } from '../services/referral.js';
import Purchase from '../models/Purchase.js';

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
  razorpayInstance = new Razorpay({ key_id, key_secret });
  return razorpayInstance;
}

function buildShortReceipt(userId) {
  const uid = String(userId || '').slice(-8);
  const ts = Date.now().toString(36);
  const rand = crypto.randomBytes(3).toString('hex');
  const receipt = `tu_${uid}_${ts}_${rand}`;
  return receipt.slice(0, 40);
}

// Minimum top-up rupees: prefer explicit env override, fallback to dynamic referral-based suggestion.
const STATIC_MIN_TOPUP_RUPEES = (() => {
  const raw = Number.parseInt(process.env.MIN_TOPUP_RUPEES || '0', 10);
  return Number.isFinite(raw) && raw > 0 ? raw : 0;
})();

async function computeDynamicMinRupees(userId) {
  if (STATIC_MIN_TOPUP_RUPEES > 0) return STATIC_MIN_TOPUP_RUPEES;
  const cfg = getReferralConfig();

  // 1) Fast path: if user already activated (from referrals), treat as renewal
  try {
    const u = await User.findById(userId).select('_id referralActivatedAt').lean().exec();
    if (u?.referralActivatedAt) return Math.round(cfg.renewalFeePaise / 100);
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
    if (hasActivation) return Math.round(cfg.renewalFeePaise / 100);
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

  return qualifyingDeposit
    ? Math.round(cfg.renewalFeePaise / 100)
    : Math.round(cfg.registrationFeePaise / 100);
}

const GST_RATE = (() => {
  const raw = Number.parseFloat(process.env.GST_RATE || '0.18');
  return Number.isFinite(raw) && raw >= 0 ? raw : 0.18;
})();
const GST_PERCENT = Math.round(GST_RATE * 100);

function parsePagination(query) {
  const limitRaw = Number.parseInt(query?.limit ?? '25', 10);
  const pageRaw = Number.parseInt(query?.page ?? '1', 10);
  const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 200) : 25;
  const page = Number.isFinite(pageRaw) && pageRaw > 0 ? pageRaw : 1;
  return { limit, page, skip: (page - 1) * limit };
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

    const minRupees = await computeDynamicMinRupees(userId);

    if (!Number.isFinite(amountInRupees) || amountInRupees < minRupees) {
      return res.status(400).json({
        error: 'amount_below_minimum',
        minimumRupees: minRupees,
      });
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

    return res.json({
      key: process.env.RAZORPAY_KEY_ID,
      order_id: order.id,
      amount: order.amount,
      currency: order.currency,
      minimumRupees: minRupees,
    });
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

    let paymentAmount = null;
    try {
      const rzp = getRazorpay();
      const pmt = await rzp.payments.fetch(razorpay_payment_id);
      if (!['captured', 'authorized'].includes(pmt.status)) {
        return res.status(400).json({ error: 'payment_not_captured' });
      }
      paymentAmount = Number(pmt.amount);
    } catch (fetchErr) {
      console.warn('payments.fetch failed; proceeding with signature-only verification');
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
      throw new Error('invalid_payment_amount');
    }
    const minRupees = await computeDynamicMinRupees(req.user.sub);
    const minPaise = minRupees * 100;
    if (creditAmount < minPaise) {
      return res.status(400).json({
        error: 'amount_below_minimum',
        minimumPaise: minPaise,
        minimumRupees: minRupees,
      });
    }

    const session = await mongoose.startSession();
    let referralResult = { payouts: [], activated: false };
    try {
      await session.withTransaction(async () => {
        const userId = req.user.sub;
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
              note: 'Razorpay top-up',
              extRef: razorpay_payment_id,
              metadata: {
                orderId: razorpay_order_id,
              },
            },
          ],
          { session },
        );

        const cfg = getReferralConfig();
        const near = (a, b) => Math.abs(a - b) <= 100; // ₹1 tolerance
        const kind = near(creditAmount, cfg.registrationFeePaise)
          ? 'REGISTRATION'
          : near(creditAmount, cfg.renewalFeePaise)
            ? 'RENEWAL'
            : undefined;

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

    return res.json({
      ok: true,
      creditedPaise: creditAmount,
      referral: referralResult,
    });
  } catch (e) {
    console.error('topups/verify error', e);
    if (e?.code === 11000) {
      return res.json({ ok: true });
    }
    return res.status(500).json({ error: 'verification_failed' });
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

export default router;
