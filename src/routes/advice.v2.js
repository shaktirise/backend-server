import express from 'express';
import mongoose from 'mongoose';
import AdviceV2, { ADVICE_V2_CATEGORIES, normalizeAdviceV2Category } from '../models/AdviceV2.js';
import Purchase from '../models/Purchase.js';
import User from '../models/User.js';
import { ensureWallet } from '../services/wallet.js';
import Wallet from '../models/Wallet.js';
import WalletLedger from '../models/WalletLedger.js';
import { auth, admin } from '../middleware/auth.js';
import { sendPushToAll } from '../services/push.js';
import { formatLocalISO, toEpochMs } from '../utils/time.js';

const router = express.Router();

const ADVICE_PUSH_LABELS = {
  STOCKS: 'Stocks',
  FUTURE: 'Future',
  OPTIONS: 'Options',
  COMMODITY: 'Commodity',
};

function buildAdviceNotification(doc, overrides = {}) {
  const label = ADVICE_PUSH_LABELS[doc.category] || doc.category;
  const title = typeof overrides.title === 'string' && overrides.title.trim()
    ? overrides.title.trim()
    : `${label} update`;
  const body = typeof overrides.body === 'string' && overrides.body.trim()
    ? overrides.body.trim()
    : `${label} has a new message.`;
  const data = {
    type: 'advice_v2',
    category: doc.category,
    adviceId: doc._id.toString(),
  };
  if (overrides.data && typeof overrides.data === 'object') {
    Object.entries(overrides.data).forEach(([key, value]) => {
      if (value !== undefined) data[key] = value;
    });
  }
  return { title, body, data };
}

async function maybeSendAdvicePush(doc, req) {
  const notify = req.body?.notify !== false;
  if (!notify) return null;

  const payload = buildAdviceNotification(doc, {
    title: req.body?.notifyTitle,
    body: req.body?.notifyBody,
    data: req.body?.notifyData,
  });
  const dryRun = req.body?.dryRun === true;

  try {
    return await sendPushToAll({
      title: payload.title,
      body: payload.body,
      data: payload.data,
      dryRun,
    });
  } catch (err) {
    console.error('advice-v2 push error', err);
    return { ok: false, error: 'push_failed' };
  }
}

async function createAdviceForCategory(category, { text, buy, target, stoploss, price }, userId) {
  const normalized = normalizeAdviceV2Category(category);
  if (!normalized) {
    const err = new Error('invalid category');
    err.code = 'INVALID_CATEGORY';
    err.allowed = ADVICE_V2_CATEGORIES;
    throw err;
  }

  let combined = (text ?? '').toString().trim();
  const buyText = (buy ?? '').toString().trim();
  const tgtText = (target ?? '').toString().trim();
  const slText = (stoploss ?? '').toString().trim();
  if (!combined) {
    const parts = [];
    if (buyText) parts.push(`BUY: ${buyText}`);
    if (tgtText) parts.push(`TARGET: ${tgtText}`);
    if (slText) parts.push(`STOPLOSS: ${slText}`);
    combined = parts.join('\n');
  }
  if (!combined) {
    const err = new Error('message required');
    err.code = 'MESSAGE_REQUIRED';
    throw err;
  }

  const rupees = Number.isFinite(price) ? Number(price) : undefined;
  const doc = await AdviceV2.create({
    category: normalized,
    text: combined,
    buy: buyText,
    target: tgtText,
    stoploss: slText,
    price: rupees ?? 116,
    updatedBy: userId || null,
  });
  return doc;
}

router.post('/', auth, admin, async (req, res) => {
  try {
    const { category, text, price, buy, target, stoploss } = req.body || {};
    const doc = await createAdviceForCategory(category, { text, buy, target, stoploss, price }, req.user?.id);
    const push = await maybeSendAdvicePush(doc, req);
    return res.json({ ok: true, id: doc._id, category: doc.category, push });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

// Convenience admin endpoints for fixed categories
router.post('/stocks', auth, admin, async (req, res) => {
  try {
    const doc = await createAdviceForCategory('STOCKS', req.body || {}, req.user?.id);
    const push = await maybeSendAdvicePush(doc, req);
    return res.json({ ok: true, id: doc._id, category: doc.category, push });
  } catch (e) {
    if (e?.code === 'MESSAGE_REQUIRED') return res.status(400).json({ error: 'message required' });
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/options', auth, admin, async (req, res) => {
  try {
    const doc = await createAdviceForCategory('OPTIONS', req.body || {}, req.user?.id);
    const push = await maybeSendAdvicePush(doc, req);
    return res.json({ ok: true, id: doc._id, category: doc.category, push });
  } catch (e) {
    if (e?.code === 'MESSAGE_REQUIRED') return res.status(400).json({ error: 'message required' });
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/future', auth, admin, async (req, res) => {
  try {
    const doc = await createAdviceForCategory('FUTURE', req.body || {}, req.user?.id);
    const push = await maybeSendAdvicePush(doc, req);
    return res.json({ ok: true, id: doc._id, category: doc.category, push });
  } catch (e) {
    if (e?.code === 'MESSAGE_REQUIRED') return res.status(400).json({ error: 'message required' });
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/commodity', auth, admin, async (req, res) => {
  try {
    const doc = await createAdviceForCategory('COMMODITY', req.body || {}, req.user?.id);
    const push = await maybeSendAdvicePush(doc, req);
    return res.json({ ok: true, id: doc._id, category: doc.category, push });
  } catch (e) {
    if (e?.code === 'MESSAGE_REQUIRED') return res.status(400).json({ error: 'message required' });
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/', auth, async (req, res) => {
  try {
    const category = req.query.category ? normalizeAdviceV2Category(req.query.category) : null;
    const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
    const skip = (page - 1) * limit;

    const filter = {};
    if (category) filter.category = category;

    const [items, total] = await Promise.all([
      AdviceV2.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
      AdviceV2.countDocuments(filter),
    ]);

    const payload = items.map((a) => ({
      id: a._id,
      category: a.category,
      createdAt: a.createdAt,
      createdAtLocal: a.createdAt ? formatLocalISO(a.createdAt) : null,
      createdAtMs: a.createdAt ? toEpochMs(a.createdAt) : null,
      price: a.price,
    }));
    return res.json({ ok: true, items: payload, page, limit, total, totalPages: Math.ceil(total / limit) || 1 });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/latest', auth, async (req, res) => {
  try {
    const category = req.query.category ? normalizeAdviceV2Category(req.query.category) : null;
    if (!category) return res.status(400).json({ error: 'invalid category' });
    const advice = await AdviceV2.findOne({ category }).sort({ createdAt: -1 });
    if (!advice) return res.json({ advice: null });
    return res.json({ advice: { id: advice._id, category: advice.category, createdAt: advice.createdAt, price: advice.price } });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

// Path-variant of latest by category
router.get('/:category/latest', auth, async (req, res) => {
  try {
    const category = normalizeAdviceV2Category(req.params.category);
    if (!category) return res.status(400).json({ error: 'invalid category' });
    const advice = await AdviceV2.findOne({ category }).sort({ createdAt: -1 });
    if (!advice) return res.json({ advice: null });
    return res.json({ advice: { id: advice._id, category: advice.category, createdAt: advice.createdAt, price: advice.price } });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/:id/unlock', auth, async (req, res) => {
  try {
    const advice = await AdviceV2.findById(req.params.id);
    if (!advice) return res.status(404).json({ error: 'advice not found' });

    const userId = req.user?.id || req.user?.sub;
    if (!userId) return res.status(401).json({ error: 'unauthorized' });

    const priceRupees = Number.isFinite(advice.price) ? Number(advice.price) : 116;
    const pricePaise = Math.max(0, Math.round(priceRupees * 100));

    const existing = await Purchase.findOne({ user: userId, 'metadata.adviceV2Id': advice._id }).lean();
    if (existing) {
      const wallet = await ensureWallet(userId);
      const walletBalancePaise = wallet?.balance ?? 0;
      const walletBalance = Math.floor(walletBalancePaise / 100);
      const walletBalanceRupees = Math.round((walletBalancePaise / 100) * 100) / 100;
      return res.json({
        advice: serializeAdvice(advice),
        walletBalance,
        walletBalancePaise,
        walletBalanceRupees,
      });
    }

    const session = await mongoose.startSession();
    let purchaseRecord = null;
    let walletBalancePaise = null;
    let insufficientFunds = false;
    const note = `Advice V2 unlock - ${advice.category || 'GENERAL'}`;

    try {
      await session.withTransaction(async () => {
        const wallet = await ensureWallet(userId, session);
        const already = await Purchase.findOne({ user: userId, 'metadata.adviceV2Id': advice._id })
          .session(session)
          .exec();
        if (already) {
          purchaseRecord = already;
          walletBalancePaise = wallet?.balance ?? 0;
          return;
        }

        const currentBalance = wallet?.balance ?? 0;
        let ledgerEntryId = null;

        if (pricePaise > 0) {
          if (currentBalance < pricePaise) {
            const err = new Error('INSUFFICIENT_FUNDS');
            err.code = 'INSUFFICIENT_FUNDS';
            throw err;
          }

          walletBalancePaise = currentBalance - pricePaise;
          await Wallet.updateOne({ _id: wallet._id }, { $inc: { balance: -pricePaise } }, { session });

          const [ledgerEntry] = await WalletLedger.create([
            {
              walletId: wallet._id,
              userId: wallet.userId || userId,
              type: 'PURCHASE',
              amount: -pricePaise,
              note,
              metadata: { adviceV2Id: advice._id, category: advice.category, pricePaise },
            },
          ], { session });
          ledgerEntryId = ledgerEntry._id;

          const [createdPurchase] = await Purchase.create([
            {
              user: userId,
              amount: Math.round(pricePaise / 100),
              amountPaise: pricePaise,
              note,
              category: advice.category,
              title: advice.text?.slice(0, 120) || advice.category || null,
              walletLedgerId: ledgerEntryId,
              metadata: { adviceV2Id: advice._id, category: advice.category, ledgerId: ledgerEntryId, pricePaise },
            },
          ], { session });
          purchaseRecord = createdPurchase;
        } else {
          walletBalancePaise = currentBalance;
          const [createdPurchase] = await Purchase.create([
            {
              user: userId,
              amount: 0,
              amountPaise: 0,
              note: `${note} (free)`,
              category: advice.category,
              title: advice.text?.slice(0, 120) || advice.category || null,
              metadata: { adviceV2Id: advice._id, category: advice.category, pricePaise: 0 },
            },
          ], { session });
          purchaseRecord = createdPurchase;
        }
      });
    } catch (err) {
      if (err?.code === 'INSUFFICIENT_FUNDS') {
        insufficientFunds = true;
      } else {
        console.error('advice-v2 unlock transaction error', err);
        throw err;
      }
    } finally {
      await session.endSession();
    }

    if (insufficientFunds) {
      return res.status(402).json({ error: 'INSUFFICIENT_FUNDS', topupRequired: true });
    }

    if (!Number.isFinite(walletBalancePaise)) {
      const wallet = await ensureWallet(userId);
      walletBalancePaise = wallet?.balance ?? 0;
    }
    const walletBalance = Math.floor((walletBalancePaise || 0) / 100);
    const walletBalanceRupees = Math.round(((walletBalancePaise || 0) / 100) * 100) / 100;

    if (!purchaseRecord) {
      const fallback = await Purchase.findOne({ user: userId, 'metadata.adviceV2Id': advice._id }).lean();
      if (!fallback) return res.status(500).json({ error: 'purchase_not_recorded' });
    }

    return res.json({ advice: serializeAdvice(advice), walletBalance, walletBalancePaise, walletBalanceRupees });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

// Unlock the latest advice for a category (deducts wallet balance)
router.post('/:category/unlock-latest', auth, async (req, res) => {
  try {
    const category = normalizeAdviceV2Category(req.params.category);
    if (!category) return res.status(400).json({ error: 'invalid category' });
    const latest = await AdviceV2.findOne({ category }).sort({ createdAt: -1 });
    if (!latest) return res.status(404).json({ error: 'advice not found' });

    // Delegate to the /:id/unlock logic by emulating the call here without duplicating response shape
    req.params.id = latest._id.toString();
    // Reuse handler by calling next route? Simpler to inline by calling the existing unlock logic.
    // For clarity and stability, call the unlock handler directly would require refactor. So we copy minimal logic.

    const userId = req.user?.id || req.user?.sub;
    const priceRupees = Number.isFinite(latest.price) ? Number(latest.price) : 116;
    const pricePaise = Math.max(0, Math.round(priceRupees * 100));

    const existing = await Purchase.findOne({ user: userId, 'metadata.adviceV2Id': latest._id }).lean();
    if (existing) {
      const wallet = await ensureWallet(userId);
      const walletBalancePaise = wallet?.balance ?? 0;
      const walletBalance = Math.floor(walletBalancePaise / 100);
      const walletBalanceRupees = Math.round((walletBalancePaise / 100) * 100) / 100;
      return res.json({ advice: serializeAdvice(latest), walletBalance, walletBalancePaise, walletBalanceRupees });
    }

    const session = await mongoose.startSession();
    let purchaseRecord = null;
    let walletBalancePaise = null;
    let insufficientFunds = false;
    const note = `Advice V2 unlock - ${latest.category || 'GENERAL'}`;

    try {
      await session.withTransaction(async () => {
        const wallet = await ensureWallet(userId, session);
        const already = await Purchase.findOne({ user: userId, 'metadata.adviceV2Id': latest._id })
          .session(session)
          .exec();
        if (already) {
          purchaseRecord = already;
          walletBalancePaise = wallet?.balance ?? 0;
          return;
        }

        const currentBalance = wallet?.balance ?? 0;
        let ledgerEntryId = null;

        if (pricePaise > 0) {
          if (currentBalance < pricePaise) {
            const err = new Error('INSUFFICIENT_FUNDS');
            err.code = 'INSUFFICIENT_FUNDS';
            throw err;
          }

          walletBalancePaise = currentBalance - pricePaise;
          await Wallet.updateOne({ _id: wallet._id }, { $inc: { balance: -pricePaise } }, { session });

          const [ledgerEntry] = await WalletLedger.create([
            { walletId: wallet._id, userId: wallet.userId || userId, type: 'PURCHASE', amount: -pricePaise, note, metadata: { adviceV2Id: latest._id, category, pricePaise } },
          ], { session });
          ledgerEntryId = ledgerEntry._id;

          const [createdPurchase] = await Purchase.create([
            { user: userId, amount: Math.round(pricePaise / 100), amountPaise: pricePaise, note, category, title: latest.text?.slice(0, 120) || category || null, walletLedgerId: ledgerEntryId, metadata: { adviceV2Id: latest._id, category, ledgerId: ledgerEntryId, pricePaise } },
          ], { session });
          purchaseRecord = createdPurchase;
        } else {
          walletBalancePaise = currentBalance;
          const [createdPurchase] = await Purchase.create([
            { user: userId, amount: 0, amountPaise: 0, note: `${note} (free)`, category, title: latest.text?.slice(0, 120) || category || null, metadata: { adviceV2Id: latest._id, category, pricePaise: 0 } },
          ], { session });
          purchaseRecord = createdPurchase;
        }
      });
    } catch (err) {
      if (err?.code === 'INSUFFICIENT_FUNDS') {
        insufficientFunds = true;
      } else {
        console.error('advice-v2 unlock-latest transaction error', err);
        throw err;
      }
    } finally {
      await session.endSession();
    }

    if (insufficientFunds) return res.status(402).json({ error: 'INSUFFICIENT_FUNDS', topupRequired: true });

    if (!Number.isFinite(walletBalancePaise)) {
      const wallet = await ensureWallet(userId);
      walletBalancePaise = wallet?.balance ?? 0;
    }
    const walletBalance = Math.floor((walletBalancePaise || 0) / 100);
    const walletBalanceRupees = Math.round(((walletBalancePaise || 0) / 100) * 100) / 100;
    if (!purchaseRecord) {
      const fallback = await Purchase.findOne({ user: userId, 'metadata.adviceV2Id': latest._id }).lean();
      if (!fallback) return res.status(500).json({ error: 'purchase_not_recorded' });
    }
    return res.json({ advice: serializeAdvice(latest), walletBalance, walletBalancePaise, walletBalanceRupees });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

function serializeAdvice(advice) {
  return {
    id: advice._id,
    category: advice.category,
    text: advice.text,
    buy: advice.buy || null,
    target: advice.target || null,
    stoploss: advice.stoploss || null,
    createdAt: advice.createdAt,
    createdAtLocal: advice.createdAt ? formatLocalISO(advice.createdAt) : null,
    createdAtMs: advice.createdAt ? toEpochMs(advice.createdAt) : null,
    price: advice.price,
  };
}

export default router;
