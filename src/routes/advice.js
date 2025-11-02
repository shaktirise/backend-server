import express from 'express';
import mongoose from 'mongoose';
import Advice, { ADVICE_CATEGORIES, normalizeAdviceCategory } from '../models/Advice.js';
import Purchase from '../models/Purchase.js';
import User from '../models/User.js';
import Wallet from '../models/Wallet.js';
import WalletLedger from '../models/WalletLedger.js';
import { ensureWallet } from '../services/wallet.js';
import { auth, admin } from '../middleware/auth.js';

const router = express.Router();

// Create a new advice entry for a category.
router.post('/', auth, admin, async (req, res) => {
  try {
    const { category, text, price, buy, target, stoploss } = req.body || {};
    const normalized = normalizeAdviceCategory(category);
    if (!normalized) {
      return res.status(400).json({ error: 'invalid category', allowed: ADVICE_CATEGORIES });
    }

    // Build combined text if not provided
    const buyText = (buy ?? '').toString().trim();
    const tgtText = (target ?? '').toString().trim();
    const slText = (stoploss ?? '').toString().trim();
    let combined = (text ?? '').toString().trim();
    if (!combined) {
      const parts = [];
      if (buyText) parts.push(`BUY: ${buyText}`);
      if (tgtText) parts.push(`TARGET: ${tgtText}`);
      if (slText) parts.push(`STOPLOSS: ${slText}`);
      combined = parts.join('\n');
    }
    if (!combined) {
      return res.status(400).json({ error: 'message required' });
    }

    const rupees = Number.isFinite(price) ? Number(price) : undefined;
    const advice = await Advice.create({
      category: normalized,
      text: combined,
      buy: buyText,
      target: tgtText,
      stoploss: slText,
      price: rupees ?? 116,
    });

    const io = req.app.get('io');
    io.emit('advice:new', { id: advice._id.toString(), category: advice.category, createdAt: advice.createdAt, price: advice.price });

    return res.json({ ok: true, id: advice._id, category: advice.category });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

// List advices with optional category filter and paging
router.get('/', auth, async (req, res) => {
  try {
    const raw = req.query.category;
    const category = raw ? normalizeAdviceCategory(raw) : null;
    const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
    const skip = (page - 1) * limit;

    const filter = {};
    if (category) filter.category = category;

    const [items, total] = await Promise.all([
      Advice.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
      Advice.countDocuments(filter),
    ]);

    const payload = items.map((a) => ({
      id: a._id,
      category: a.category,
      createdAt: a.createdAt,
      price: a.price,
      // do not send text/buy/target/stoploss until unlocked
    }));

    return res.json({
      ok: true,
      items: payload,
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit) || 1,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/latest', auth, async (req, res) => {
  try {
    const { category } = req.query;
    const normalized = normalizeAdviceCategory(category);
    if (!normalized) return res.status(400).json({ error: 'invalid category' });
    const advice = await Advice.findOne({ category: normalized }).sort({ createdAt: -1 });
    if (!advice) return res.json({ advice: null });
    return res.json({ advice: { id: advice._id, category: advice.category, createdAt: advice.createdAt, price: advice.price } });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/:id/unlock', auth, async (req, res) => {
  try {
    const advice = await Advice.findById(req.params.id);
    if (!advice) return res.status(404).json({ error: 'advice not found' });

    const userId = req.user?.id || req.user?.sub;
    if (!userId) return res.status(401).json({ error: 'unauthorized' });

    const user = await User.findById(userId);
    if (!user) return res.status(401).json({ error: 'unauthorized' });

    const priceRupees = Number.isFinite(advice.price) ? Number(advice.price) : 116;
    const pricePaise = Math.max(0, Math.round(priceRupees * 100));

    const existing = await Purchase.findOne({ user: user._id, advice: advice._id }).lean();
    if (existing) {
      const wallet = await ensureWallet(user._id);
      const walletBalancePaise = wallet?.balance ?? 0;
      const walletBalance = Math.floor(walletBalancePaise / 100);
      const walletBalanceRupees = Math.round((walletBalancePaise / 100) * 100) / 100;

      await User.updateOne({ _id: user._id }, { walletBalance }).catch(() => {});

      return res.json({
        advice: {
          id: advice._id,
          category: advice.category,
          text: advice.text,
          createdAt: advice.createdAt,
          price: advice.price,
        },
        walletBalance,
        walletBalancePaise,
        walletBalanceRupees,
      });
    }

    const session = await mongoose.startSession();
    let purchaseRecord = null;
    let walletBalancePaise = null;
    let insufficientFunds = false;

    const baseNote = `Advice unlock - ${advice.category || 'GENERAL'}`;

    try {
      await session.withTransaction(async () => {
        const wallet = await ensureWallet(user._id, session);
        const already = await Purchase.findOne({ user: user._id, advice: advice._id })
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

          await Wallet.updateOne(
            { _id: wallet._id },
            { $inc: { balance: -pricePaise } },
            { session }
          );

          const [ledgerEntry] = await WalletLedger.create(
            [
              {
                walletId: wallet._id,
                userId: user._id,
                type: 'PURCHASE',
                amount: -pricePaise,
                note: baseNote,
                metadata: {
                  adviceId: advice._id,
                  adviceCategory: advice.category,
                  pricePaise,
                },
              },
            ],
            { session }
          );
          ledgerEntryId = ledgerEntry._id;

          const [createdPurchase] = await Purchase.create(
            [
              {
                user: user._id,
                advice: advice._id,
                amount: Math.round(pricePaise / 100),
                amountPaise: pricePaise,
                note: baseNote,
                category: advice.category,
                title: advice.text?.slice(0, 120) || advice.category || null,
                walletLedgerId: ledgerEntryId,
                metadata: {
                  adviceId: advice._id,
                  adviceCategory: advice.category,
                  ledgerId: ledgerEntryId,
                  pricePaise,
                },
              },
            ],
            { session }
          );
          purchaseRecord = createdPurchase;
        } else {
          walletBalancePaise = currentBalance;

          const [createdPurchase] = await Purchase.create(
            [
              {
                user: user._id,
                advice: advice._id,
                amount: 0,
                amountPaise: 0,
                note: `${baseNote} (free)`,
                category: advice.category,
                title: advice.text?.slice(0, 120) || advice.category || null,
                metadata: {
                  adviceId: advice._id,
                  adviceCategory: advice.category,
                  pricePaise: 0,
                },
              },
            ],
            { session }
          );
          purchaseRecord = createdPurchase;
        }
      });
    } catch (err) {
      if (err?.code === 'INSUFFICIENT_FUNDS') {
        insufficientFunds = true;
      } else {
        console.error('advice unlock transaction error', err);
        throw err;
      }
    } finally {
      await session.endSession();
    }

    if (insufficientFunds) {
      return res.status(402).json({ error: 'INSUFFICIENT_FUNDS', topupRequired: true });
    }

    if (!purchaseRecord) {
      const fallback = await Purchase.findOne({ user: user._id, advice: advice._id }).lean();
      if (fallback) {
        purchaseRecord = fallback;
      }
    }

    if (!Number.isFinite(walletBalancePaise)) {
      const wallet = await ensureWallet(user._id);
      walletBalancePaise = wallet?.balance ?? 0;
    }

    const walletBalance = Math.floor((walletBalancePaise || 0) / 100);
    const walletBalanceRupees = Math.round(((walletBalancePaise || 0) / 100) * 100) / 100;

    await User.updateOne({ _id: user._id }, { walletBalance }).catch(() => {});

    if (!purchaseRecord) {
      return res.status(500).json({ error: 'purchase_not_recorded' });
    }

    return res.json({
      advice: {
        id: advice._id,
        category: advice.category,
        text: advice.text,
        buy: advice.buy || null,
        target: advice.target || null,
        stoploss: advice.stoploss || null,
        createdAt: advice.createdAt,
        price: advice.price,
      },
      walletBalance,
      walletBalancePaise,
      walletBalanceRupees,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

export default router;
