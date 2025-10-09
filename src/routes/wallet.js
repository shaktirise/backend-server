import express from 'express';
import { auth } from '../middleware/auth.js';
import User from '../models/User.js';
import Purchase from '../models/Purchase.js';
import { ensureWallet } from '../services/wallet.js';

const router = express.Router();

router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(401).json({ error: 'unauthorized' });

    const [wallet, purchasesRaw] = await Promise.all([
      ensureWallet(user._id),
      Purchase.find({ user: user._id })
        .sort({ createdAt: -1 })
        .populate('advice', 'category price createdAt text')
        .lean(),
    ]);

    const purchases = purchasesRaw.map((purchase) => {
      const amountPaise = Number.isFinite(purchase.amountPaise)
        ? purchase.amountPaise
        : Number.isFinite(purchase.amount)
          ? Math.round(purchase.amount * 100)
          : null;
      const advice = purchase.advice && typeof purchase.advice === 'object' ? purchase.advice : null;
      return {
        id: purchase._id,
        adviceId: advice?._id || (purchase.advice && typeof purchase.advice === 'string' ? purchase.advice : null),
        title: purchase.title || advice?.text || null,
        category: purchase.category || advice?.category || null,
        amountPaise,
        amount: Number.isFinite(amountPaise) ? Math.round(amountPaise / 100) : null,
        note: purchase.note || null,
        createdAt: purchase.createdAt,
        metadata: purchase.metadata || null,
      };
    });

    return res.json({
      walletBalanceLegacy: user.walletBalance,
      walletBalancePaise: wallet?.balance ?? 0,
      walletBalanceRupees: Math.round(((wallet?.balance ?? 0) / 100) * 100) / 100,
      purchases,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

export default router;
