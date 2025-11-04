import express from 'express';
import mongoose from 'mongoose';
import { auth, admin } from '../middleware/auth.js';
import { getReferralConfig, handleReferralTopupPayout } from '../services/referral.js';

const router = express.Router();

// Admin-only helper APIs to simulate MLM payouts without Razorpay/wallet credit.
// These do NOT change wallet balances; they only record ReferralLedger entries
// as "pending" (dummy integer values) as per the 10-level scheme.

router.use(auth, admin);

router.get('/config', (req, res) => {
  try {
    const cfg = getReferralConfig();
    return res.json({
      registrationFeePaise: cfg.registrationFeePaise,
      renewalFeePaise: cfg.renewalFeePaise,
      registrationAmountsPaise: cfg.registrationAmountsPaise,
      renewalAmountsPaise: cfg.renewalAmountsPaise,
      maxDepth: cfg.maxDepth,
    });
  } catch (err) {
    console.error('mlm config error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/simulate', async (req, res) => {
  const { userId, type } = req.body || {};
  try {
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ error: 'invalid userId' });
    }
    const cfg = getReferralConfig();
    const kind = String(type || '').toUpperCase() === 'RENEWAL' ? 'RENEWAL' : 'REGISTRATION';
    const amount = kind === 'RENEWAL' ? cfg.renewalFeePaise : cfg.registrationFeePaise;

    const session = await mongoose.startSession();
    let result = { payouts: [], activated: false };
    try {
      await session.withTransaction(async () => {
        result = await handleReferralTopupPayout({
          userId,
          topupAmountPaise: amount,
          // No wallet ledger entry; extRef is just for traceability
          sourceLedger: { _id: null, extRef: `mlm:simulate:${kind}:${Date.now()}` },
          kind,
          session,
        });
      });
    } finally {
      await session.endSession();
    }

    const totalPaise = result.payouts.reduce((s, p) => s + (p.amountPaise || 0), 0);
    return res.json({ ok: true, kind, amountPaise: amount, totalDistributedPaise: totalPaise, ...result });
  } catch (err) {
    console.error('mlm simulate error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

export default router;

