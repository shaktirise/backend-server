import express from 'express';
import Razorpay from 'razorpay';
import crypto from 'crypto';
import mongoose from 'mongoose';
import { auth } from '../middleware/auth.js';
import Wallet from '../models/Wallet.js';
import WalletLedger from '../models/WalletLedger.js';

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

async function ensureWallet(userId, session) {
  const opts = session ? { upsert: true, new: true, setDefaultsOnInsert: true, session } : { upsert: true, new: true, setDefaultsOnInsert: true };
  const wallet = await Wallet.findOneAndUpdate(
    { userId },
    { $setOnInsert: { balance: 0 } },
    opts
  );
  return wallet;
}

router.use(auth);

router.post('/topups/create-order', async (req, res) => {
  try {
    const userId = req.user.sub;
    const amountInRupees = Number.isFinite(req.body?.amountInRupees) ? Number(req.body.amountInRupees) : 1000; // default ₹1000
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

    const session = await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        const userId = req.user.sub;
        const wallet = await ensureWallet(userId, session);

        const creditAmount = Number.isFinite(paymentAmount) ? paymentAmount : null;
        if (!creditAmount || creditAmount <= 0) {
          
          throw new Error('invalid_payment_amount');
        }

        await Wallet.updateOne({ _id: wallet._id }, { $inc: { balance: creditAmount } }, { session });
        await WalletLedger.create([
          {
            walletId: wallet._id,
            type: 'TOPUP',
            amount: creditAmount,
            note: 'Razorpay top-up',
            extRef: razorpay_payment_id,
          },
        ], { session });
      });
    } finally {
      session.endSession();
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error('topups/verify error', e);
    if (e?.code === 11000) {
      
      return res.json({ ok: true });
    }
    return res.status(500).json({ error: 'verification_failed' });
  }
});

// advice 100rs debit 
router.post('/debit', async (req, res) => {
  try {
    const amountInRupees = Number.isFinite(req.body?.amountInRupees) ? Number(req.body.amountInRupees) : 100;
    const note = typeof req.body?.note === 'string' ? req.body.note : 'Advice purchase';
    const amount = Math.round(amountInRupees * 100);
    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: 'invalid_amount' });
    }

    const userId = req.user.sub;
    const wallet = await ensureWallet(userId);
    if ((wallet.balance || 0) < amount) {
      return res.status(402).json({ error: 'INSUFFICIENT_FUNDS', topupRequired: true });
    }

    const session = await mongoose.startSession();
    let newBalance = wallet.balance;
    try {
      await session.withTransaction(async () => {
        const fresh = await Wallet.findById(wallet._id).session(session).exec();
        if (!fresh || fresh.balance < amount) {
          throw Object.assign(new Error('insufficient_funds'), { code: 'INSUFFICIENT_FUNDS' });
        }
        newBalance = fresh.balance - amount;
        await Wallet.updateOne({ _id: wallet._id }, { $inc: { balance: -amount } }, { session });
        await WalletLedger.create([
          { walletId: wallet._id, type: 'PURCHASE', amount: -amount, note }
        ], { session });
      });
    } catch (txErr) {
      if (txErr?.code === 'INSUFFICIENT_FUNDS') {
        return res.status(402).json({ error: 'INSUFFICIENT_FUNDS', topupRequired: true });
      }
      throw txErr;
    } finally {
      session.endSession();
    }

    return res.json({ ok: true, newBalancePaise: newBalance });
  } catch (e) {
    console.error('debit error', e);
    return res.status(500).json({ error: 'debit_failed' });
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
