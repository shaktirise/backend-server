import express from 'express';
import Advice from '../models/Advice.js';
import Purchase from '../models/Purchase.js';
import User from '../models/User.js';
import { auth, admin } from '../middleware/auth.js';

const router = express.Router();

router.post('/', auth, admin, async (req, res) => {
  try {
    const { category, text, price } = req.body;
    if (!category || !text) return res.status(400).json({ error: 'category and text required' });
    const advice = await Advice.create({ category, text, price: price || 100 });

    const io = req.app.get('io');
    io.emit('advice:new', { id: advice._id.toString(), category: advice.category, createdAt: advice.createdAt, price: advice.price });

    return res.json({ ok: true, id: advice._id });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/latest', auth, async (req, res) => {
  try {
    const { category } = req.query;
    if (!category) return res.status(400).json({ error: 'category required' });
    const advice = await Advice.findOne({ category }).sort({ createdAt: -1 });
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

    const user = await User.findById(req.user.id);
    if (!user) return res.status(401).json({ error: 'unauthorized' });

    const already = await Purchase.findOne({ user: user._id, advice: advice._id });
    if (already) return res.json({ advice: { id: advice._id, category: advice.category, text: advice.text, createdAt: advice.createdAt, price: advice.price }, walletBalance: user.walletBalance });

    const price = advice.price || 100;
    if (user.walletBalance < price) return res.status(400).json({ error: 'insufficient balance' });

    user.walletBalance -= price;
    await user.save();

    await Purchase.create({ user: user._id, advice: advice._id, amount: price });

    return res.json({ advice: { id: advice._id, category: advice.category, text: advice.text, createdAt: advice.createdAt, price: advice.price }, walletBalance: user.walletBalance });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

export default router;
