import express from 'express';
import { auth } from '../middleware/auth.js';
import User from '../models/User.js';
import Purchase from '../models/Purchase.js';

const router = express.Router();

router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(401).json({ error: 'unauthorized' });
    const purchases = await Purchase.find({ user: user._id }).sort({ createdAt: -1 }).populate('advice', 'category price createdAt');
    return res.json({ walletBalance: user.walletBalance, purchases });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

export default router;
