import express from 'express';
import DailyTip from '../models/DailyTip.js';

const router = express.Router();

router.get('/latest', async (req, res) => {
  try {
    const tip = await DailyTip.findOne({})
      .sort({ publishedAt: -1, createdAt: -1 })
      .lean();

    if (!tip) {
      return res.json({ tip: null });
    }

    return res.json({
      tip: {
        id: tip._id,
        message: tip.message,
        publishedAt: tip.publishedAt,
        createdAt: tip.createdAt,
      },
    });
  } catch (err) {
    console.error('daily tip latest error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/', async (req, res) => {
  try {
    const limit = Math.min(
      Math.max(parseInt(req.query.limit || '20', 10) || 20, 1),
      100
    );
    const tips = await DailyTip.find({})
      .sort({ publishedAt: -1, createdAt: -1 })
      .limit(limit)
      .lean();
    return res.json({
      items: tips.map((tip) => ({
        id: tip._id,
        message: tip.message,
        publishedAt: tip.publishedAt,
        createdAt: tip.createdAt,
      })),
    });
  } catch (err) {
    console.error('daily tip list error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

export default router;
