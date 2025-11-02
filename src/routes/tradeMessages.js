import express from 'express';
import { auth, admin } from '../middleware/auth.js';
import TradeMessage, { TRADE_MESSAGE_CATEGORIES, normalizeTradeMessageCategory } from '../models/TradeMessage.js';
import TradeMessageHistory from '../models/TradeMessageHistory.js';

const router = express.Router();

function serialize(doc, fallbackCategory) {
  if (!doc) {
    return {
      category: fallbackCategory,
      text: '',
      buy: '',
      target: '',
      stoploss: '',
      updatedAt: null,
      updatedBy: null,
    };
  }
  return {
    category: doc.category,
    text: doc.text || '',
    buy: doc.buy || '',
    target: doc.target || '',
    stoploss: doc.stoploss || '',
    updatedAt: doc.updatedAt || null,
    updatedBy: doc.updatedBy ? String(doc.updatedBy) : null,
  };
}

router.get('/', async (req, res) => {
  try {
    const items = await TradeMessage.find({ category: { $in: TRADE_MESSAGE_CATEGORIES } }).lean();
    const byCat = new Map(items.map((i) => [i.category, i]));
    return res.json({
      categories: TRADE_MESSAGE_CATEGORIES,
      items: TRADE_MESSAGE_CATEGORIES.map((cat) => serialize(byCat.get(cat), cat)),
    });
  } catch (err) {
    console.error('trade-messages list error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/:category', async (req, res) => {
  try {
    const category = normalizeTradeMessageCategory(req.params.category);
    if (!category) return res.status(404).json({ error: 'category not found' });
    const doc = await TradeMessage.findOne({ category }).lean();
    return res.json(serialize(doc, category));
  } catch (err) {
    console.error('trade-messages get error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/:category/history', async (req, res) => {
  try {
    const category = normalizeTradeMessageCategory(req.params.category);
    if (!category) return res.status(404).json({ error: 'category not found' });
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
    const entries = await TradeMessageHistory.find({ category })
      .sort({ createdAt: -1 })
      .limit(limit)
      .lean();
    return res.json({
      category,
      items: entries.map((e) => ({
        id: e._id,
        text: e.text || '',
        buy: e.buy || '',
        target: e.target || '',
        stoploss: e.stoploss || '',
        updatedAt: e.createdAt,
        updatedBy: e.updatedBy ? String(e.updatedBy) : null,
      })),
    });
  } catch (err) {
    console.error('trade-messages history error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.post('/:category', auth, admin, async (req, res) => {
  try {
    const category = normalizeTradeMessageCategory(req.params.category);
    if (!category) return res.status(404).json({ error: 'category not found' });

    const buy = (req.body?.buy ?? '').toString().trim();
    const target = (req.body?.target ?? '').toString().trim();
    const stoploss = (req.body?.stoploss ?? '').toString().trim();
    let text = (req.body?.text ?? '').toString().trim();

    if (!text) {
      const parts = [];
      if (buy) parts.push(`BUY: ${buy}`);
      if (target) parts.push(`TARGET: ${target}`);
      if (stoploss) parts.push(`STOPLOSS: ${stoploss}`);
      text = parts.join('\n');
    }

    if (!text) return res.status(400).json({ error: 'message required' });

    const update = {
      category,
      text,
      buy,
      target,
      stoploss,
      updatedBy: req.user?.id || null,
    };

    const doc = await TradeMessage.findOneAndUpdate(
      { category },
      update,
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );

    await TradeMessageHistory.create({
      category,
      text,
      buy,
      target,
      stoploss,
      updatedBy: req.user?.id || null,
    });

    const payload = serialize(doc, category);
    const io = req.app.get('io');
    if (io) {
      io.emit('trade-message:update', { category: payload.category, updatedAt: payload.updatedAt });
    }

    return res.json({ ok: true, message: payload });
  } catch (err) {
    console.error('trade-messages upsert error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

export default router;

