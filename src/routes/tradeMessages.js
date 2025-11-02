import express from 'express';
import { auth, admin } from '../middleware/auth.js';
import TradeMessage, { TRADE_MESSAGE_CATEGORIES, normalizeTradeMessageCategory } from '../models/TradeMessage.js';
import TradeMessageHistory from '../models/TradeMessageHistory.js';
import { sendTextSms } from '../services/sms.js';

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

// Send SMS for a specific trade message category (admin only)
// POST /api/trade-messages/:category/send-sms
// Body: { to: "+91...", text?: string, buy?: string, target?: string, stoploss?: string }
router.post('/:category/send-sms', auth, admin, async (req, res) => {
  try {
    const category = normalizeTradeMessageCategory(req.params.category);
    if (!category) return res.status(404).json({ error: 'category not found' });

    const to = req.body?.to || req.body?.phone;
    if (!to) return res.status(400).json({ error: 'to required' });

    const explicitText = (req.body?.text || '').toString().trim();
    let body = explicitText;

    if (!body) {
      const doc = await TradeMessage.findOne({ category }).lean();
      if (doc?.text && String(doc.text).trim()) {
        body = String(doc.text).trim();
      } else {
        const buy = (req.body?.buy || doc?.buy || '').toString().trim();
        const target = (req.body?.target || doc?.target || '').toString().trim();
        const stoploss = (req.body?.stoploss || doc?.stoploss || '').toString().trim();
        const parts = [];
        if (buy) parts.push(`BUY: ${buy}`);
        if (target) parts.push(`TARGET: ${target}`);
        if (stoploss) parts.push(`STOPLOSS: ${stoploss}`);
        body = parts.join('\n');
      }
    }

    if (!body) return res.status(400).json({ error: 'message empty' });

    const headerDry = String(req.headers['x-dry-run'] || '').toLowerCase();
    const queryDry = String(req.query.dryRun || req.query.dry || '').toLowerCase();
    const bodyDry = req.body?.dryRun === true || req.body?.dry === true;
    const dryRun = bodyDry || headerDry === 'true' || headerDry === '1' || queryDry === 'true' || queryDry === '1';

    const result = await sendTextSms(to, body, { dryRun });
    if (!result.ok) {
      return res.status(502).json({ ok: false, error: result.error || 'send_failed' });
    }
    return res.json({ ok: true, simulated: !!result.simulated, sid: result.sid || null, category, to, preview: result.simulated ? { to, body } : undefined });
  } catch (err) {
    console.error('trade-messages send-sms error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

export default router;
