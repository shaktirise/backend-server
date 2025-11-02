import express from 'express';
import { sendTextSms } from '../services/sms.js';
import TradeMessage, { normalizeTradeMessageCategory } from '../models/TradeMessage.js';

const router = express.Router();

function requireTestApiKey(req, res, next) {
  const expected = process.env.SMS_TEST_API_KEY || '';
  const provided = req.headers['x-api-key'] || req.query.api_key || req.body?.apiKey;
  if (!expected) return res.status(500).json({ error: 'sms_test_api_key_not_configured' });
  if (String(provided) !== String(expected)) return res.status(401).json({ error: 'invalid_api_key' });
  next();
}

function buildMessageFromDoc(doc, overrides = {}) {
  // If explicit text provided, prefer that
  const explicitText = (overrides.text || '').toString().trim();
  if (explicitText) return explicitText;

  if (!doc) return '';
  const text = (doc.text || '').toString().trim();
  if (text) return text;

  const buy = (doc.buy || overrides.buy || '').toString().trim();
  const target = (doc.target || overrides.target || '').toString().trim();
  const stoploss = (doc.stoploss || overrides.stoploss || '').toString().trim();
  const parts = [];
  if (buy) parts.push(`BUY: ${buy}`);
  if (target) parts.push(`TARGET: ${target}`);
  if (stoploss) parts.push(`STOPLOSS: ${stoploss}`);
  return parts.join('\n');
}

// POST /api/sms/test/:category
// Body: { to: "+91...", text?: string }
router.post('/test/:category', requireTestApiKey, async (req, res) => {
  try {
    const category = normalizeTradeMessageCategory(req.params.category);
    if (!category) return res.status(404).json({ error: 'category_not_found' });

    const to = req.body?.to || req.body?.phone;
    if (!to) return res.status(400).json({ error: 'to_required' });

    const doc = await TradeMessage.findOne({ category }).lean();
    const body = buildMessageFromDoc(doc, req.body || {});
    if (!body) return res.status(400).json({ error: 'message_empty' });

    const result = await sendTextSms(to, body, { dryRun: true });
    if (!result.ok) {
      return res.status(502).json({ ok: false, error: result.error || 'send_failed' });
    }
    return res.json({ ok: true, simulated: !!result.simulated, preview: { to, body }, category });
  } catch (err) {
    console.error('sms test send error', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

export default router;
