import mongoose from 'mongoose';

// New canonical categories: STOCKS, FUTURE, OPTIONS, COMMODITY
export const ADVICE_CATEGORIES = Object.freeze([
  'STOCKS',
  'FUTURE',
  'OPTIONS',
  'COMMODITY',
]);

export function normalizeAdviceCategory(value) {
  if (value === undefined || value === null) return null;
  const key = String(value).trim().toUpperCase();
  const alias = new Map([
    ['STOCK', 'STOCKS'],
    ['STOCKS', 'STOCKS'],
    ['FUTURE', 'FUTURE'],
    ['FUTURES', 'FUTURE'],
    ['OPTION', 'OPTIONS'],
    ['OPTIONS', 'OPTIONS'],
    ['COMMODITY', 'COMMODITY'],
    ['COMODITY', 'COMMODITY'],
    // legacy mappings
    ['NIFTY', 'FUTURE'],
    ['BANK_NIFTY', 'FUTURE'],
    ['BANKNIFTY', 'FUTURE'],
    ['SENSEX', 'STOCKS'],
  ]);
  const normalized = alias.get(key) || key;
  return ADVICE_CATEGORIES.includes(normalized) ? normalized : null;
}

const AdviceSchema = new mongoose.Schema(
  {
    category: {
      type: String,
      enum: ADVICE_CATEGORIES,
      required: true,
      index: true,
    },
    // Structured fields for clear separation in UI
    buy: { type: String, trim: true, default: '' },
    target: { type: String, trim: true, default: '' },
    stoploss: { type: String, trim: true, default: '' },
    // Backward/compat: combined text rendered to clients; server composes if not provided
    text: { type: String, required: true },
    // Price per advice (in rupees)
    price: { type: Number, default: 116 },
  },
  { timestamps: true }
);

export default mongoose.model('Advice', AdviceSchema);
