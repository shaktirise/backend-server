import mongoose from 'mongoose';

export const ADVICE_V2_CATEGORIES = Object.freeze([
  'STOCKS',
  'FUTURE',
  'OPTIONS',
  'COMMODITY',
]);

export function normalizeAdviceV2Category(value) {
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
  ]);
  const normalized = alias.get(key) || key;
  return ADVICE_V2_CATEGORIES.includes(normalized) ? normalized : null;
}

const AdviceV2Schema = new mongoose.Schema(
  {
    category: { type: String, enum: ADVICE_V2_CATEGORIES, required: true, index: true },
    text: { type: String, required: true, trim: true, maxlength: 2000 },
    buy: { type: String, trim: true, default: '' },
    target: { type: String, trim: true, default: '' },
    stoploss: { type: String, trim: true, default: '' },
    price: { type: Number, default: 116 },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  },
  { timestamps: true }
);

// Auto-delete advice 6 hours after creation so stale calls do not clutter the feed
AdviceV2Schema.index({ createdAt: 1 }, { expireAfterSeconds: 6 * 60 * 60 });

export default mongoose.model('AdviceV2', AdviceV2Schema);
