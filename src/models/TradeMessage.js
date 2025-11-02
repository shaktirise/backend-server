import mongoose from 'mongoose';

export const TRADE_MESSAGE_CATEGORIES = Object.freeze([
  'STOCKS',
  'FUTURE',
  'OPTIONS',
  'COMMODITY',
]);

export function normalizeTradeMessageCategory(value) {
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
  return TRADE_MESSAGE_CATEGORIES.includes(normalized) ? normalized : null;
}

const TradeMessageSchema = new mongoose.Schema(
  {
    category: { type: String, enum: TRADE_MESSAGE_CATEGORIES, required: true, unique: true },
    text: { type: String, trim: true, default: '', maxlength: 2000 },
    buy: { type: String, trim: true, default: '' },
    target: { type: String, trim: true, default: '' },
    stoploss: { type: String, trim: true, default: '' },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  },
  { timestamps: true }
);

export default mongoose.model('TradeMessage', TradeMessageSchema);
