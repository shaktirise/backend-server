import mongoose from 'mongoose';

// Updated to 4 keys: STOCKS, FUTURE, OPTIONS, COMMODITY
export const SEGMENT_KEYS = Object.freeze(['STOCKS', 'FUTURE', 'OPTIONS', 'COMMODITY']);

export function normalizeSegmentKey(value) {
  if (value === undefined || value === null) return null;
  const key = String(value)
    .trim()
    .toUpperCase()
    .replace(/[\s_-]+/g, '');
  const aliasMap = new Map([
    ['STOCK', 'STOCKS'],
    ['STOCKS', 'STOCKS'],
    ['FUTURE', 'FUTURE'],
    ['FUTURES', 'FUTURE'],
    ['OPTION', 'OPTIONS'],
    ['OPTIONS', 'OPTIONS'],
    ['COMMODITY', 'COMMODITY'],
    ['COMODITY', 'COMMODITY'],
    // legacy keys map to new segments where sensible
    ['NIFTY', 'FUTURE'],
    ['BANKNIFTY', 'FUTURE'],
    ['BANKNIFTY50', 'FUTURE'],
    ['BANKNIFTYINDEX', 'FUTURE'],
    ['SENSEX', 'STOCKS'],
  ]);
  const normalized = aliasMap.get(key) || key;
  return SEGMENT_KEYS.find((segment) => segment === normalized) || null;
}

const SegmentMessageSchema = new mongoose.Schema(
  {
    segment: { type: String, enum: SEGMENT_KEYS, required: true, unique: true },
    message: { type: String, trim: true, default: '', maxlength: 1000 },
    imageUrl: { type: String, trim: true, default: '' },
    imagePublicId: { type: String, trim: true, default: '' },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  },
  { timestamps: true }
);

export default mongoose.model('SegmentMessage', SegmentMessageSchema);
