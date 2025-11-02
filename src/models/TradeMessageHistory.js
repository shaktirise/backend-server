import mongoose from 'mongoose';

const TradeMessageHistorySchema = new mongoose.Schema(
  {
    category: { type: String, required: true, index: true },
    text: { type: String, trim: true, default: '' },
    buy: { type: String, trim: true, default: '' },
    target: { type: String, trim: true, default: '' },
    stoploss: { type: String, trim: true, default: '' },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  },
  { timestamps: true }
);

TradeMessageHistorySchema.index({ category: 1, createdAt: -1 });

export default mongoose.model('TradeMessageHistory', TradeMessageHistorySchema);

