import mongoose from 'mongoose';

const AdviceSchema = new mongoose.Schema(
  {
    category: {
      type: String,
      enum: ['NIFTY', 'BANK_NIFTY', 'SENSEX', 'STOCK', 'COMMODITY'],
      required: true,
      index: true,
    },
    text: { type: String, required: true },
    price: { type: Number, default: 100 },
  },
  { timestamps: true }
);

// Auto-delete advice 12 hours after creation so users only see fresh calls
AdviceSchema.index({ createdAt: 1 }, { expireAfterSeconds: 12 * 60 * 60 });

export default mongoose.model('Advice', AdviceSchema);
