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

export default mongoose.model('Advice', AdviceSchema);
