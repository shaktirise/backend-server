import mongoose from 'mongoose';

const PurchaseSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    advice: { type: mongoose.Schema.Types.ObjectId, ref: 'Advice', required: true, index: true },
    amount: { type: Number, required: true },
  },
  { timestamps: true }
);

export default mongoose.model('Purchase', PurchaseSchema);
