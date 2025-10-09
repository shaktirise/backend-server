import mongoose from 'mongoose';

const { Schema } = mongoose;

const PurchaseSchema = new Schema(
  {
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    advice: { type: Schema.Types.ObjectId, ref: 'Advice', index: true },
    amount: { type: Number },
    amountPaise: { type: Number },
    note: { type: String },
    category: { type: String },
    title: { type: String },
    walletLedgerId: { type: Schema.Types.ObjectId, ref: 'WalletLedger', index: true },
    metadata: { type: Schema.Types.Mixed },
  },
  { timestamps: true }
);

PurchaseSchema.index({ user: 1, createdAt: -1 });
PurchaseSchema.index({ advice: 1, createdAt: -1 });

export default mongoose.model('Purchase', PurchaseSchema);
