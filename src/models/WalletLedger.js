import mongoose from 'mongoose';

const { Schema } = mongoose;

const WalletLedgerSchema = new Schema(
  {
    walletId: { type: Schema.Types.ObjectId, ref: 'Wallet', required: true, index: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User', index: true },
    type: { type: String, enum: ['TOPUP', 'PURCHASE', 'REFERRAL'], required: true },
    // Amount in paise (integer). Positive for credit, negative for debit.
    amount: { type: Number, required: true },
    note: { type: String },
    // External reference for idempotency (e.g., Razorpay payment_id)
    extRef: { type: String, unique: true, sparse: true, index: true },
    metadata: { type: Schema.Types.Mixed },
  },
  { 
    timestamps: true 
  }
);

export default mongoose.model('WalletLedger', WalletLedgerSchema);

