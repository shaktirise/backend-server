import mongoose from 'mongoose';

const { Schema } = mongoose;

const WalletLedgerSchema = new Schema(
  {
    walletId: { type: Schema.Types.ObjectId, ref: 'Wallet', required: true, index: true },
    type: { type: String, enum: ['TOPUP', 'PURCHASE'], required: true },
    // Amount in paise (integer). Positive for credit, negative for debit.
    amount: { type: Number, required: true },
    note: { type: String },
    // External reference for idempotency (e.g., Razorpay payment_id)
    extRef: { type: String, unique: true, sparse: true, index: true },
  },
  { 
    timestamps: true 
  }
);

export default mongoose.model('WalletLedger', WalletLedgerSchema);

