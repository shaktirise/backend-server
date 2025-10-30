import mongoose from 'mongoose';
import {
  WALLET_LEDGER_ALLOWED_TYPES,
  WALLET_LEDGER_TYPES,
  normalizeLedgerType,
} from '../constants/walletLedger.js';

const { Schema } = mongoose;

const WalletLedgerSchema = new Schema(
  {
    walletId: { type: Schema.Types.ObjectId, ref: 'Wallet', required: true, index: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User', index: true },
    type: { type: String, enum: WALLET_LEDGER_ALLOWED_TYPES, required: true },
    // Amount in paise (integer). Positive for credit, negative for debit.
    amount: { type: Number, required: true },
    note: { type: String },
    // External reference for idempotency (e.g., Razorpay payment_id)
    extRef: { type: String, unique: true, sparse: true, index: true },
    metadata: { type: Schema.Types.Mixed },
    normalizedType: {
      type: String,
      enum: Object.values(WALLET_LEDGER_TYPES),
      index: true,
    },
  },
  {
    timestamps: true,
  }
);

WalletLedgerSchema.index({ userId: 1, createdAt: -1 });
WalletLedgerSchema.index({ userId: 1, type: 1, createdAt: -1 });
WalletLedgerSchema.index({ userId: 1, normalizedType: 1, createdAt: -1 });
WalletLedgerSchema.index({ type: 1, createdAt: -1 });
WalletLedgerSchema.index({ normalizedType: 1, createdAt: -1 });

WalletLedgerSchema.pre('save', function walletLedgerNormalize(next) {
  if (this.isModified('type') || !this.normalizedType) {
    const normalized = normalizeLedgerType(this.type);
    if (normalized) {
      this.type = normalized;
      this.normalizedType = normalized;
    } else if (this.type) {
      this.normalizedType = this.type;
    }
  }
  next();
});

WalletLedgerSchema.pre('findOneAndUpdate', function walletLedgerNormalizeUpdate(next) {
  const update = this.getUpdate();
  if (update?.type) {
    const normalized = normalizeLedgerType(update.type);
    if (normalized) {
      update.type = normalized;
      update.normalizedType = normalized;
    }
  }
  if (update?.$set?.type) {
    const normalized = normalizeLedgerType(update.$set.type);
    if (normalized) {
      update.$set.type = normalized;
      update.$set.normalizedType = normalized;
    }
  }
  next();
});

export default mongoose.model('WalletLedger', WalletLedgerSchema);

