import mongoose from 'mongoose';

const { Schema } = mongoose;

const WalletWithdrawalRequestSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    amountPaise: { type: Number, required: true },
    method: { type: String, enum: ['UPI', 'BANK'], required: true },

    // UPI details
    upiId: { type: String, trim: true },

    // Bank details
    bankAccountName: { type: String, trim: true },
    bankAccountNumber: { type: String, trim: true },
    bankIfsc: { type: String, trim: true },
    bankName: { type: String, trim: true },

    // Contact details
    contactName: { type: String, trim: true },
    contactMobile: { type: String, trim: true },

    note: { type: String, trim: true },

    status: { type: String, enum: ['pending', 'paid', 'cancelled'], default: 'pending', index: true },
    paymentRef: { type: String, trim: true },
    processedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    processedAt: { type: Date },
    metadata: { type: Schema.Types.Mixed },
  },
  { timestamps: true },
);

WalletWithdrawalRequestSchema.index({ userId: 1, status: 1, createdAt: -1 });

export default mongoose.model('WalletWithdrawalRequest', WalletWithdrawalRequestSchema);

