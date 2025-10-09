import mongoose from 'mongoose';

const { Schema } = mongoose;

const ReferralWithdrawalRequestSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    amountPaise: { type: Number, required: true },
    status: {
      type: String,
      enum: ['pending', 'paid', 'cancelled'],
      default: 'pending',
      index: true,
    },
    ledgerEntryIds: [{ type: Schema.Types.ObjectId, ref: 'ReferralLedger' }],
    note: { type: String },
    adminNote: { type: String },
    processedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    processedAt: { type: Date },
  },
  { timestamps: true },
);

ReferralWithdrawalRequestSchema.index({ status: 1, createdAt: -1 });

export default mongoose.model('ReferralWithdrawalRequest', ReferralWithdrawalRequestSchema);

