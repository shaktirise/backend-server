import mongoose from 'mongoose';

const { Schema } = mongoose;

const ReferralLedgerSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    sourceUserId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    level: { type: Number, required: true },
    amountPaise: { type: Number, required: true },
    note: { type: String },
    status: {
      type: String,
      enum: ['pending', 'paid', 'cancelled'],
      default: 'pending',
      index: true,
    },
    topupLedgerId: { type: Schema.Types.ObjectId, ref: 'WalletLedger' },
    topupExtRef: { type: String },
  },
  { timestamps: true },
);

ReferralLedgerSchema.index({ userId: 1, status: 1, createdAt: -1 });
ReferralLedgerSchema.index({ topupExtRef: 1, level: 1, userId: 1 }, { unique: true, sparse: true });

export default mongoose.model('ReferralLedger', ReferralLedgerSchema);

