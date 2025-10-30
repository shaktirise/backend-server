import mongoose from 'mongoose';

const { Schema } = mongoose;

const ActivationEventSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    sourceUserId: { type: Schema.Types.ObjectId, ref: 'User', index: true },
    sourceLedgerId: { type: Schema.Types.ObjectId, ref: 'WalletLedger' },
    type: {
      type: String,
      enum: ['TOPUP', 'REFERRAL', 'MANUAL'],
      default: 'TOPUP',
      index: true,
    },
    status: {
      type: String,
      enum: ['PENDING', 'SUCCEEDED', 'FAILED', 'REVERSED'],
      default: 'PENDING',
      index: true,
    },
    amountPaise: { type: Number, default: 0 },
    occurredAt: { type: Date, default: () => new Date(), index: true },
    metadata: { type: Schema.Types.Mixed },
  },
  { timestamps: true }
);

ActivationEventSchema.index({ userId: 1, status: 1, occurredAt: -1 });
ActivationEventSchema.index({ userId: 1, occurredAt: -1 });
ActivationEventSchema.index({ occurredAt: -1 });
ActivationEventSchema.index({ sourceLedgerId: 1 }, { unique: true, sparse: true });

export default mongoose.model('ActivationEvent', ActivationEventSchema);
