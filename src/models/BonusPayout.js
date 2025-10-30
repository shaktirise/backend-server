import mongoose from 'mongoose';

const { Schema } = mongoose;

const BonusPayoutSchema = new Schema(
  {
    uplineUserId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    downlineUserId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    activationEventId: { type: Schema.Types.ObjectId, ref: 'ActivationEvent', index: true },
    walletLedgerId: { type: Schema.Types.ObjectId, ref: 'WalletLedger', index: true },
    reversalLedgerId: { type: Schema.Types.ObjectId, ref: 'WalletLedger', index: true },
    level: { type: Number, required: true, min: 1, max: 50 },
    amountPaise: { type: Number, required: true },
    status: {
      type: String,
      enum: ['PENDING', 'RELEASED', 'REVERSED'],
      default: 'PENDING',
      index: true,
    },
    note: { type: String },
    createdForRange: {
      from: { type: Date },
      to: { type: Date },
    },
    processedAt: { type: Date },
    processedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    metadata: { type: Schema.Types.Mixed },
  },
  { timestamps: true }
);

BonusPayoutSchema.index({ uplineUserId: 1, level: 1, status: 1, createdAt: -1 });
BonusPayoutSchema.index({ uplineUserId: 1, createdAt: -1 });
BonusPayoutSchema.index({ status: 1, createdAt: -1 });
BonusPayoutSchema.index({ downlineUserId: 1, status: 1 });
BonusPayoutSchema.index(
  { activationEventId: 1, uplineUserId: 1, level: 1 },
  { unique: true, sparse: true }
);
BonusPayoutSchema.index({ walletLedgerId: 1 }, { unique: true, sparse: true });
BonusPayoutSchema.index({ reversalLedgerId: 1 }, { unique: true, sparse: true });

export default mongoose.model('BonusPayout', BonusPayoutSchema);
