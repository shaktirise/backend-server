import mongoose from 'mongoose';

const { Schema } = mongoose;

const ReferralClosureSchema = new Schema(
  {
    ancestorId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    descendantId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    depth: { type: Number, required: true, min: 0, index: true },
  },
  { timestamps: true }
);

ReferralClosureSchema.index({ ancestorId: 1, descendantId: 1 }, { unique: true });
ReferralClosureSchema.index({ ancestorId: 1, depth: 1 });
ReferralClosureSchema.index({ descendantId: 1, depth: 1 });
ReferralClosureSchema.index({ depth: 1 });

export default mongoose.model('ReferralClosure', ReferralClosureSchema);
