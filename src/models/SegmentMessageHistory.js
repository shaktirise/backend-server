import mongoose from 'mongoose';

const SegmentMessageHistorySchema = new mongoose.Schema(
  {
    segment: { type: String, required: true, index: true },
    message: { type: String, required: true, trim: true, maxlength: 1000 },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  },
  { timestamps: true }
);

SegmentMessageHistorySchema.index({ segment: 1, createdAt: -1 });

export default mongoose.model('SegmentMessageHistory', SegmentMessageHistorySchema);
