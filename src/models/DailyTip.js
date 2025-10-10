import mongoose from 'mongoose';

const DailyTipSchema = new mongoose.Schema(
  {
    message: { type: String, required: true, trim: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    publishedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

DailyTipSchema.index({ publishedAt: -1, createdAt: -1 });

export default mongoose.model('DailyTip', DailyTipSchema);
