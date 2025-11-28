import mongoose from 'mongoose';
import { normalizeSegmentKey } from './SegmentMessage.js';

const NotificationTokenSchema = new mongoose.Schema(
  {
    token: { type: String, required: true, unique: true, index: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
    platform: {
      type: String,
      enum: ['android', 'ios', 'web', 'unknown'],
      default: 'unknown',
      index: true,
    },
    deviceId: { type: String },
    appVersion: { type: String },
    segments: { type: [String], default: [], index: true },
    lastSeenAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

NotificationTokenSchema.pre('save', function dedupeSegments(next) {
  if (Array.isArray(this.segments) && this.segments.length) {
    const normalized = this.segments
      .map((value) => normalizeSegmentKey(value))
      .filter(Boolean);
    this.segments = Array.from(new Set(normalized));
  }
  next();
});

export default mongoose.model('NotificationToken', NotificationTokenSchema);
