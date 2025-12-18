import mongoose from 'mongoose';
import { normalizeSegmentKey } from './SegmentMessage.js';

const NotificationTokenSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
    token: { type: String, required: true, unique: true, index: true },
    platform: {
      type: String,
      enum: ['android', 'ios', 'web', 'unknown'],
      default: 'unknown',
      index: true,
    },
    deviceId: { type: String },
    appId: { type: String },
    appVersion: { type: String },
    deviceModel: { type: String },
    osVersion: { type: String },
    segments: { type: [String], default: [], index: true },
    lastActiveAt: { type: Date, index: true },
    lastSeenAt: { type: Date, default: Date.now, index: true },
    lastNotificationAt: { type: Date },
    disabled: { type: Boolean, default: false, index: true },
  },
  { timestamps: true }
);

NotificationTokenSchema.index({ userId: 1, deviceId: 1 });

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
