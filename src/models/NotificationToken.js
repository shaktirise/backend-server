import mongoose from 'mongoose';
<<<<<<< HEAD

const NotificationTokenSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    token: { type: String, required: true, unique: true },
=======
import { normalizeSegmentKey } from './SegmentMessage.js';

const NotificationTokenSchema = new mongoose.Schema(
  {
    token: { type: String, required: true, unique: true, index: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
>>>>>>> 67feb5c4e79bd31cb0e9bdce43e5f03b920a6d8a
    platform: {
      type: String,
      enum: ['android', 'ios', 'web', 'unknown'],
      default: 'unknown',
      index: true,
    },
    deviceId: { type: String },
<<<<<<< HEAD
    appId: { type: String },
    appVersion: { type: String },
    deviceModel: { type: String },
    osVersion: { type: String },
    lastActiveAt: { type: Date, index: true },
    lastNotificationAt: { type: Date },
    disabled: { type: Boolean, default: false, index: true },
  },
  {
    timestamps: true,
  },
);

NotificationTokenSchema.index({ userId: 1, deviceId: 1 });
=======
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
>>>>>>> 67feb5c4e79bd31cb0e9bdce43e5f03b920a6d8a

export default mongoose.model('NotificationToken', NotificationTokenSchema);
