import mongoose from 'mongoose';

const NotificationTokenSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    token: { type: String, required: true, unique: true },
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
    lastActiveAt: { type: Date, index: true },
    lastNotificationAt: { type: Date },
    disabled: { type: Boolean, default: false, index: true },
  },
  {
    timestamps: true,
  },
);

NotificationTokenSchema.index({ userId: 1, deviceId: 1 });

export default mongoose.model('NotificationToken', NotificationTokenSchema);
