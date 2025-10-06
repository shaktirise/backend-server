import mongoose from 'mongoose';

const UserSchema = new mongoose.Schema(
  {
    phone: { type: String, unique: true, sparse: true, index: true },
    email: { type: String, unique: true, sparse: true, index: true },
    passwordHash: { type: String },

    role: { type: String, enum: ['user', 'admin'], default: 'user', index: true },
    walletBalance: { type: Number, default: 1000 },

    otpHash: { type: String },
    otpExpiresAt: { type: Date },

    name: { type: String },

    referralCode: { type: String, unique: true, sparse: true, index: true },
    pendingReferredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
    referralActivatedAt: { type: Date },
    referralCount: { type: Number, default: 0 },

    pinHash: { type: String },
    pinSetAt: { type: Date },

    lastLoginAt: { type: Date },
    loginCount: { type: Number, default: 0 },
    lastLoginIp: { type: String },
    lastOtpAt: { type: Date },
    lastOtpIp: { type: String },

    refreshTokenHash: { type: String },
    refreshTokenExpiresAt: { type: Date },
  },
  { 
    timestamps: true
  }
);

export default mongoose.model('User', UserSchema);
