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
