import mongoose from 'mongoose';

// Stores verified Aadhaar KYC details for a user.
// Only non-sensitive details are persisted (last 4 digits of Aadhaar).
const AadhaarKycSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true, index: true },
    name: { type: String },
    dob: { type: Date },
    gender: { type: String },
    // Address can be a structured object returned by provider or a single string
    address: { type: mongoose.Schema.Types.Mixed },
    aadhaarLast4: { type: String },
    verified: { type: Boolean, default: false, index: true },
    providerTxnId: { type: String },
    verificationDate: { type: Date },
  },
  { timestamps: true }
);

export default mongoose.model('AadhaarKyc', AadhaarKycSchema);

