import mongoose from 'mongoose';

const { Schema } = mongoose;

const WalletSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, unique: true, index: true },
    // Balance in paise (integer only)
    balance: { type: Number, default: 0 },
  },
  { timestamps: true }
);

export default mongoose.model('Wallet', WalletSchema);

