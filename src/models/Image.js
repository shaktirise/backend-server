import mongoose from 'mongoose';

const ImageSchema = new mongoose.Schema(
  {
    publicId: { type: String, index: true, required: true },
    url: { type: String },
    secureUrl: { type: String, required: true },
    width: { type: Number },
    height: { type: Number },
    format: { type: String },
    bytes: { type: Number },
    folder: { type: String },
    tags: [{ type: String }],
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  },
  { 
    timestamps: true 
  }
);

export default mongoose.model('Image', ImageSchema);

