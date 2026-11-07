import mongoose from 'mongoose';

const schema = new mongoose.Schema({
  conversation: { type: mongoose.Schema.Types.ObjectId, ref: 'Conversation', required: true, index: true },
  uploader: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  storage: { type: String, enum: ['local', 'cloudinary'], required: true },
  storageKey: { type: String, required: true },
  size: { type: Number, required: true },
  mimeType: { type: String, required: true, default: 'application/octet-stream' },
  originalName: { type: String, required: true, default: 'encrypted.bin' },
  encrypted: { type: Boolean, required: true, default: true }
}, { timestamps: true });

export default mongoose.model('ProtectedUpload', schema);
