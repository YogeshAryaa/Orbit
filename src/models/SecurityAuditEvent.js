import mongoose from 'mongoose';

const schema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  actorDeviceId: { type: String, default: '' },
  action: { type: String, required: true, maxlength: 80 },
  targetType: { type: String, default: '', maxlength: 40 },
  targetId: { type: String, default: '', maxlength: 100 },
  details: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { timestamps: true });

schema.index({ user: 1, createdAt: -1 });

export default mongoose.model('SecurityAuditEvent', schema);
