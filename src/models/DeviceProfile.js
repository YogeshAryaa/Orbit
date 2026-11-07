import mongoose from 'mongoose';

const schema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  name: { type: String, required: true, trim: true, maxlength: 60 },
  allowedConversations: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Conversation' }],
  allowedGroups: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Conversation' }]
}, { timestamps: true });

schema.index({ user: 1, name: 1 }, { unique: true });

export default mongoose.model('DeviceProfile', schema);
