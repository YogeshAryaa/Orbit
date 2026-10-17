import mongoose from 'mongoose';

const preKeySchema = new mongoose.Schema({
  keyId: { type: String, required: true },
  publicKey: { type: String, required: true }
}, { _id: false });

const tabSchema = new mongoose.Schema({
  tabId: { type: String, required: true },
  title: { type: String, default: 'Browser Tab' },
  lastActiveAt: { type: Date, default: Date.now },
  status: { type: String, enum: ['active', 'restricted', 'closed'], default: 'active' }
}, { _id: false });

const schema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  deviceId: { type: String, required: true },
  identityPublicKey: { type: String, required: true },
  signedPreKeyPublic: { type: String, required: true },
  signedPreKeySignature: { type: String, required: true },
  oneTimePreKeys: { type: [preKeySchema], default: [] },
  lastSeenAt: { type: Date, default: Date.now },

  // Device & session metadata
  deviceName: { type: String, default: 'Web Browser' },
  os: { type: String, default: 'Unknown OS' },
  browser: { type: String, default: 'Browser' },
  deviceType: { type: String, default: 'browser' },
  ipAddress: { type: String, default: '' },
  userAgent: { type: String, default: '' },
  sessionId: { type: String, default: '' },

  // Permissions
  historyAllowed: { type: Boolean, default: true },
  newMessagesAllowed: { type: Boolean, default: true },
  status: {
    type: String,
    enum: ['authorized', 'history_blocked', 'fully_blocked', 'revoked'],
    default: 'authorized'
  },
  historyAllowedAt: { type: Date, default: null },

  // Active browser tabs tracked on this device
  tabs: { type: [tabSchema], default: [] }
}, { timestamps: true });

schema.index({ user: 1, deviceId: 1 }, { unique: true });

export default mongoose.model('DeviceKey', schema);
