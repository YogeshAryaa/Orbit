import mongoose from 'mongoose';
const preKeySchema = new mongoose.Schema({ keyId: {type:String,required:true}, publicKey: {type:String,required:true} }, {_id:false});
const schema = new mongoose.Schema({
 user: {type:mongoose.Schema.Types.ObjectId,ref:'User',required:true,index:true},
 deviceId: {type:String,required:true},
 identityPublicKey: {type:String,required:true},
 signedPreKeyPublic: {type:String,required:true},
 signedPreKeySignature: {type:String,required:true},
 oneTimePreKeys: {type:[preKeySchema],default:[]},
 lastSeenAt: {type:Date,default:Date.now}
},{timestamps:true});
schema.index({user:1,deviceId:1},{unique:true});
export default mongoose.model('DeviceKey',schema);
