import mongoose from 'mongoose';
const attachment=new mongoose.Schema({url:String,publicId:String,mimeType:String,size:Number,originalName:String},{_id:false});
const envelope=new mongoose.Schema({recipientDeviceId:{type:String,required:true},oneTimePreKeyId:{type:String,default:null},ephemeralPublicKey:{type:String,required:true},salt:{type:String,required:true},keyNonce:{type:String,required:true},encryptedKey:{type:String,required:true}},{_id:false});
const encryptedPayload=new mongoose.Schema({version:{type:Number,enum:[1],required:true},algorithm:{type:String,enum:['ECDH-P256-HKDF-SHA256-AES256GCM'],required:true},nonce:{type:String,required:true},ciphertext:{type:String,required:true},senderDeviceId:{type:String,required:true},recipientEnvelopes:{type:[envelope],required:true}},{_id:false});
const schema=new mongoose.Schema({
 conversation:{type:mongoose.Schema.Types.ObjectId,ref:'Conversation',required:true,index:true},sender:{type:mongoose.Schema.Types.ObjectId,ref:'User',required:true},
 encryptedPayload:{type:encryptedPayload,default:null},text:{type:String,select:false,default:''},attachments:[attachment],replyTo:{type:mongoose.Schema.Types.ObjectId,ref:'Message',default:null},
 forwardedFrom:{type:mongoose.Schema.Types.ObjectId,ref:'Message',default:null},editedAt:Date,deletedFor:[{type:mongoose.Schema.Types.ObjectId,ref:'User'}],
 deletedForEveryone:{type:Boolean,default:false},reactions:[{user:{type:mongoose.Schema.Types.ObjectId,ref:'User'},emoji:{type:String,maxlength:32}}],
 pinnedBy:[{type:mongoose.Schema.Types.ObjectId,ref:'User'}],deliveredTo:[{type:mongoose.Schema.Types.ObjectId,ref:'User'}],readBy:[{type:mongoose.Schema.Types.ObjectId,ref:'User'}],
 expiresAt:{type:Date,index:{expireAfterSeconds:0}}
},{timestamps:true});
schema.index({conversation:1,createdAt:-1});
export default mongoose.model('Message',schema);
