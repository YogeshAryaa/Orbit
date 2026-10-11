import mongoose from 'mongoose';
const schema=new mongoose.Schema({
 publicId:{type:String,unique:true,index:true},username:{type:String,required:true,unique:true,lowercase:true,trim:true},
 displayName:{type:String,required:true,trim:true,maxlength:60},email:{type:String,lowercase:true,sparse:true,unique:true},
 phone:{type:String,sparse:true,unique:true},passwordHash:{type:String,required:true,select:false},bio:{type:String,default:'',maxlength:300},
 avatarUrl:{type:String,default:''},statusMessage:{type:String,default:'',maxlength:140},discoverableByPhone:{type:Boolean,default:false},
 emailVerified:{type:Boolean,default:false},blockedUsers:[{type:mongoose.Schema.Types.ObjectId,ref:'User'}],
 privacy:{lastSeen:{type:String,enum:['everyone','contacts','nobody'],default:'everyone'},profilePhoto:{type:String,enum:['everyone','contacts','nobody'],default:'everyone'},readReceipts:{type:Boolean,default:true}},
 pushSubscriptions:[{endpoint:String,keys:{p256dh:String,auth:String}}],status:{type:String,enum:['active','deleted'],default:'active'},lastSeenAt:Date
},{timestamps:true});
export default mongoose.model('User',schema);
