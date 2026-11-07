import mongoose from 'mongoose';
const schema=new mongoose.Schema({
 type:{type:String,enum:['direct','group'],required:true},title:{type:String,maxlength:100,default:''},
 description:{type:String,maxlength:500,default:''},avatarUrl:{type:String,default:''},
 onlyAdminsCanSend:{type:Boolean,default:false},
 members:[{type:mongoose.Schema.Types.ObjectId,ref:'User',required:true}],admins:[{type:mongoose.Schema.Types.ObjectId,ref:'User'}],
 createdBy:{type:mongoose.Schema.Types.ObjectId,ref:'User',required:true},archivedBy:[{type:mongoose.Schema.Types.ObjectId,ref:'User'}],
 pinnedBy:[{type:mongoose.Schema.Types.ObjectId,ref:'User'}],disappearingAfterSeconds:{type:Number,min:0,default:0},
 groupAccessMode:{type:String,enum:['full_decryption','header_only'],default:'full_decryption'},
 memberAccessPolicies:[{
  user:{type:mongoose.Schema.Types.ObjectId,ref:'User',required:true},
  mode:{type:String,enum:['all_authorized','mobile_only','selected_devices','master_authorization'],default:'all_authorized'},
  selectedDeviceIds:{type:[String],default:[]}
 }],
 lastMessageAt:{type:Date,default:Date.now},memberSettings:[{user:{type:mongoose.Schema.Types.ObjectId,ref:'User'},muted:{type:Boolean,default:false}}]
},{timestamps:true});
schema.index({members:1,lastMessageAt:-1});
export default mongoose.model('Conversation',schema);
