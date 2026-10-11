import mongoose from 'mongoose';
const schema=new mongoose.Schema({reporter:{type:mongoose.Schema.Types.ObjectId,ref:'User',required:true},target:{type:mongoose.Schema.Types.ObjectId,ref:'User',required:true},reason:{type:String,required:true,maxlength:1000},status:{type:String,enum:['open','reviewing','resolved','dismissed'],default:'open'},reviewedBy:{type:mongoose.Schema.Types.ObjectId,ref:'User'}},{timestamps:true});
schema.index({reporter:1,target:1,createdAt:-1});export default mongoose.model('Report',schema);
