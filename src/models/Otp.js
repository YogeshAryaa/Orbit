import mongoose from 'mongoose';
const schema=new mongoose.Schema({email:{type:String,required:true,index:true},purpose:{type:String,enum:['verify','reset'],required:true},codeHash:{type:String,required:true},expiresAt:{type:Date,required:true,index:{expireAfterSeconds:0}},attempts:{type:Number,default:0},used:{type:Boolean,default:false}},{timestamps:true});
export default mongoose.model('Otp',schema);
