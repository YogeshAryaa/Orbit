import mongoose from 'mongoose';
const schema=new mongoose.Schema({
 user:{type:mongoose.Schema.Types.ObjectId,ref:'User',required:true,index:true},
 text:{type:String,required:true,maxlength:500},
 backgroundColor:{type:String,default:'#6C5CE7'},
 fontStyle:{type:String,enum:['normal','bold','italic'],default:'normal'},
 viewedBy:[{type:mongoose.Schema.Types.ObjectId,ref:'User'}],
 expiresAt:{type:Date,index:{expireAfterSeconds:0},default:()=>new Date(Date.now()+24*60*60*1000)}
},{timestamps:true});
schema.pre('save',function(next){if(!this.expiresAt)this.expiresAt=new Date(Date.now()+24*60*60*1000);next();});
export default mongoose.model('Status',schema);
