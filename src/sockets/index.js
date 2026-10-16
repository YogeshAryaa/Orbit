import jwt from 'jsonwebtoken';import {env} from '../config/env.js';import User from '../models/User.js';import Conversation from '../models/Conversation.js';import {isSessionActive} from '../services/tokenService.js';
export function configureSockets(io){
 io.use(async(s,next)=>{try{const token=s.handshake.auth?.token;if(!token)return next(new Error('unauthorized'));const p=jwt.verify(token,env.JWT_SECRET);if(!await isSessionActive(p.sid,p.sub))return next(new Error('unauthorized'));const u=await User.findById(p.sub).select('_id status');if(!u||u.status!=='active')return next(new Error('unauthorized'));s.userId=u.id;s.sessionId=p.sid;s.data.sessionId=p.sid;next();}catch{next(new Error('unauthorized'));}});
 io.on('connection',async s=>{const uid=s.userId;s.join(`user:${uid}`);await User.updateOne({_id:uid},{$set:{lastSeenAt:new Date()}});const uDoc=await User.findById(uid).select('privacy');if(uDoc?.privacy?.lastSeen!=='nobody')io.emit('presence:online',{userId:uid});
  s.on('conversation:join',async(p,ack=()=>{})=>{try{const c=await Conversation.findOne({_id:p?.conversationId,members:uid}).select('_id');if(!c)return ack({success:false,message:'Conversation not found'});s.join(c.id);ack({success:true,data:{conversationId:c.id}});}catch{ack({success:false,message:'Invalid conversation'});}});
  for(const event of ['typing:start','typing:stop'])s.on(event,async(p,ack=()=>{})=>{try{const c=await Conversation.findOne({_id:p?.conversationId,members:uid}).select('_id');if(!c)return ack({success:false,message:'Conversation not found'});s.to(c.id).emit('typing:update',{conversationId:c.id,userId:uid,typing:event.endsWith('start')});ack({success:true});}catch{ack({success:false,message:'Invalid request'});}});
  s.on('message:delivered',async(p,ack=()=>{})=>{try{const c=await Conversation.findOne({_id:p?.conversationId,members:uid}).select('_id');if(!c)return ack({success:false,message:'Conversation not found'});const m=await import('../models/Message.js');await m.default.updateMany({_id:{$in:p.messageIds||[]},conversation:c._id},{$addToSet:{deliveredTo:uid}});io.to(c.id).emit('receipt:delivered',{conversationId:c.id,userId:uid,messageIds:p.messageIds||[]});ack({success:true});}catch{ack({success:false,message:'Invalid request'});}});
  s.on('call:signal',async(p,ack=()=>{})=>{try{
   const c=await Conversation.findOne({_id:p?.conversationId,members:uid}).select('_id type members');
   if(!c)return ack({success:false,message:'Conversation not found'});
   if(!p.signal||typeof p.signal.type!=='string')return ack({success:false,message:'Invalid signal type'});
   if(c.type==='direct'){
    if(!['offer','answer','ice-candidate','reject','busy','end'].includes(p.signal.type))return ack({success:false,message:'Invalid signal type'});
    const other=c.members.find(x=>String(x)!==String(uid));
    const blocked=await User.exists({_id:other,blockedUsers:uid});
    if(blocked)return ack({success:false,message:'Call not allowed due to privacy settings'});
    io.to(`user:${other}`).emit('call:signal',{conversationId:c.id,from:uid,signal:p.signal});
    return ack({success:true});
   }
   const groupSignalTypes=['invite','join','offer','answer','ice-candidate','reject','busy','leave'];
   if(!groupSignalTypes.includes(p.signal.type)||typeof p.signal.callId!=='string'||!p.signal.callId||p.signal.callId.length>128)return ack({success:false,message:'Invalid group call signal'});
   const members=c.members.filter(member=>String(member)!==String(uid));
   let recipients=members;
   if(p.toUserId!==undefined){
    if(typeof p.toUserId!=='string'||!members.some(member=>String(member)===p.toUserId))return ack({success:false,message:'Invalid group call recipient'});
    recipients=members.filter(member=>String(member)===p.toUserId);
   }
   const sender=await User.findById(uid).select('blockedUsers');
   const blockedRecipients=new Set((await User.find({_id:{$in:recipients},blockedUsers:uid}).select('_id')).map(user=>String(user._id)));
   recipients=recipients.filter(member=>!sender?.blockedUsers?.some(blocked=>String(blocked)===String(member))&&!blockedRecipients.has(String(member)));
   if(p.toUserId!==undefined&&!recipients.length)return ack({success:false,message:'Call not allowed due to privacy settings'});
   for(const member of recipients)io.to(`user:${member}`).emit('call:signal',{conversationId:c.id,from:uid,signal:p.signal});
   ack({success:true});
  }catch{ack({success:false,message:'Invalid request'});}});
  s.on('disconnect',async()=>{const sockets=await io.in(`user:${uid}`).fetchSockets();if(!sockets.length){const lastSeenAt=new Date();await User.updateOne({_id:uid},{$set:{lastSeenAt}});const uDoc=await User.findById(uid).select('privacy');if(uDoc?.privacy?.lastSeen!=='nobody')io.emit('presence:offline',{userId:uid,lastSeenAt:lastSeenAt.toISOString()});}});
 });
}
