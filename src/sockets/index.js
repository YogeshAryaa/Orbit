import jwt from 'jsonwebtoken';import {env} from '../config/env.js';import User from '../models/User.js';import Conversation from '../models/Conversation.js';import DeviceKey from '../models/DeviceKey.js';import Message from '../models/Message.js';import {isSessionActive} from '../services/tokenService.js';import {notifyUser} from '../services/pushService.js';import {conversationAccess,emitToAuthorizedConversation,emitToAuthorizedUser} from '../services/accessPolicy.js';
export function configureSockets(io){
 io.use(async(s,next)=>{try{const token=s.handshake.auth?.token;if(!token)return next(new Error('unauthorized'));const p=jwt.verify(token,env.JWT_SECRET);if(!await isSessionActive(p.sid,p.sub))return next(new Error('unauthorized'));const u=await User.findById(p.sub).select('_id status');if(!u||u.status!=='active')return next(new Error('unauthorized'));const deviceId=s.handshake.auth?.deviceId||s.handshake.headers?.['x-device-id'];if(!deviceId||deviceId!==p.deviceId)return next(new Error('device_required'));const dev=await DeviceKey.findOne({user:u.id,deviceId,sessionId:p.sid,status:'authorized',linkStatus:'approved'});if(!dev)return next(new Error('device_not_authorized'));s.deviceId=deviceId;s.tabId=s.handshake.auth?.tabId||s.handshake.headers?.['x-tab-id']||'tab_default';s.userId=u.id;s.sessionId=p.sid;s.data.sessionId=p.sid;next();}catch{next(new Error('unauthorized'));}});
 io.on('connection',s=>{const uid=s.userId;s.join(`user:${uid}`);
  // Handlers below must be attached synchronously; awaiting DB calls first made the server drop early client events (e.g. conversation:join right after connect).
  (async()=>{try{await User.updateOne({_id:uid},{$set:{lastSeenAt:new Date()}});const uDoc=await User.findById(uid).select('privacy');if(uDoc?.privacy?.lastSeen!=='nobody')io.emit('presence:online',{userId:uid});}catch(e){console.error(JSON.stringify({level:'error',event:'presence_online_failed',message:e.message}));}})();
  s.on('conversation:join',async(p,ack=()=>{})=>{try{const c=await Conversation.findOne({_id:p?.conversationId,members:uid});if(!c)return ack({success:false,message:'Conversation not found'});if(!(await conversationAccess(c,uid,await DeviceKey.findOne({user:uid,deviceId:s.deviceId,sessionId:s.sessionId}), 'new')).allowed)return ack({success:false,locked:true,message:'Conversation content is locked on this device'});s.join(c.id);ack({success:true,data:{conversationId:c.id}});}catch{ack({success:false,message:'Invalid conversation'});}});
  for(const event of ['typing:start','typing:stop'])s.on(event,async(p,ack=()=>{})=>{try{const c=await Conversation.findOne({_id:p?.conversationId,members:uid});if(!c)return ack({success:false,message:'Conversation not found'});const d=await DeviceKey.findOne({user:uid,deviceId:s.deviceId,sessionId:s.sessionId});if(!(await conversationAccess(c,uid,d,'new')).allowed)return ack({success:false,locked:true});await emitToAuthorizedConversation(io,c,'typing:update',{conversationId:c.id,userId:uid,typing:event.endsWith('start')});ack({success:true});}catch{ack({success:false,message:'Invalid request'});}});
  s.on('message:delivered',async(p,ack=()=>{})=>{try{const c=await Conversation.findOne({_id:p?.conversationId,members:uid});if(!c)return ack({success:false,message:'Conversation not found'});const d=await DeviceKey.findOne({user:uid,deviceId:s.deviceId,sessionId:s.sessionId});if(!(await conversationAccess(c,uid,d,'new')).allowed)return ack({success:false,locked:true});await Message.updateMany({_id:{$in:p.messageIds||[]},conversation:c._id},{$addToSet:{deliveredTo:uid}});await emitToAuthorizedConversation(io,c,'receipt:delivered',{conversationId:c.id,userId:uid,messageIds:p.messageIds||[]});ack({success:true});}catch{ack({success:false,message:'Invalid request'});}});
  s.on('call:signal',async(p,ack=()=>{})=>{try{
   const c=await Conversation.findOne({_id:p?.conversationId,members:uid}).select('_id type members title');
   if(!c)return ack({success:false,message:'Conversation not found'});
   const callerDevice=await DeviceKey.findOne({user:uid,deviceId:s.deviceId,sessionId:s.sessionId});
   if(!(await conversationAccess(c,uid,callerDevice,'new')).allowed)return ack({success:false,locked:true,message:'Conversation content is locked on this device'});
   if(!p.signal||typeof p.signal.type!=='string')return ack({success:false,message:'Invalid signal type'});
   const caller=await User.findById(uid).select('_id username displayName avatarUrl');
   const callerPayload={id:caller?._id,username:caller?.username,displayName:caller?.displayName,avatarUrl:caller?.avatarUrl};
   if(c.type==='direct'){
    if(!['offer','answer','ice-candidate','reject','busy','end'].includes(p.signal.type))return ack({success:false,message:'Invalid signal type'});
    const other=c.members.find(x=>String(x)!==String(uid));
    const blocked=await User.exists({_id:other,blockedUsers:uid});
    if(blocked)return ack({success:false,message:'Call not allowed due to privacy settings'});
    await emitToAuthorizedUser(io,other,c,'call:signal',{conversationId:c.id,from:uid,caller:callerPayload,signal:p.signal});
    if(p.signal.type==='offer'){
     notifyUser(other,{
      title:`📞 Incoming ${p.signal.kind==='video'?'Video':'Voice'} Call`,
      body:`${caller?.displayName||caller?.username||'Someone'} is calling you on Orbit`,
      type:'call',
      callKind:p.signal.kind||'audio',
      callerName:caller?.displayName||caller?.username,
      callerAvatar:caller?.avatarUrl,
      conversationId:c.id,
      url:`/chat?open=${c.id}&call=incoming`
     }).catch(()=>{});
    }
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
   for(const member of recipients){
    await emitToAuthorizedUser(io,member,c,'call:signal',{conversationId:c.id,from:uid,caller:callerPayload,conversationTitle:c.title,signal:p.signal});
   }
   if(p.signal.type==='invite'){
    for(const member of recipients){
     notifyUser(member,{
      title:`📞 Group ${p.signal.kind==='video'?'Video':'Voice'} Call`,
      body:`${caller?.displayName||caller?.username||'Someone'} started a group call in ${c.title||'Group'}`,
      type:'call',
      callKind:p.signal.kind||'audio',
      callerName:caller?.displayName||caller?.username,
      conversationId:c.id,
      url:`/chat?open=${c.id}&call=incoming`
     }).catch(()=>{});
    }
   }
   ack({success:true});
  }catch{ack({success:false,message:'Invalid request'});}});
  s.on('disconnect',async()=>{try{const sockets=await io.in(`user:${uid}`).fetchSockets();if(!sockets.length){const lastSeenAt=new Date();await User.updateOne({_id:uid},{$set:{lastSeenAt}});const uDoc=await User.findById(uid).select('privacy');if(uDoc?.privacy?.lastSeen!=='nobody')io.emit('presence:offline',{userId:uid,lastSeenAt:lastSeenAt.toISOString()});}}catch(e){console.error(JSON.stringify({level:'error',event:'presence_offline_failed',message:e.message}));}});
 });
}
