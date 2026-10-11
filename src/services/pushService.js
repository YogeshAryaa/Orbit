import {pushEnabled,webpush} from '../config/push.js';
import User from '../models/User.js';
export async function notifyUser(userId,payload){if(!pushEnabled)return {sent:0,configured:false};const user=await User.findById(userId).select('pushSubscriptions');let sent=0;for(const sub of user?.pushSubscriptions||[]){try{await webpush.sendNotification(sub,JSON.stringify(payload));sent++;}catch(e){if(e.statusCode===404||e.statusCode===410)await User.updateOne({_id:userId},{$pull:{pushSubscriptions:{endpoint:sub.endpoint}}});}}return {sent,configured:true};}
