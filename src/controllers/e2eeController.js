import DeviceKey from '../models/DeviceKey.js';
import Conversation from '../models/Conversation.js';
import { ApiError } from '../utils/ApiError.js';
import { ok } from '../utils/respond.js';
import { assertObjectId } from '../utils/ids.js';

const clean = (d, includePrekeys=true) => ({ userId:String(d.user), deviceId:d.deviceId, identityPublicKey:d.identityPublicKey, signedPreKeyPublic:d.signedPreKeyPublic, signedPreKeySignature:d.signedPreKeySignature, ...(includePrekeys ? {oneTimePreKeyCount:d.oneTimePreKeys.length} : {}) });
export async function registerDeviceKeys(req,res) {
 const b=req.body||{};
 if(typeof b.deviceId!=='string'||b.deviceId.length<1||b.deviceId.length>100) throw new ApiError(400,'deviceId is required (1-100 characters)');
 for (const k of ['identityPublicKey','signedPreKeyPublic','signedPreKeySignature']) if(typeof b[k]!=='string'||b[k].length<20||b[k].length>4096) throw new ApiError(400,`${k} is invalid`);
 if(!Array.isArray(b.oneTimePreKeys)||b.oneTimePreKeys.length>500) throw new ApiError(400,'oneTimePreKeys must be an array with at most 500 entries');
 const seen=new Set();
 for(const p of b.oneTimePreKeys){if(!p||typeof p.keyId!=='string'||p.keyId.length>100||typeof p.publicKey!=='string'||p.publicKey.length<20||p.publicKey.length>4096||seen.has(p.keyId))throw new ApiError(400,'Invalid or duplicate one-time prekey');seen.add(p.keyId);}
 const doc=await DeviceKey.findOneAndUpdate({user:req.user.id,deviceId:b.deviceId},{$set:{identityPublicKey:b.identityPublicKey,signedPreKeyPublic:b.signedPreKeyPublic,signedPreKeySignature:b.signedPreKeySignature,oneTimePreKeys:b.oneTimePreKeys,lastSeenAt:new Date()}},{upsert:true,new:true,runValidators:true});
 ok(res,clean(doc),'Public device keys registered');
}
export async function listMyDevices(req,res){const ds=await DeviceKey.find({user:req.user.id}).select('deviceId identityPublicKey signedPreKeyPublic signedPreKeySignature oneTimePreKeys.length lastSeenAt');ok(res,ds.map(d=>clean(d)),'Your registered devices');}
export async function deleteMyDevice(req,res){const deviceId=String(req.params.deviceId||'');const result=await DeviceKey.deleteOne({user:req.user.id,deviceId});if(!result.deletedCount)throw new ApiError(404,'Device not found');ok(res,null,'Device keys deleted');}
export async function getUserKeyBundles(req,res){assertObjectId(req.params.userId,'user ID');const other=String(req.params.userId);if(other!==String(req.user.id)){const mutual=await Conversation.exists({members:{$all:[req.user.id,other]}});if(!mutual)throw new ApiError(404,'User or shared conversation not found');}
 const devices=await DeviceKey.find({user:other}).select('+oneTimePreKeys');if(!devices.length)throw new ApiError(404,'No encryption keys registered for this user');
 const bundles=[];
 for(const d of devices){let preKey=null;if(d.oneTimePreKeys.length){preKey=d.oneTimePreKeys[0];const pulled=await DeviceKey.findOneAndUpdate({_id:d._id,'oneTimePreKeys.keyId':preKey.keyId},{$pull:{oneTimePreKeys:{keyId:preKey.keyId}}},{new:false});if(!pulled)preKey=null;}
  bundles.push({userId:other,deviceId:d.deviceId,identityPublicKey:d.identityPublicKey,signedPreKeyPublic:d.signedPreKeyPublic,signedPreKeySignature:d.signedPreKeySignature,oneTimePreKey:preKey});}
 ok(res,bundles,'Encryption key bundles');
}
export async function replenishOneTimePreKeys(req,res){const b=req.body||{};if(!Array.isArray(b.oneTimePreKeys)||b.oneTimePreKeys.length<1||b.oneTimePreKeys.length>500)throw new ApiError(400,'Provide 1-500 one-time prekeys');const deviceId=String(b.deviceId||'');const d=await DeviceKey.findOne({user:req.user.id,deviceId});if(!d)throw new ApiError(404,'Device keys not found');const existing=new Set(d.oneTimePreKeys.map(p=>p.keyId));for(const p of b.oneTimePreKeys){if(!p||typeof p.keyId!=='string'||typeof p.publicKey!=='string'||p.publicKey.length<20||p.publicKey.length>4096||existing.has(p.keyId))throw new ApiError(400,'Invalid or duplicate one-time prekey');existing.add(p.keyId);}d.oneTimePreKeys.push(...b.oneTimePreKeys);await d.save();ok(res,{remaining:d.oneTimePreKeys.length},'One-time prekeys replenished');}
