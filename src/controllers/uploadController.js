import crypto from 'node:crypto';import multer from 'multer';import path from 'node:path';import fs from 'node:fs/promises';import {v2 as cloudinary} from 'cloudinary';import {cloudinaryEnabled} from '../config/cloudinary.js';import {env} from '../config/env.js';import {ApiError} from '../utils/ApiError.js';import {ok} from '../utils/respond.js';import Conversation from '../models/Conversation.js';import ProtectedUpload from '../models/ProtectedUpload.js';import {assertObjectId} from '../utils/ids.js';import {conversationAccess} from '../services/accessPolicy.js';
const allowed=new Set(['image/jpeg','image/png','image/webp','image/gif','video/mp4','video/webm','audio/mpeg','audio/mp4','audio/ogg','audio/wav','audio/webm','application/pdf','text/plain','application/zip','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']);
export const uploadMiddleware=multer({storage:multer.memoryStorage(),limits:{fileSize:env.MAX_UPLOAD_MB*1024*1024,files:1},fileFilter:(req,file,cb)=>{const e2ee=String(env.E2EE_REQUIRED).toLowerCase()!=='false';if(file.mimetype==='application/octet-stream')return cb(null,true);if(!e2ee&&allowed.has(file.mimetype))return cb(null,true);return cb(new ApiError(415,e2ee?'E2EE mode requires client-encrypted application/octet-stream uploads':'File type not allowed'));}}).single('file');
export async function uploadFile(req,res){
 if(!req.file)throw new ApiError(400,'Upload a file in multipart field "file"');
 const encrypted=req.file.mimetype==='application/octet-stream';
 if(String(env.E2EE_REQUIRED).toLowerCase()!=='false'&&!encrypted)throw new ApiError(415,'E2EE mode requires encrypted uploads');
 const conversationId=String(req.body?.conversationId||'');
 assertObjectId(conversationId,'conversation ID');
 const conversation=await Conversation.findOne({_id:conversationId,members:req.user.id});
 if(!conversation)throw new ApiError(404,'Conversation not found');
 if(!(await conversationAccess(conversation,req.user.id,req.device,'new')).allowed)throw new ApiError(403,'This device is not authorized to upload to this conversation');
 let storageKey,storage;
 if(cloudinaryEnabled){
  const uploaded=await new Promise((resolve,reject)=>{const stream=cloudinary.uploader.upload_stream({resource_type:'raw',type:'authenticated',folder:'chat-app'},(error,result)=>error?reject(error):resolve(result));stream.end(req.file.buffer);});
  storageKey=uploaded.public_id;storage='cloudinary';
 }else{
  const dir=path.resolve('uploads');await fs.mkdir(dir,{recursive:true});
  const name=`${Date.now()}-${crypto.randomUUID()}.bin`;
  await fs.writeFile(path.join(dir,name),req.file.buffer,{flag:'wx'});
  storageKey=path.join(dir,name);storage='local';
 }
 const originalName=encrypted?'encrypted.bin':path.basename(req.file.originalname).slice(0,255);
 const mimeType=encrypted?'application/octet-stream':req.file.mimetype;
 const asset=await ProtectedUpload.create({conversation:conversation._id,uploader:req.user.id,storage,storageKey,size:req.file.size,mimeType,originalName,encrypted});
 ok(res,{url:`/api/uploads/${asset.id}`,publicId:asset.id,mimeType,size:req.file.size,originalName,encrypted},'File uploaded',201);
}

export async function downloadProtectedUpload(req,res){
 assertObjectId(req.params.assetId,'upload ID');
 const asset=await ProtectedUpload.findById(req.params.assetId);
 if(!asset)throw new ApiError(404,'File not found');
 const conversation=await Conversation.findOne({_id:asset.conversation,members:req.user.id});
 if(!conversation)throw new ApiError(404,'File not found');
 if(!(await conversationAccess(conversation,req.user.id,req.device,'history')).allowed)throw new ApiError(403,'This device is not authorized to download this file');
 let bytes;
 if(asset.storage==='local')bytes=await fs.readFile(asset.storageKey);
 else{
  const url=cloudinary.url(asset.storageKey,{resource_type:'raw',type:'authenticated',secure:true,sign_url:true});
  const response=await fetch(url);
  if(!response.ok)throw new ApiError(502,'Protected file storage could not serve this file');
  bytes=Buffer.from(await response.arrayBuffer());
 }
 res.setHeader('Content-Type',asset.mimeType || 'application/octet-stream');
 res.setHeader('Cache-Control','private, no-store');
 res.setHeader('Content-Length',String(bytes.length));
 res.send(bytes);
}
