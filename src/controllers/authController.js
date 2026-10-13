import {register,login,requestOtp,verifyEmail,resetPassword} from '../services/authService.js';import {revokeSession, revokeAllUserSessions} from '../services/tokenService.js';import {ok} from '../utils/respond.js';import {ApiError} from '../utils/ApiError.js';
export async function registerUser(req,res){ok(res,await register(req.validated.body),'Account created',201);}
export async function loginUser(req,res){ok(res,await login(req.validated.body.identifier,req.validated.body.password),'Logged in');}
export async function logoutUser(req,res){await revokeSession(req.sessionId);const io=req.app.get('io');if(io){const sockets=await io.in(`user:${req.user.id}`).fetchSockets();for(const socket of sockets)if(socket.data?.sessionId===req.sessionId)socket.disconnect(true);}ok(res,null,'Logged out');}
export async function logoutAllUserSessions(req,res){await revokeAllUserSessions(req.user.id);const io=req.app.get('io');if(io){const sockets=await io.in(`user:${req.user.id}`).fetchSockets();for(const socket of sockets)socket.disconnect(true);}ok(res,null,'All sessions logged out');}
export async function sendVerifyOtp(req,res){if(!req.user.email)throw new ApiError(400,'An email is required');ok(res,await requestOtp(req.user.email,'verify'),'Verification code sent');}
export async function verifyOtp(req,res){ok(res,await verifyEmail(req.validated.body.email,req.validated.body.code),'Email verified');}
export async function sendResetOtp(req,res){ok(res,await requestOtp(req.validated.body.email,'reset'),'If account exists and email is configured, code sent');}
export async function reset(req,res){ok(res,await resetPassword(req.validated.body.email,req.validated.body.code,req.validated.body.newPassword),'Password reset');}
export async function updatePassword(req,res){const {changePassword}=await import('../services/authService.js');ok(res,await changePassword(req.user.id,req.validated.body.currentPassword,req.validated.body.newPassword),'Password updated');}

