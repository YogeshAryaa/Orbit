import nodemailer from 'nodemailer';
import {env} from './env.js';
export const mailerEnabled=Boolean(env.SMTP_HOST&&env.SMTP_USER&&env.SMTP_PASS&&env.SMTP_FROM);
const transporter=mailerEnabled?nodemailer.createTransport({host:env.SMTP_HOST,port:env.SMTP_PORT,secure:env.SMTP_SECURE==='true',auth:{user:env.SMTP_USER,pass:env.SMTP_PASS}}):null;
export async function sendMail({to,subject,text}){if(!transporter) throw Object.assign(new Error('Email provider is not configured'),{statusCode:503});return transporter.sendMail({from:env.SMTP_FROM,to,subject,text});}
