import webpush from 'web-push';
import {env} from './env.js';
export const pushEnabled=Boolean(env.VAPID_PUBLIC_KEY&&env.VAPID_PRIVATE_KEY);
if(pushEnabled) webpush.setVapidDetails(env.VAPID_SUBJECT,env.VAPID_PUBLIC_KEY,env.VAPID_PRIVATE_KEY);
export {webpush};
