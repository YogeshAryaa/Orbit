import mongoose from 'mongoose';
import {ApiError} from './ApiError.js';
export function assertObjectId(value,label='ID'){if(!mongoose.isValidObjectId(value))throw new ApiError(400,`Invalid ${label}`);return value;}
export function escapeRegex(value){return value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');}
