import test from 'node:test';import assert from 'node:assert/strict';import {registerSchema,loginSchema,verifyOtpSchema} from '../src/validators/schemas.js';
test('registration rejects short password and invalid username',()=>assert.equal(registerSchema.safeParse({body:{username:'x',displayName:'A',password:'123'},params:{},query:{}}).success,false));
test('login accepts identifier and password',()=>assert.equal(loginSchema.safeParse({body:{identifier:'alice',password:'correct horse'},params:{},query:{}}).success,true));
test('OTP schema rejects non-six-digit code',()=>assert.equal(verifyOtpSchema.safeParse({body:{email:'a@b.com',code:'abc'},params:{},query:{}}).success,false));
