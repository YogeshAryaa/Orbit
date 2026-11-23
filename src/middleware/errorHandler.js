export function notFound(req,res,next){next(Object.assign(new Error(`Route not found: ${req.method} ${req.path}`),{statusCode:404}));}
export function errorHandler(err,req,res,next){
 if(res.headersSent)return next(err);
 let status=err.statusCode||err.status;
 if(!status){
  if(err.name==='MulterError')status=err.code==='LIMIT_FILE_SIZE'?413:400;
  else if(err.type==='entity.too.large')status=413;
  else if(err.type==='entity.parse.failed')status=400;
  else if(err.name==='ValidationError'||err.name==='ZodError'||err.name==='CastError')status=400;
  else if(err.code===11000)status=409;
  else status=500;
 }
 const message=status>=500&&process.env.NODE_ENV==='production'?'Internal server error':(err.message||'Internal server error');
 if(status>=500) console.error(JSON.stringify({level:'error',event:'request_failed',path:req.path,method:req.method,errorName:err.name,code:err.code}));
 res.status(status).json({success:false,data:null,message,...(err.details?{errors:err.details}:{})});
}
