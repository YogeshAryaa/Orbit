export function notFound(req,res,next){next(Object.assign(new Error(`Route not found: ${req.method} ${req.path}`),{statusCode:404}));}
export function errorHandler(err,req,res,next){
 const status=err.statusCode||(err.name==='ValidationError'||err.name==='ZodError'?400:err.code===11000?409:500);
 const message=status>=500&&process.env.NODE_ENV==='production'?'Internal server error':(err.message||'Internal server error');
 if(status>=500) console.error(JSON.stringify({level:'error',event:'request_failed',path:req.path,method:req.method,message:err.message}));
 res.status(status).json({success:false,data:null,message,...(err.details?{errors:err.details}:{})});
}
