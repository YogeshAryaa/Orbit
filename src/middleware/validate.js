export const validate=schema=>(req,res,next)=>{
 const parsed=schema.safeParse({body:req.body,params:req.params,query:req.query});
 if(!parsed.success){
  const issues=parsed.error.issues.map(i=>({field:i.path.filter(p=>p!=='body'&&p!=='params'&&p!=='query').join('.')||i.path.join('.'),message:i.message}));
  const first=issues[0];
  const message=first?`Validation failed: ${first.field?first.field+' - ':''}${first.message}`:'Validation failed';
  return res.status(400).json({success:false,data:null,message,errors:{issues,...parsed.error.flatten()}});
 }
 req.validated=parsed.data;next();
};
