export const ok=(res,data,message='OK',status=200)=>res.status(status).json({success:true,data,message});
