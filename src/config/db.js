import mongoose from 'mongoose';
export async function connectDB(uri){mongoose.set('strictQuery',true);await mongoose.connect(uri,{serverSelectionTimeoutMS:10000});console.log(JSON.stringify({level:'info',event:'mongodb_connected',db:mongoose.connection.name}));}
