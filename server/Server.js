import express from "express";
import cors from "cors";
import 'dotenv/config';
import cookieParser from "cookie-parser";
import authRouter from './routes/authRoutes.js';
import userAuth from './middleware/userAuth.js';

import connectDB from "./config/Mongodb.js";
import userRouter from "./routes/userRoutes.js";

const app = express();
const port = process.env.PORT || 4000
connectDB();

app.use(express.json());
app.use(cookieParser());
app.use(cors({credentials : true}))

// API ENDOPOINT

app.get('/',(req,res)=> res.send("api working"));
app.use('/api/auth',authRouter);
app.use('/api/user',userRouter);



app.listen(port, ()=> console.log(`server started on port:${port}`));