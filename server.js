import express, { json } from "express";
import cors from "cors";
import { config } from "dotenv";
import cookieParser from "cookie-parser";
import connectDB from './src/config/db.js';
import userRoutes from './src/routes/userRoutes.js'
config();
connectDB();

const app = express();

app.use(cors());
app.use(json());
app.use(cookieParser());

app.use("/api/users", userRoutes);

app.listen(5000, () => console.log("Server running on port 5000"));
