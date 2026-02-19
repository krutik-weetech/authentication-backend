import express from "express";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import authRouter from "./routes/auth.routes";
import userRouter from "./routes/user.routes";

dotenv.config();
export const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.use("/auth", authRouter);
app.use("/user", userRouter);



//Youtube link for reference 
//https://youtu.be/nHvf6P4cFCQ?si=EnBjP2XmbgB2SvmQ


// https://mailtrap.io/ ==> for sending test emails in development environment