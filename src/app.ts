import express from "express";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";


dotenv.config();
export const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});