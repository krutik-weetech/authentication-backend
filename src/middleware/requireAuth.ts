import { NextFunction, Request, Response } from "express";
import { verifyAccessToken } from "../lib/token";
import { User } from "../models/user.modal";

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({
        message:
          "You are not authenticated! Please log in to access this resource.",
      });
  }

  const token = authHeader.split(" ")[1];

  try {
    const payload = verifyAccessToken(token);

    const user = await User.findById(payload.sub);

    if (!user) {
      return res
        .status(401)
        .json({
          message: "User not found! Please log in to access this resource.",
        });
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({ message: "Token invalidated" });
    }

    const authReq = req as any;

    authReq.user = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
    };

    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

export default requireAuth;
