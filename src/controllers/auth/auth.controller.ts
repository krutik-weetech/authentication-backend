import { Request, Response } from "express";
import { registerSchema } from "./auth.schema";
import { User } from "../../models/user.modal";

export async function registerHandler(req: Request, res: Response) {
  try {
    const result = registerSchema.safeParse(req.body);
    if (!result.success) {
      return res
        .status(400)
        .json({ message: "Invalid input data", error: result.error.flatten() });
    }
    const { name, email, password } = result.data;

    const normalizedEmail = email.toLowerCase().trim();

    // Check if user already exists
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      return res.status(400).json({ message: "Email already in use" });
    }

    
  } catch (error) {
    return res.status(500).json({ message: "Internal server error" });
  }
}
