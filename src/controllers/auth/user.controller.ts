import { Request, Response } from "express";
import { User } from "../../models/user.modal";

export async function getUserProfile(req: Request, res: Response) {
  const user = (req as any).user;
  res.json({
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    isEmailVerified: user.isEmailVerified,
  });
}

export async function getUsersList(req: Request, res: Response) {
  try {
    //get all users from database and return them

    const users = await User.find().select(
      "-password -twoFactorSecret -resetPasswordToken -resetPasswordExpires",
    );

    res.json(users);
  } catch (error) {
    console.error("Error fetching users list:", error);
    res.status(500).json({ message: "Internal server error" });
  }
}
