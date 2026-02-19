import { Request, Response } from "express";
import { loginSchema, registerSchema } from "./auth.schema";
import { User } from "../../models/user.modal";
import { comparePassword, hashPassword } from "../../lib/hash";
import jwt from "jsonwebtoken";
import { sendEmail } from "../../lib/email";
import {
  createAccessToken,
  createRefreshToken,
  verifyRefreshToken,
} from "../../lib/token";
import crypto from "crypto";

function getAppUrl() {
  return process.env.NODE_ENV === "production"
    ? process.env.PROD_APP_URL
    : process.env.DEV_APP_URL || `http://localhost:${process.env.PORT || 3000}`;
}

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

    const passwordHash = await hashPassword(password);

    const newUser = await User.create({
      name,
      email: normalizedEmail,
      password: passwordHash,
      role: "user",
      isEmailVerified: false,
      twoFactorEnabled: false,
    });

    //email verification access token
    const verifyToken = jwt.sign(
      { sub: newUser.id },
      process.env.JWT_ACCESS_SECRET!,
      {
        expiresIn: process.env
          .JWT_ACCESS_EXPIRES_IN as jwt.SignOptions["expiresIn"],
      },
    );

    const verificationLink = `${getAppUrl()}/auth/verify-email?token=${verifyToken}`;

    await sendEmail(
      newUser.email,
      "Verify your email",
      `Please click the following link to verify your email: ${verificationLink}`,
    );

    return res.status(201).json({
      message:
        "User registered successfully. Please check your email to verify your account.",
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        isEmailVerified: newUser.isEmailVerified,
      },
    });
  } catch (error) {
    console.error("Error in registerHandler:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function verifyEmailHandler(req: Request, res: Response) {
  try {
    const token = req.query.token as string;
    if (!token) {
      return res
        .status(400)
        .json({ message: "Verification token is required" });
    }
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
      sub: string;
    };
    const user = await User.findById(payload.sub);
    if (!user) {
      return res.status(400).json({ message: "Invalid verification token" });
    }
    if (user.isEmailVerified) {
      return res.status(400).json({ message: "Email is already verified" });
    }
    user.isEmailVerified = true;

    await user.save();

    return res
      .status(200)
      .json({ message: "Email verified successfully. You can now log in." });
  } catch (error) {
    console.error("Error in verifyEmailHandler:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function loginHandler(req: Request, res: Response) {
  try {
    const result = loginSchema.safeParse(req.body);
    if (!result.success) {
      return res
        .status(400)
        .json({ message: "Invalid input data", error: result.error.flatten() });
    }
    const { email, password } = result.data;

    const normalizedEmail = email.toLowerCase().trim();

    const user = await User.findOne({ email: normalizedEmail });
    //user.id === user._id.toString()

    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }
    const isPasswordValid = await comparePassword(password, user.password);

    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    if (!user.isEmailVerified) {
      return res
        .status(403)
        .json({ message: "Please verify your email first" });
    }

    const accessToken = createAccessToken(
      user.id, //user.id === user._id.toString()
      user.role,
      user.tokenVersion,
    );

    const refreshToken = createRefreshToken(
      user.id,
      user.role,
      user.tokenVersion,
    );

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax", // Adjust as needed (e.g., "strict" or "none" with secure)
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return res.status(200).json({
      message: "Login successful",
      accessToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.error("Error in loginHandler:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function refreshHandler(req: Request, res: Response) {
  try {
    const token = req.cookies?.refreshToken as string | undefined;

    if (!token) {
      return res.status(401).json({ message: "Refresh token is missing" });
    }

    const payload = verifyRefreshToken(token);

    const user = await User.findById(payload.sub);
    console.log("🚀 ~ auth.controller.ts:192 ~ refreshHandler ~ user:", user);
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }
    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    const newAccessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion,
    );
    const newRefreshToken = createRefreshToken(
      user.id,
      user.role,
      user.tokenVersion,
    );
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax", // Adjust as needed (e.g., "strict" or "none" with secure)
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
    return res.status(200).json({
      message: "Token refreshed successfully",
      accessToken: newAccessToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.error("Error in refreshHandler:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function logoutHandler(_req: Request, res: Response) {
  try {
    res.clearCookie("refreshToken", { path: "/" });
    return res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("Error in logoutHandler:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function forgotPasswordHandler(req: Request, res: Response) {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }
    const normalizedEmail = email.toLowerCase().trim();

    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      return res.status(200).json({
        message: "If that email is registered, a reset link has been sent",
      });
    }

    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    user.resetPasswordToken = tokenHash;
    user.resetPasswordExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await user.save();

    const resetLink = `${getAppUrl()}/auth/reset-password?token=${rawToken}`;

    await sendEmail(
      user.email,
      "Password Reset Request",
      `You requested a password reset. Click the link to reset your password: ${resetLink}`,
    );
    return res.status(200).json({
      message: "If that email is registered, a reset link has been sent",
    });
  } catch (error) {
    console.error("Error in forgotPasswordHandler:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function resetPasswordHandler(req: Request, res: Response) {
  try {
    const { token, password } = req.body;
    if (!token || !password) {
      return res
        .status(400)
        .json({ message: "Token and new password are required" });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: "New password must be at least 6 characters long" });
    }


    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      resetPasswordToken: tokenHash,
      resetPasswordExpires: { $gt: new Date() },
    });
    if (!user) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }
    user.password = await hashPassword(password);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    user.tokenVersion += 1; // Invalidate existing tokens
    await user.save();

    return res.status(200).json({ message: "Password reset successful" });
  } catch (error) {
    console.error("Error in resetPasswordHandler:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}
