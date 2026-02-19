import jwt from "jsonwebtoken";

export function createAccessToken(
  userId: string,
  role: "user" | "admin",
  tokenVersion: number,
) {
  const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET!;
  const ACCESS_EXPIRES =
    (process.env.JWT_ACCESS_EXPIRES_IN as jwt.SignOptions["expiresIn"]) || "1d";

  const payload = { sub: userId, role, tokenVersion };

  return jwt.sign(payload, ACCESS_SECRET, {
    expiresIn: ACCESS_EXPIRES,
  });
}

export function verifyAccessToken(token: string) {
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
    sub: string;
    role: "user" | "admin";
    tokenVersion: number;
  };
}

export function createRefreshToken(
  userId: string,
  role: "user" | "admin",
  tokenVersion: number,
) {
  const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET!;
  const REFRESH_EXPIRES =
    (process.env.JWT_REFRESH_EXPIRES_IN as jwt.SignOptions["expiresIn"]) ||
    "7d";
  const payload = { sub: userId, role, tokenVersion };
  return jwt.sign(payload, REFRESH_SECRET, {
    expiresIn: REFRESH_EXPIRES,
  });
}

export function verifyRefreshToken(token: string) {
  return jwt.verify(token, process.env.JWT_REFRESH_SECRET!) as {
    sub: string;
    tokenVersion: number;
  };
}
