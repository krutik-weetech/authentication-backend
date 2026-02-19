import bcrypt from "bcryptjs";

export async function hashPassword(password: string) {
  const saltRounds = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, saltRounds);
}


export async function comparePassword( password: string, hashedPassword: string) {
  return await bcrypt.compare(password, hashedPassword);
}