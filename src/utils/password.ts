import * as bcrypt from 'bcryptjs';

// u5bf9u5bc6u7801u8fdbu884cu54c8u5e0cu52a0u5bc6
export async function hashPassword(password: string): Promise<string> {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
}

// u6bd4u8f83u5bc6u7801u662fu5426u5339u914d
export async function comparePassword(password: string, hashedPassword: string): Promise<boolean> {
  return bcrypt.compare(password, hashedPassword);
}
