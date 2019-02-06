import { PasswordHasher, PasswordVerificationResult } from './PasswordHasher';

export const verify = async (password: string, hash: string) => {
  const hasher = new PasswordHasher();
  const result = await hasher.verifyHashedPassword(hash, password);

  return result !== PasswordVerificationResult.Failed;
};

export const hash = async (password: string) => {
  const hasher = new PasswordHasher();
  const hashedPassword = await hasher.hashPassword(password);

  return hashedPassword;
};
