import {
  PasswordHasher,
  PasswordVerificationResult,
} from '../src/PasswordHasher';

describe('verifyHashedPassword', () => {
  it('Should return failed if the decoded hashed password length is zero', async () => {
    let hashedPassword: string = '';
    let providedPassword: string = '';

    const hasher = new PasswordHasher();
    const result = await hasher.verifyHashedPassword(
      hashedPassword,
      providedPassword
    );

    expect(result).toBe(PasswordVerificationResult.Failed);
  });

  it('Should return failed if the format marker is unknown', async () => {
    let hashedPassword: string = 'asdf';
    let providedPassword: string = '';

    const hasher = new PasswordHasher();
    const result = await hasher.verifyHashedPassword(
      hashedPassword,
      providedPassword
    );

    expect(result).toBe(PasswordVerificationResult.Failed);
  });

  it('Should return success if passwords match', async () => {
    let hashedPassword: string =
      'AQAAAAEAACcQAAAAEFu4dWKdwFM0edzCkR9GmR8p6ICQ4x7B9sishNgunrQ82vocwJ6QBa0uhqGmNYOKrg==';
    let providedPassword: string = 'test123';

    const hasher = new PasswordHasher();
    const result = await hasher.verifyHashedPassword(
      hashedPassword,
      providedPassword
    );

    expect(result).toBe(PasswordVerificationResult.Success);
  });

  it('Should return failed if passwords does not match', async () => {
    let hashedPassword: string =
      'AQAAAAEAACcQAAAAEFu4dWKdwFM0edzCkR9GmR8p6ICQ4x7B9sishNgunrQ82vocwJ6QBa0uhqGmNYOKrg==';
    let providedPassword: string = 'invalid';

    const hasher = new PasswordHasher();
    const result = await hasher.verifyHashedPassword(
      hashedPassword,
      providedPassword
    );

    expect(result).toBe(PasswordVerificationResult.Failed);
  });

  it('Should return SuccessRehashNeeded if embeddedIterCount is less than iterCount', async () => {
    let hashedPassword: string =
      'AQAAAAEAACcQAAAAEFu4dWKdwFM0edzCkR9GmR8p6ICQ4x7B9sishNgunrQ82vocwJ6QBa0uhqGmNYOKrg==';
    let providedPassword: string = 'test123';

    const hasher = new PasswordHasher(20000);
    const result = await hasher.verifyHashedPassword(
      hashedPassword,
      providedPassword
    );

    expect(result).toBe(PasswordVerificationResult.SuccessRehashNeeded);
  });
});
