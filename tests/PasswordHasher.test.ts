import {
  PasswordHasher,
  PasswordVerificationResult,
} from '../src/PasswordHasher';

describe('verifyHashedPassword', () => {
  it('Should throw exception if hashedPassword is null or undefined', () => {
    let hashedPassword: string;
    let providedPassword: string = '';

    const hasher = new PasswordHasher();

    expect(() => {
      hasher.verifyHashedPassword(hashedPassword, providedPassword);
    }).toThrow();
  });

  it('Should throw exception if providedPassword is null or undefined', () => {
    let hashedPassword: string = '';
    let providedPassword: string;

    const hasher = new PasswordHasher();

    expect(() => {
      hasher.verifyHashedPassword(hashedPassword, providedPassword);
    }).toThrow();
  });

  it('Should return failed if the decoded hashed password length is zero', () => {
    let hashedPassword: string = '';
    let providedPassword: string = '';

    const hasher = new PasswordHasher();
    const result = hasher.verifyHashedPassword(
      hashedPassword,
      providedPassword
    );

    expect(result).toBe(PasswordVerificationResult.Failed);
  });

  it('Should return failed if the format marker is unknown', () => {
    let hashedPassword: string = 'asdf';
    let providedPassword: string = '';

    const hasher = new PasswordHasher();
    const result = hasher.verifyHashedPassword(
      hashedPassword,
      providedPassword
    );

    expect(result).toBe(PasswordVerificationResult.Failed);
  });

  it('Should return success if passwords match', () => {
    let hashedPassword: string =
      'AQAAAAEAACcQAAAAEFu4dWKdwFM0edzCkR9GmR8p6ICQ4x7B9sishNgunrQ82vocwJ6QBa0uhqGmNYOKrg==';
    let providedPassword: string = 'test123';

    const hasher = new PasswordHasher();
    const result = hasher.verifyHashedPassword(
      hashedPassword,
      providedPassword
    );

    expect(result).toBe(PasswordVerificationResult.Success);
  });

  it('Should return failed if passwords does not match', () => {
    let hashedPassword: string =
      'AQAAAAEAACcQAAAAEFu4dWKdwFM0edzCkR9GmR8p6ICQ4x7B9sishNgunrQ82vocwJ6QBa0uhqGmNYOKrg==';
    let providedPassword: string = 'invalid';

    const hasher = new PasswordHasher();
    const result = hasher.verifyHashedPassword(
      hashedPassword,
      providedPassword
    );

    expect(result).toBe(PasswordVerificationResult.Failed);
  });

  it('Should return SuccessRehashNeeded if embeddedIterCount is less than iterCount', () => {
    let hashedPassword: string =
      'AQAAAAEAACcQAAAAEFu4dWKdwFM0edzCkR9GmR8p6ICQ4x7B9sishNgunrQ82vocwJ6QBa0uhqGmNYOKrg==';
    let providedPassword: string = 'test123';

    const hasher = new PasswordHasher(20000);
    const result = hasher.verifyHashedPassword(
      hashedPassword,
      providedPassword
    );

    expect(result).toBe(PasswordVerificationResult.SuccessRehashNeeded);
  });
});
