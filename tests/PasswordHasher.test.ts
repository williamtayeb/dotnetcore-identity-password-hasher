import {
  PasswordHasher,
  PasswordHasherCompatibilityMode,
  PasswordVerificationResult,
} from '../src/PasswordHasher';

describe('hashPassword', () => {
  it('Should return a V2 hash if compability mode is set to IdentityV2', async () => {
    const iterCount = 0;
    let password: string = 'password';

    const hasher = new PasswordHasher(
      iterCount,
      PasswordHasherCompatibilityMode.IdentityV2
    );

    const hashedPassword = await hasher.hashPassword(password);
    const decodedHashedPassword = Buffer.from(hashedPassword, 'base64');
    const format = decodedHashedPassword[0];

    expect(format).toBe(0x00);
  });

  it('Should return a V3 hash if compability mode is set to IdentityV3', async () => {
    const iterCount = 10000;
    let password: string = 'password';

    const hasher = new PasswordHasher(
      iterCount,
      PasswordHasherCompatibilityMode.IdentityV3
    );

    const hashedPassword = await hasher.hashPassword(password);
    const decodedHashedPassword = Buffer.from(hashedPassword, 'base64');
    const format = decodedHashedPassword[0];

    expect(format).toBe(0x01);
  });
});

describe('hashPasswordV2', () => {
  it('Should not return empty string', async () => {
    let password: string = 'password';

    const hasher = new PasswordHasher();
    const hashedPassword = await hasher.hashPasswordV2(password);

    expect(hashedPassword.length).toBeGreaterThanOrEqual(1);
  });

  it('Should return base64 string', async () => {
    let password: string = 'password';

    const hasher = new PasswordHasher();
    const hashedPassword = await hasher.hashPasswordV2(password);

    const checkBase64 = Buffer.from(hashedPassword, 'base64').toString(
      'base64'
    );

    expect(checkBase64).toBe(hashedPassword);
  });

  it('Should not be idempotent', async () => {
    let password: string = 'password';

    const hasher = new PasswordHasher();

    const hashedPassword1 = await hasher.hashPasswordV2(password);
    const hashedPassword2 = await hasher.hashPasswordV2(password);

    const check = hashedPassword1 === hashedPassword2;

    expect(check).toBeFalsy();
  });

  it('Should be able to be verified', async () => {
    let password: string = 'password';

    const hasher = new PasswordHasher(
      0,
      PasswordHasherCompatibilityMode.IdentityV2
    );

    const hashedPassword = await hasher.hashPasswordV2(password);
    const result = await hasher.verifyHashedPassword(hashedPassword, password);

    expect(result).toBe(PasswordVerificationResult.Success);
  });
});

describe('hashPasswordV3', () => {
  it('Should not return empty string', async () => {
    let password: string = 'password';

    const hasher = new PasswordHasher();
    const hashedPassword = await hasher.hashPasswordV3(password);

    expect(hashedPassword.length).toBeGreaterThanOrEqual(1);
  });

  it('Should return base64 string', async () => {
    let password: string = 'password';

    const hasher = new PasswordHasher();
    const hashedPassword = await hasher.hashPasswordV3(password);

    const checkBase64 = Buffer.from(hashedPassword, 'base64').toString(
      'base64'
    );

    expect(checkBase64).toBe(hashedPassword);
  });

  it('Should not be idempotent', async () => {
    let password: string = 'password';

    const hasher = new PasswordHasher();

    const hashedPassword1 = await hasher.hashPasswordV3(password);
    const hashedPassword2 = await hasher.hashPasswordV3(password);

    const check = hashedPassword1 === hashedPassword2;

    expect(check).toBeFalsy();
  });

  it('Should be able to be verified', async () => {
    let password: string = 'password';

    const hasher = new PasswordHasher();

    const hashedPassword = await hasher.hashPasswordV3(password);
    const result = await hasher.verifyHashedPassword(hashedPassword, password);

    expect(result).toBe(PasswordVerificationResult.Success);
  });
});

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

  it('Should return failed if V2 passwords does not match', async () => {
    let hashedPasswordV2: string =
      'ANuQywFHdT6GVuXGl4TXfmi5TUoR45Cizppo6FN3IqeGUzHoVXAL51x6GHiAWpavVQ==';
    let providedPassword: string = 'invalid';

    const hasher = new PasswordHasher();
    const result = await hasher.verifyHashedPassword(
      hashedPasswordV2,
      providedPassword
    );

    expect(result).toBe(PasswordVerificationResult.Failed);
  });

  it('Should return success if V2 passwords match and compatibility mode is set to V2', async () => {
    let hashedPasswordV2: string =
      'ANuQywFHdT6GVuXGl4TXfmi5TUoR45Cizppo6FN3IqeGUzHoVXAL51x6GHiAWpavVQ==';
    let providedPassword: string = 'test123';

    const hasher = new PasswordHasher(
      0,
      PasswordHasherCompatibilityMode.IdentityV2
    );
    const result = await hasher.verifyHashedPassword(
      hashedPasswordV2,
      providedPassword
    );

    expect(result).toBe(PasswordVerificationResult.Success);
  });

  it('Should return SuccessRehashNeeded if V2 passwords match and compatibility mode is set to V3', async () => {
    let hashedPasswordV2: string =
      'ANuQywFHdT6GVuXGl4TXfmi5TUoR45Cizppo6FN3IqeGUzHoVXAL51x6GHiAWpavVQ==';
    let providedPassword: string = 'test123';

    const hasher = new PasswordHasher(
      10000,
      PasswordHasherCompatibilityMode.IdentityV3
    );
    const result = await hasher.verifyHashedPassword(
      hashedPasswordV2,
      providedPassword
    );

    expect(result).toBe(PasswordVerificationResult.SuccessRehashNeeded);
  });
});
