import { hash, verify } from '../src/index';

describe('verify', () => {
  it('Should return true if verified V3', async () => {
    const password = 'test123';
    const hashedPassword =
      'AQAAAAEAACcQAAAAEFu4dWKdwFM0edzCkR9GmR8p6ICQ4x7B9sishNgunrQ82vocwJ6QBa0uhqGmNYOKrg==';
    const result = await verify(password, hashedPassword);

    expect(result).toBeTruthy();
  });

  it('Should return true if verified V2', async () => {
    const password = 'test123';
    const hashedPasswordV2 =
      'ANuQywFHdT6GVuXGl4TXfmi5TUoR45Cizppo6FN3IqeGUzHoVXAL51x6GHiAWpavVQ==';
    const result = await verify(password, hashedPasswordV2);

    expect(result).toBeTruthy();
  });

  it('Should return false if not verified', async () => {
    const password = 'invalid';
    const hashedPassword =
      'AQAAAAEAACcQAAAAEFu4dWKdwFM0edzCkR9GmR8p6ICQ4x7B9sishNgunrQ82vocwJ6QBa0uhqGmNYOKrg==';
    const result = await verify(password, hashedPassword);

    expect(result).toBeFalsy();
  });
});

describe('hash', () => {
  it('Should be verifiable', async () => {
    const password = 'test123';
    const hashedPassword = await hash(password);

    const result = await verify(password, hashedPassword);
    expect(result).toBeTruthy();
  });
});
