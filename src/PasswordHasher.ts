import * as crypto from 'crypto';

const DEFAULT_ITER_COUNT = 10000;

export enum PasswordVerificationResult {
  Failed,
  Success,
  SuccessRehashNeeded,
}

export enum PasswordHasherCompatibilityMode {
  IdentityV2,
  IdentityV3,
}

export enum PRF {
  SHA1 = 0,
  SHA256 = 1,
}

export class PasswordHasher {
  // Gets or sets the number of iterations used when hashing passwords using PBKDF2. Default is 10,000.
  private iterCount: number;

  // Used when verifying V3 hash
  private embeddedIterCount: number = 0;
  private compatibilityMode: PasswordHasherCompatibilityMode;

  constructor(
    iterCount: number = DEFAULT_ITER_COUNT,
    compatibilityMode: PasswordHasherCompatibilityMode = PasswordHasherCompatibilityMode.IdentityV3
  ) {
    this.iterCount = iterCount;
    this.compatibilityMode = compatibilityMode;
  }

  public async hashPassword(password: string): Promise<string> {
    if (this.compatibilityMode === PasswordHasherCompatibilityMode.IdentityV2) {
      return this.hashPasswordV2(password);
    } else {
      return this.hashPasswordV3(password);
    }
  }

  public async hashPasswordV2(password: string): Promise<string> {
    const prf = PRF.SHA1; // default for Rfc2898DeriveBytes
    const iterCount = 1000; // default for Rfc2898DeriveBytes
    const subkeyLength = 256 / 8; // 256 bits
    const saltSize = 128 / 8; // 128 bits

    let salt = await PasswordHasher.randomBytes(saltSize);
    let subkey = await PasswordHasher.pbkdf2(
      password,
      salt,
      prf,
      iterCount,
      subkeyLength
    );

    let outputBytes = Buffer.alloc(1 + salt.byteLength + subkey.byteLength);

    outputBytes[0] = 0x00; // Format maker

    salt.copy(outputBytes, 1, 0, salt.byteLength);
    subkey.copy(outputBytes, 1 + saltSize, 0, subkey.byteLength);

    return outputBytes.toString('base64');
  }

  public async hashPasswordV3(password: string): Promise<string> {
    const saltSize = 128 / 8;
    const numBytesRequested = 256 / 8;
    const prf = PRF.SHA256;

    let salt = await PasswordHasher.randomBytes(saltSize);
    let subkey = await PasswordHasher.pbkdf2(
      password,
      salt,
      prf,
      this.iterCount,
      numBytesRequested
    );

    let outputBytes = Buffer.alloc(13 + salt.byteLength + subkey.byteLength);

    outputBytes[0] = 0x01; // Format maker
    PasswordHasher.writeNetworkByteOrder(outputBytes, 1, prf);
    PasswordHasher.writeNetworkByteOrder(outputBytes, 5, this.iterCount);
    PasswordHasher.writeNetworkByteOrder(outputBytes, 9, saltSize);

    salt.copy(outputBytes, 13, 0, salt.byteLength);
    subkey.copy(outputBytes, 13 + saltSize, 0, subkey.byteLength);

    return outputBytes.toString('base64');
  }

  private static async randomBytes(size: number): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      crypto.randomBytes(size, (err, buffer) => {
        if (err) throw err;
        resolve(buffer);
      });
    });
  }

  public async verifyHashedPassword(
    hashedPassword: string,
    providedPassword: string
  ): Promise<PasswordVerificationResult> {
    if (typeof hashedPassword === 'undefined' || hashedPassword === null) {
      throw 'Hashed password cannot be null or undefined.';
    }

    if (typeof providedPassword === 'undefined' || providedPassword === null) {
      throw 'Provided password cannot be null or undefined.';
    }

    const decodedHashedPassword = Buffer.from(hashedPassword, 'base64');

    if (decodedHashedPassword.length == 0) {
      return PasswordVerificationResult.Failed;
    }

    switch (decodedHashedPassword[0]) {
      case 0x00:
        const matchV2 = await this.verifyHashedPasswordV2(
          decodedHashedPassword,
          providedPassword
        );

        if (matchV2) {
          // This is an old password hash format - the caller needs to rehash if we're not running in an older compat mode.
          return this.compatibilityMode ===
            PasswordHasherCompatibilityMode.IdentityV3
            ? PasswordVerificationResult.SuccessRehashNeeded
            : PasswordVerificationResult.Success;
        } else {
          return PasswordVerificationResult.Failed;
        }

      case 0x01:
        this.embeddedIterCount = 0;

        const matchV3 = await this.verifyHashedPasswordV3(
          decodedHashedPassword,
          providedPassword
        );

        if (matchV3) {
          return this.embeddedIterCount < this.iterCount
            ? PasswordVerificationResult.SuccessRehashNeeded
            : PasswordVerificationResult.Success;
        } else {
          return PasswordVerificationResult.Failed;
        }

      default:
        // Unknown format marker
        return PasswordVerificationResult.Failed;
    }
  }

  private async verifyHashedPasswordV2(
    hashedPassword: Buffer,
    password: string
  ): Promise<boolean> {
    const prf = PRF.SHA1; // default for Rfc2898DeriveBytes
    const iterCount = 1000; // default for Rfc2898DeriveBytes
    const subkeyLength = 256 / 8; // 256 bits
    const saltSize = 128 / 8; // 128 bits

    // We know ahead of time the exact length of a valid hashed password payload.
    if (hashedPassword.byteLength != 1 + saltSize + subkeyLength) {
      return false; // bad size
    }

    let salt = Buffer.alloc(saltSize);
    hashedPassword.copy(salt, 0, 1);

    let expectedSubkey = Buffer.alloc(subkeyLength);
    hashedPassword.copy(expectedSubkey, 0, 1 + salt.byteLength);

    // Hash the incoming password and verify it
    const actualSubkey = await PasswordHasher.pbkdf2(
      password,
      salt,
      prf,
      iterCount,
      subkeyLength
    );

    return actualSubkey.equals(expectedSubkey);
  }

  private async verifyHashedPasswordV3(
    hashedPassword: Buffer,
    password: string
  ): Promise<boolean> {
    // Read header information
    const prf = PasswordHasher.readNetworkByteOrder(hashedPassword, 1);
    const iterCount = PasswordHasher.readNetworkByteOrder(hashedPassword, 5);
    const saltLength = PasswordHasher.readNetworkByteOrder(hashedPassword, 9);

    this.embeddedIterCount = iterCount;

    // Read the salt: must be >= 128 bits
    if (saltLength < 128 / 8) {
      return false;
    }

    let salt = Buffer.allocUnsafe(saltLength);
    hashedPassword.copy(salt, 0, 13);

    // Read the subkey (the rest of the payload): must be >= 128 bits
    const subkeyLength = hashedPassword.length - 13 - salt.length;

    if (subkeyLength < 128 / 8) {
      return false;
    }

    let expectedSubkey = Buffer.allocUnsafe(subkeyLength);
    hashedPassword.copy(expectedSubkey, 0, 13 + salt.length);

    // Hash the incoming password and verify it
    const actualSubkey = await PasswordHasher.pbkdf2(
      password,
      salt,
      prf,
      iterCount,
      subkeyLength
    );

    return actualSubkey.equals(expectedSubkey);
  }

  private static pbkdf2(
    password: string | Buffer,
    salt: Buffer,
    prf: number,
    iterCount: number,
    length: number
  ): Promise<Buffer> {
    let digest: string;

    switch (prf) {
      case PRF.SHA1:
        digest = 'SHA1';
        break;
      case PRF.SHA256:
        digest = 'SHA256';
        break;
      default:
        throw 'Unknown PRF';
    }

    return new Promise(function(resolve, reject) {
      crypto.pbkdf2(
        password,
        salt,
        iterCount,
        length,
        digest,
        (err, derivedKey) => {
          if (err) {
            throw err;
          } else {
            resolve(derivedKey);
          }
        }
      );
    });
  }

  private static readNetworkByteOrder(buffer: Buffer, offset: number): number {
    return (
      (Number(buffer[offset + 0]) << 24) |
      (Number(buffer[offset + 1]) << 16) |
      (Number(buffer[offset + 2]) << 8) |
      Number(buffer[offset + 3])
    );
  }

  private static writeNetworkByteOrder(
    buffer: Buffer,
    offset: number,
    value: number
  ): void {
    buffer[offset + 0] = value >> 24;
    buffer[offset + 1] = value >> 16;
    buffer[offset + 2] = value >> 8;
    buffer[offset + 3] = value >> 0;
  }
}
