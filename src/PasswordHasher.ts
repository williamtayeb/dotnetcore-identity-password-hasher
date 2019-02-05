import * as crypto from 'crypto';

const DEFAULT_ITER_COUNT = 10000;

export enum PasswordVerificationResult {
  Failed,
  Success,
  SuccessRehashNeeded,
}

export enum PFR {
  SHA1 = 0,
  SHA256 = 1,
}

export class PasswordHasher {
  // Gets or sets the number of iterations used when hashing passwords using PBKDF2. Default is 10,000.
  private iterCount: number = DEFAULT_ITER_COUNT;

  // Used when verifying V3 hash
  private embeddedIterCount: number = 0;

  constructor(iterCount: number = DEFAULT_ITER_COUNT) {
    this.iterCount = iterCount;
  }

  /*public hashPassword(password: string): string {

  }*/

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
        // TODO: Refactor
        return PasswordVerificationResult.Failed;
        break;
      case 0x01:
        this.embeddedIterCount = 0;

        const match = await this.verifyHashedPasswordV3(
          decodedHashedPassword,
          providedPassword
        );

        if (match) {
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
      case PFR.SHA1:
        digest = 'SHA1';
        break;
      case PFR.SHA256:
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
}
