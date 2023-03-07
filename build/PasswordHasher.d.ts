export declare enum PasswordVerificationResult {
    Failed = 0,
    Success = 1,
    SuccessRehashNeeded = 2
}
export declare enum PasswordHasherCompatibilityMode {
    IdentityV2 = 0,
    IdentityV3 = 1
}
export declare enum PRF {
    SHA1 = 0,
    SHA256 = 1,
    SHA512 = 2
}
export declare class PasswordHasher {
    private iterCount;
    private embeddedIterCount;
    private compatibilityMode;
    constructor(iterCount?: number, compatibilityMode?: PasswordHasherCompatibilityMode);
    hashPassword(password: string): Promise<string>;
    hashPasswordV2(password: string): Promise<string>;
    hashPasswordV3(password: string): Promise<string>;
    private static randomBytes;
    verifyHashedPassword(hashedPassword: string, providedPassword: string): Promise<PasswordVerificationResult>;
    private verifyHashedPasswordV2;
    private verifyHashedPasswordV3;
    private static pbkdf2;
    private static readNetworkByteOrder;
    private static writeNetworkByteOrder;
}
