"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.PasswordHasher = exports.PRF = exports.PasswordHasherCompatibilityMode = exports.PasswordVerificationResult = void 0;
const crypto = require("crypto");
const DEFAULT_ITER_COUNT = 10000;
var PasswordVerificationResult;
(function (PasswordVerificationResult) {
    PasswordVerificationResult[PasswordVerificationResult["Failed"] = 0] = "Failed";
    PasswordVerificationResult[PasswordVerificationResult["Success"] = 1] = "Success";
    PasswordVerificationResult[PasswordVerificationResult["SuccessRehashNeeded"] = 2] = "SuccessRehashNeeded";
})(PasswordVerificationResult = exports.PasswordVerificationResult || (exports.PasswordVerificationResult = {}));
var PasswordHasherCompatibilityMode;
(function (PasswordHasherCompatibilityMode) {
    PasswordHasherCompatibilityMode[PasswordHasherCompatibilityMode["IdentityV2"] = 0] = "IdentityV2";
    PasswordHasherCompatibilityMode[PasswordHasherCompatibilityMode["IdentityV3"] = 1] = "IdentityV3";
})(PasswordHasherCompatibilityMode = exports.PasswordHasherCompatibilityMode || (exports.PasswordHasherCompatibilityMode = {}));
var PRF;
(function (PRF) {
    PRF[PRF["SHA1"] = 0] = "SHA1";
    PRF[PRF["SHA256"] = 1] = "SHA256";
    PRF[PRF["SHA512"] = 2] = "SHA512";
})(PRF = exports.PRF || (exports.PRF = {}));
class PasswordHasher {
    constructor(iterCount = DEFAULT_ITER_COUNT, compatibilityMode = PasswordHasherCompatibilityMode.IdentityV3) {
        // Used when verifying V3 hash
        this.embeddedIterCount = 0;
        this.iterCount = iterCount;
        this.compatibilityMode = compatibilityMode;
    }
    hashPassword(password) {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.compatibilityMode === PasswordHasherCompatibilityMode.IdentityV2) {
                return this.hashPasswordV2(password);
            }
            else {
                return this.hashPasswordV3(password);
            }
        });
    }
    hashPasswordV2(password) {
        return __awaiter(this, void 0, void 0, function* () {
            const prf = PRF.SHA1; // default for Rfc2898DeriveBytes
            const iterCount = 1000; // default for Rfc2898DeriveBytes
            const subkeyLength = 256 / 8; // 256 bits
            const saltSize = 128 / 8; // 128 bits
            let salt = yield PasswordHasher.randomBytes(saltSize);
            let subkey = yield PasswordHasher.pbkdf2(password, salt, prf, iterCount, subkeyLength);
            let outputBytes = Buffer.alloc(1 + salt.byteLength + subkey.byteLength);
            outputBytes[0] = 0x00; // Format maker
            salt.copy(outputBytes, 1, 0, salt.byteLength);
            subkey.copy(outputBytes, 1 + saltSize, 0, subkey.byteLength);
            return outputBytes.toString('base64');
        });
    }
    hashPasswordV3(password) {
        return __awaiter(this, void 0, void 0, function* () {
            const saltSize = 128 / 8;
            const numBytesRequested = 256 / 8;
            const prf = PRF.SHA256;
            let salt = yield PasswordHasher.randomBytes(saltSize);
            let subkey = yield PasswordHasher.pbkdf2(password, salt, prf, this.iterCount, numBytesRequested);
            let outputBytes = Buffer.alloc(13 + salt.byteLength + subkey.byteLength);
            outputBytes[0] = 0x01; // Format maker
            PasswordHasher.writeNetworkByteOrder(outputBytes, 1, prf);
            PasswordHasher.writeNetworkByteOrder(outputBytes, 5, this.iterCount);
            PasswordHasher.writeNetworkByteOrder(outputBytes, 9, saltSize);
            salt.copy(outputBytes, 13, 0, salt.byteLength);
            subkey.copy(outputBytes, 13 + saltSize, 0, subkey.byteLength);
            return outputBytes.toString('base64');
        });
    }
    static randomBytes(size) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => {
                crypto.randomBytes(size, (err, buffer) => {
                    if (err)
                        throw err;
                    resolve(buffer);
                });
            });
        });
    }
    verifyHashedPassword(hashedPassword, providedPassword) {
        return __awaiter(this, void 0, void 0, function* () {
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
                    const matchV2 = yield this.verifyHashedPasswordV2(decodedHashedPassword, providedPassword);
                    if (matchV2) {
                        // This is an old password hash format - the caller needs to rehash if we're not running in an older compat mode.
                        return this.compatibilityMode ===
                            PasswordHasherCompatibilityMode.IdentityV3
                            ? PasswordVerificationResult.SuccessRehashNeeded
                            : PasswordVerificationResult.Success;
                    }
                    else {
                        return PasswordVerificationResult.Failed;
                    }
                case 0x01:
                    this.embeddedIterCount = 0;
                    const matchV3 = yield this.verifyHashedPasswordV3(decodedHashedPassword, providedPassword);
                    if (matchV3) {
                        return this.embeddedIterCount < this.iterCount
                            ? PasswordVerificationResult.SuccessRehashNeeded
                            : PasswordVerificationResult.Success;
                    }
                    else {
                        return PasswordVerificationResult.Failed;
                    }
                default:
                    // Unknown format marker
                    return PasswordVerificationResult.Failed;
            }
        });
    }
    verifyHashedPasswordV2(hashedPassword, password) {
        return __awaiter(this, void 0, void 0, function* () {
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
            const actualSubkey = yield PasswordHasher.pbkdf2(password, salt, prf, iterCount, subkeyLength);
            return actualSubkey.equals(expectedSubkey);
        });
    }
    verifyHashedPasswordV3(hashedPassword, password) {
        return __awaiter(this, void 0, void 0, function* () {
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
            const actualSubkey = yield PasswordHasher.pbkdf2(password, salt, prf, iterCount, subkeyLength);
            return actualSubkey.equals(expectedSubkey);
        });
    }
    static pbkdf2(password, salt, prf, iterCount, length) {
        let digest;
        switch (prf) {
            case PRF.SHA1:
                digest = 'SHA1';
                break;
            case PRF.SHA256:
                digest = 'SHA256';
                break;
            case PRF.SHA512:
                digest = 'SHA512';
                break;
            default:
                throw 'Unknown PRF';
        }
        return new Promise(function (resolve, reject) {
            crypto.pbkdf2(password, salt, iterCount, length, digest, (err, derivedKey) => {
                if (err) {
                    throw err;
                }
                else {
                    resolve(derivedKey);
                }
            });
        });
    }
    static readNetworkByteOrder(buffer, offset) {
        return ((Number(buffer[offset + 0]) << 24) |
            (Number(buffer[offset + 1]) << 16) |
            (Number(buffer[offset + 2]) << 8) |
            Number(buffer[offset + 3]));
    }
    static writeNetworkByteOrder(buffer, offset, value) {
        buffer[offset + 0] = value >> 24;
        buffer[offset + 1] = value >> 16;
        buffer[offset + 2] = value >> 8;
        buffer[offset + 3] = value >> 0;
    }
}
exports.PasswordHasher = PasswordHasher;
//# sourceMappingURL=PasswordHasher.js.map