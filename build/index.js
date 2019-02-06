"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const PasswordHasher_1 = require("./PasswordHasher");
exports.verify = (password, hash) => __awaiter(this, void 0, void 0, function* () {
    const hasher = new PasswordHasher_1.PasswordHasher();
    const result = yield hasher.verifyHashedPassword(hash, password);
    return result !== PasswordHasher_1.PasswordVerificationResult.Failed;
});
exports.hash = (password) => __awaiter(this, void 0, void 0, function* () {
    const hasher = new PasswordHasher_1.PasswordHasher();
    const hashedPassword = yield hasher.hashPassword(password);
    return hashedPassword;
});
//# sourceMappingURL=index.js.map