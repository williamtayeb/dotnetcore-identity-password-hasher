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
exports.hash = exports.verify = void 0;
const PasswordHasher_1 = require("./PasswordHasher");
const verify = (password, hash) => __awaiter(void 0, void 0, void 0, function* () {
    const hasher = new PasswordHasher_1.PasswordHasher();
    const result = yield hasher.verifyHashedPassword(hash, password);
    return result !== PasswordHasher_1.PasswordVerificationResult.Failed;
});
exports.verify = verify;
const hash = (password) => __awaiter(void 0, void 0, void 0, function* () {
    const hasher = new PasswordHasher_1.PasswordHasher();
    const hashedPassword = yield hasher.hashPassword(password);
    return hashedPassword;
});
exports.hash = hash;
//# sourceMappingURL=index.js.map