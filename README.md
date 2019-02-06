A useful library incase you are migrating user data including hashed passwords from a .NET Core stack to Node.js. Provides a Node.js implementation of ASP.NET Core Identity's Password Hasher including support for V2 and V3.

# Getting Started

Install the package using [`yarn`](https://yarnpkg.com/):

```bash
yarn add aspnetcore-identity-password-hasher
```

Or [`npm`](https://www.npmjs.com/):

```bash
npm install aspnetcore-identity-password-hasher
```

```javascript
const identity = require('aspnetcore-identity-password-hasher');
```

**Generating a password hash:**
Uses the V3 method to generate a password hash. See the note below if you are interested in using the old V2 method.

```javascript
const password = 'example';

identity.hash(password).then(hashedPassword => {
  // Store the hashed password
});
```

**Verifying plain text password with associated hash:**
Is able to verify both V2 and V3 hashes since the format type is included within the payload of the hash.

```javascript
identity.verify(password, hashedPassword).then(res => {
  // res is true if the plain text password matches with the hash
  // otherwise false.
});
```

# Note

The original PasswordHasher class from .NET Core has been completely ported and is available in `src/PasswordHasher.t`. The class includes explicit method for generating V2 password hashes.
