# Cipher Class

This `Cipher` class provides various cryptographic functionalities using Node.js's built-in `crypto` module. It supports hashing, JWT creation and validation, RSA key pair generation, and AES-256 encryption and decryption.

## Installation

To use this class, ensure you have Node.js installed and include the `crypto` module.

```bash
npm install
```

## Usage

### Importing the Class

```javascript
const { Cipher } = require('./path/to/cipher');
```

### Initialization

Create an instance of the `Cipher` class by providing the necessary keys and tokens.

```javascript
const cipher = new Cipher(aes256Key, aes256Iv, appKey, appToken);
```

### Methods

#### `hash(input, [algorithm='sha256'])`

Generates a hash of the input using the specified algorithm.

```javascript
const hash = cipher.hash('your-input-string', 'sha256');
```

#### `CheckClientHeaders(clientAppKey, clientAppToken)`

Checks the validity of client headers.

```javascript
cipher.CheckClientHeaders(clientAppKey, clientAppToken)
    .then(isValid => console.log(isValid))
    .catch(error => console.error(error));
```

#### `createJWT(payload, jwtPrivateKey)`

Creates a JWT with the given payload and private key.

```javascript
cipher.createJWT(payload, jwtPrivateKey)
    .then(token => console.log(token))
    .catch(error => console.error(error));
```

#### `getSessionData(JWTtoken)`

Gets session data from a JWT.

```javascript
cipher.getSessionData(JWTtoken)
    .then(sessionData => console.log(sessionData))
    .catch(error => console.error(error));
```

#### `validateJWT(ip, jwt, jwtpublickey)`

Validates a JWT with the given IP and public key.

```javascript
cipher.validateJWT(ip, jwt, jwtpublickey)
    .then(isValid => console.log(isValid))
    .catch(error => console.error(error));
```

#### `RSAGenerateKeyPair([encodingPrivateKeyType], [encodingFormatBoth], [encodingPublicKeyType], [bitLength])`

Generates an RSA key pair.

```javascript
cipher.RSAGenerateKeyPair()
    .then(([publicKey, privateKey]) => console.log(publicKey, privateKey))
    .catch(error => console.error(error));
```

#### `RSAsignDocument(privateKey, dataToSign, [encodingFormat], [encodingType])`

Signs data using RSA.

```javascript
cipher.RSAsignDocument(privateKey, dataToSign)
    .then(signature => console.log(signature))
    .catch(error => console.error(error));
```

#### `RSAverifySignature(publicKey, dataToVerify, signature, [encodingFormat], [publicKeyType])`

Verifies an RSA signature.

```javascript
cipher.RSAverifySignature(publicKey, dataToVerify, signature)
    .then(isValid => console.log(isValid))
    .catch(error => console.error(error));
```

#### `AES256encrypt(text, salt)`

Encrypts text using AES-256-CBC.

```javascript
cipher.AES256encrypt('your-text', 'your-salt')
    .then(encryptedText => console.log(encryptedText))
    .catch(error => console.error(error));
```

#### `AES256decrypt(cryptedText, salt)`

Decrypts text using AES-256-CBC.

```javascript
cipher.AES256decrypt(encryptedText, 'your-salt')
    .then(decryptedText => console.log(decryptedText))
    .catch(error => console.error(error));
```

## License

This project is licensed under the MIT License.

