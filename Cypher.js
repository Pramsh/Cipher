const { createCipheriv, createDecipheriv, pbkdf2Sync, generateKeyPair, createVerify, createSign, createHash, constants, sign, verify } = require('crypto');

/**
 * @class Cipher
 * @description Class providing cryptographic functionalities.
 */
class Cipher {
    #aes256Key;
    #aes256Iv;
    #appKey;
    #appToken;

    /**
     * @constructor
     * @param {string} aes256Key - The AES-256 key.
     * @param {string} aes256Iv - The AES-256 initialization vector.
     * @param {string} appKey - The application key.
     * @param {string} appToken - The application token.
     */
    constructor(aes256Key, aes256Iv, appKey, appToken) {
        this.#aes256Key = aes256Key;
        this.#aes256Iv = aes256Iv;
        this.#appKey = appKey;
        this.#appToken = appToken;
    }
    /**
     * Generates a hash of the input using the specified algorithm.
     * @param {string} input - The input string to hash.
     * @param {string} [algorithm='sha256'] - The hash algorithm to use.
     * @returns {string} - The hash of the input.
     */
    hash(input, algorithm = 'sha256') {
        const hash = createHash(algorithm);
        hash.update(input);
        return hash.digest('hex');
    }

    #isValidJSON(str) {
        if (typeof str !== 'string') return false;
        str = str.trim();
        if (str === '') return false;
        try {
            JSON.parse(str);
        } catch (e) {
            return false; // If parsing fails, return false
        }
        return true; // If parsing succeeds, return true
    }

    /**
     * Checks client headers for validity.
     * @param {string} clientAppKey - The client app key.
     * @param {string} clientAppToken - The client app token.
     * @returns {Promise<boolean>} - Whether the headers are valid.
     */
    CheckClientHeaders(clientAppKey, clientAppToken) {
        return new Promise((resolve, reject) => {
            if (clientAppKey === this.#appKey && clientAppToken === this.#appToken) {
                resolve(true);
            } else {
                if (!this.#appKey || !this.#appToken) {
                    reject({
                        message: "To use this service, you need to set the app key and token on the class instance",
                        status: 500
                    });
                } else if (!clientAppKey || !clientAppToken) {
                    reject({
                        message: "Missing credentials",
                        status: 401
                    });
                } else {
                    reject({
                        message: "Wrong credentials",
                        status: 403
                    });
                }
            }
        });
    }

    /**
     * Creates a JWT.
     * @param {Object} payload - The payload of the JWT.
     * @param {string} jwtPrivateKey - The private key to sign the JWT with.
     * @returns {Promise<string>} - The generated JWT.
     */
    async createJWT(payload, jwtPrivateKey) {
        return new Promise(async (resolve, reject) => {
            try {
                const header = JSON.stringify({ alg: 'RS256', typ: 'JWT' });
                const base64Header = Buffer.from(header).toString('base64url');
                const base64Payload = Buffer.from(JSON.stringify(payload)).toString('base64url');

                const signatureInput = `${base64Header}.${base64Payload}`;
                const signature = sign('RSA-SHA256', Buffer.from(signatureInput), {
                    key: jwtPrivateKey,
                    padding: constants.RSA_PKCS1_PSS_PADDING,
                });

                const base64Signature = signature.toString('base64url');
                resolve(`${signatureInput}.${base64Signature}`);
            } catch (error) {
                reject({ status: 401, message: "Error creating JWT -- " + (error?.message ?? JSON.stringify(error)) });
            }
        });
    }

    /**
     * Decodes a JWT.
     * @param {string} JWTtoken - The JWT to decode.
     * @returns {Promise<Array>} - The decoded payload, signature input, and signature.
     */
    async #decodeJWT(JWTtoken) {
        return new Promise((resolve, reject) => {
            try {
                const [header64, payload64, signature64] = JWTtoken.split('.');
                const signatureInput = `${header64}.${payload64}`;
                // Decode the header and payload
                const payload = JSON.parse(Buffer.from(payload64, 'base64url').toString());
                resolve([payload, signatureInput, signature64]);
            } catch (error) {
                reject({ status: 401, message: "Error decoding JWT -- " + (error?.message ?? JSON.stringify(error)) });
            }
        });
    }

    /**
     * Gets session data from a JWT.
     * @param {string} JWTtoken - The JWT to get session data from.
     * @returns {Promise<Object>} - The session data.
     */
    async getSessionData(JWTtoken) {
        return new Promise(async (resolve, reject) => {
            try {
                const [payload] = await this.#decodeJWT(JWTtoken);

                if (payload) {
                    resolve(payload);
                } else {
                    reject({ status: 401, message: "Invalid session" });
                }
            } catch (error) {
                reject({ status: error?.status ?? 500, message: "Error getting session -- " + (error?.message ?? JSON.stringify(error)) });
            }
        });
    }

    /**
     * Validates a JWT.
     * Called from client, returns always a token, if fails back to login.
     * @param {string} ip - The IP address of the client.
     * @param {string} jwt - The JWT to validate.
     * @param {string} jwtpublickey - The public key to validate the JWT with.
     * @returns {Promise<Object|boolean>} - The validated session data or false if invalid.
     */
    async validateJWT(ip, jwt, jwtpublickey) {
        return new Promise(async (resolve, reject) => {
            try {
                const [payload, signatureInput, signature64] = await this.#decodeJWT(jwt);

                if (payload.ip !== ip) {
                    return reject({ status: 401, message: "Changed IP" });
                }

                // Verify the signature
                const isValid = verify(
                    'RSA-SHA256',
                    Buffer.from(signatureInput), // Input made of headers and payloads
                    {
                        key: jwtpublickey,
                        padding: constants.RSA_PKCS1_PSS_PADDING,
                    },
                    Buffer.from(signature64, 'base64url') // Signature itself
                );

                resolve(isValid ? payload : false);
            } catch (error) {
                resolve(false);
            }
        });
    }

    /**
     * Generates an RSA key pair.
     * @param {string} [encodingPrivateKeyType='pkcs8'] - The encoding type for the private key.
     * @param {string} [encodingFormatBoth='pem'] - The encoding format for both keys.
     * @param {string} [encodingPublicKeyType='spki'] - The encoding type for the public key.
     * @param {number} [bitLength=2048] - The bit length of the key.
     * @returns {Promise<Array<string>>} - The generated RSA key pair [publicKey, privateKey].
     */
    async RSAGenerateKeyPair(encodingPrivateKeyType = 'pkcs8', encodingFormatBoth = 'pem', encodingPublicKeyType = 'spki', bitLength = 2048) {
        return new Promise((resolve, reject) => {
            generateKeyPair('rsa', {
                modulusLength: bitLength, // Length of key in bits
                publicKeyEncoding: {
                    type: encodingPublicKeyType, // Recommended to use 'spki' for public key
                    format: encodingFormatBoth, // Format for public key
                },
                privateKeyEncoding: {
                    type: encodingPrivateKeyType, // Recommended to use 'pkcs8' for private key
                    format: encodingFormatBoth, // Format for private key
                }
            }, (err, publicKey, privateKey) => {
                if (err) {
                    return reject(err); // Reject the promise on error
                }
                resolve([publicKey, privateKey]); // Resolve with the keys
            });
        });
    }

    /**
     * Signs data using RSA.
     * @param {string|Buffer} privateKey - The private key to sign with.
     * @param {string|Buffer} dataToSign - The data to sign.
     * @param {string} [encodingFormat='pem'] - The encoding format of the key.
     * @param {string} [encodingType='pkcs8'] - The type of the key.
     * @returns {Promise<string|Buffer>} - The generated signature.
     */
    async RSAsignDocument(privateKey, dataToSign, encodingFormat = 'pem', encodingType = 'pkcs8') {
        return new Promise((resolve, reject) => {
            try {
                const contentBuffer = Buffer.isBuffer(dataToSign) ? dataToSign : Buffer.from(dataToSign);
                const sign = createSign('SHA256');
                sign.update(contentBuffer);
                sign.end();
                let signature;
                if (encodingFormat === 'der' && encodingType === 'pkcs8') {
                    signature = sign.sign({
                        key: privateKey,
                        format: encodingFormat,
                        type: encodingType
                    });
                } else {
                    signature = sign.sign(privateKey, 'base64');
                }
                resolve(signature);
            } catch (error) {
                console.log(error);
                reject(error);
            }
        });
    }

    /**
     * Verifies an RSA signature.
     * @param {string|Buffer} publicKey - The public key to verify with.
     * @param {string|Buffer} dataToVerify - The data to verify.
     * @param {string|Buffer} signature - The signature to verify.
     * @param {string} [encodingFormat='pem'] - The encoding format of the key.
     * @param {string} [publicKeyType='spki'] - The type of the key.
     * @returns {Promise<boolean>} - Whether the signature is valid.
     */
    async RSAverifySignature(publicKey, dataToVerify, signature, encodingFormat = 'pem', publicKeyType = 'spki') {
        return new Promise((resolve, reject) => {
            try {
                const contentBuffer = Buffer.isBuffer(dataToVerify) ? dataToVerify : Buffer.from(dataToVerify);
                const verify = createVerify('SHA256');
                verify.update(contentBuffer);
                verify.end();
                let isValid;
                if (encodingFormat === 'der' && publicKeyType === 'spki') {
                    isValid = verify.verify({
                        key: publicKey,
                        format: encodingFormat,
                        type: publicKeyType
                    }, signature);
                } else {
                    isValid = verify.verify(publicKey, signature, 'base64');
                }
                resolve(isValid);
            } catch (error) {
                reject({ message: "Error verifying signature -- details: " + (error?.message ?? JSON.stringify(error)), status: 500 });
            }
        });
    }

    /**
     * Generates a key and IV for AES encryption.
     * @param {string} salt - The salt used for key derivation.
     * @returns {Array<Buffer>} - The derived key and IV.
     */
    #generateKeyAndIv(salt) {
        return [pbkdf2Sync(this.#aes256Key, salt, 100000, 32, 'sha512'), pbkdf2Sync(this.#aes256Iv, salt, 100000, 16, 'sha512')];
    }

    /**
     * Encrypts text using AES-256-CBC.
     * @param {string|Object} text - The text to encrypt.
     * @param {string} salt - The salt used for key derivation.
     * @returns {Promise<string>} - The encrypted text.
     */
    async AES256encrypt(text, salt) {
        return new Promise((resolve, reject) => {
            if (this.#aes256Key === undefined || this.#aes256Iv === undefined)
                return reject({ message: "Class must be initialized with AES-256 key and IV", status: 500 });
            try {
                const [key, iv] = this.#generateKeyAndIv(salt);
                const cipher = createCipheriv('aes-256-cbc', key, iv);
                if (typeof text === "object") {
                    text = JSON.stringify(text);
                }
                resolve(cipher.update(text, 'utf-8', 'hex') + cipher.final('hex'));
            } catch (error) {
                reject({ message: "An error occurred while AES encrypting -- details: " + error?.message, status: 403 });
            }
        });
    }

    /**
     * Decrypts text using AES-256-CBC.
     * @param {string} cryptedText - The encrypted text to decrypt.
     * @param {string} salt - The salt used for key derivation.
     * @returns {Promise<string|Object>} - The decrypted text or JSON object.
     */
    async AES256decrypt(cryptedText, salt) {
        if (this.#aes256Key === undefined || this.#aes256Iv === undefined)
            return reject({ message: "Class must be initialized with AES-256 key and IV", status: 500 });
        return new Promise((resolve, reject) => {
            try {
                const [key, iv] = this.#generateKeyAndIv(salt);
                const decipher = createDecipheriv('aes-256-cbc', key, iv);
                const decryptedValue = decipher.update(cryptedText, 'hex', 'utf8') + decipher.final('utf8');
                let stringifyIfNeeded = this.#isValidJSON(decryptedValue) ? JSON.parse(decryptedValue) : decryptedValue;
                resolve(stringifyIfNeeded);
            } catch (error) {
                reject({ message: "Error trying to AES256decrypt -- details: " + (error?.message ?? JSON.stringify(error)), status: 500 });
            }
        });
    }
}

module.exports = { Cipher };
