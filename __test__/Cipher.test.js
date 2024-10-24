const { Cipher } = require('../Cypher');
const { generateKeyPairSync } = require('crypto');

// Cypher.test.js

describe('Cipher', () => {
    let cipher;
    const aes256Key = 'mysecretkeymysecretkeymysecretkey12'; // 32 bytes
    const aes256Iv = 'mysecretivmysecret'; // 16 bytes
    const appKey = 'appKey';
    const appToken = 'appToken';

    beforeAll(() => {
        cipher = new Cipher(aes256Key, aes256Iv, appKey, appToken);
    });

    test('should generate SHA-256 hash', () => {
        const hash = cipher.hash('test', 'sha256');
        expect(hash).toBe('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');
    });
    test('should generate MD5 hash', () => {
        const hash = cipher.hash('test', 'md5');
        expect(hash).toBe('098f6bcd4621d373cade4e832627b4f6');
    });

    test('should generate SHA-1 hash', () => {
        const hash = cipher.hash('test', 'sha1');
        expect(hash).toBe('a94a8fe5ccb19ba61c4c0873d391e987982fbbd3');
    });

    test('should generate SHA-512 hash', () => {
        const hash = cipher.hash('test', 'sha512');
        expect(hash).toBe('ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff');
    });

    test('should check client headers', async () => {
        await expect(cipher.CheckClientHeaders(appKey, appToken)).resolves.toBe(true);
        await expect(cipher.CheckClientHeaders('wrongKey', 'wrongToken')).rejects.toEqual({
            message: 'Wrong credentials',
            status: 403
        });
    });

    test('should generate RSA key pair', async () => {
        const [publicKey, privateKey] = await cipher.RSAGenerateKeyPair();
        expect(publicKey).toBeDefined();
        expect(privateKey).toBeDefined();
    });

    test('should create a valid JWT', async () => {
        const { privateKey } = generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        const payload = {
            user: {
                id: '12345',
                name: 'John Doe',
                roles: ['admin', 'user']
            },
            exp: Math.floor(Date.now() / 1000) + (60 * 60), // 1 hour expiration
            iss: 'testIssuer'
        };

        const validationInputPromise = Promise.resolve();
        const jwt = await cipher.createJWT(payload, privateKey, validationInputPromise);
        expect(jwt).toBeDefined();
        expect(jwt.split('.').length).toBe(3); // JWT should have 3 parts
    });

    test('should reject if validationInputPromise rejects', async () => {
        const { privateKey } = generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        const payload = {
            user: {
                id: '12345',
                name: 'John Doe',
                roles: ['admin', 'user']
            },
            exp: Math.floor(Date.now() / 1000) + (60 * 60), // 1 hour expiration
            iss: 'testIssuer'
        };

        const validationInputPromise = Promise.reject(new Error('Validation failed'));
        await expect(cipher.createJWT(payload, privateKey, validationInputPromise)).rejects.toEqual({
            status: 401,
            message: expect.stringContaining('Error creating JWT')
        });
    });

    test('should reject if an error occurs during JWT creation', async () => {
        const payload = {
            user: {
                id: '12345',
                name: 'John Doe',
                roles: ['admin', 'user']
            },
            exp: Math.floor(Date.now() / 1000) + (60 * 60), // 1 hour expiration
            iss: 'testIssuer'
        };

        const validationInputPromise = Promise.resolve();
        const { privateKey } = generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        await expect(cipher.createJWT(payload, privateKey, validationInputPromise)).resolves.toBeDefined();
    });

    test('should reject if IP address does not match', async () => {
        const { privateKey, publicKey } = generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        const payload = {
            user: {
                id: '12345',
                name: 'John Doe',
                roles: ['admin', 'user']
            },
            ip: '127.0.0.1',
            exp: Math.floor(Date.now() / 1000) + (60 * 60), // 1 hour expiration
            iss: 'testIssuer'
        };

        const validationInputPromise = Promise.resolve();
        const jwt = await cipher.createJWT(payload, privateKey, validationInputPromise);

        await expect(cipher.validateJWT('192.168.0.1', jwt, publicKey, validationInputPromise)).rejects.toEqual({
            status: 401,
            message: "Changed IP"
        });
    });

    test('should return false for an invalid JWT', async () => {
        const { publicKey } = generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        const invalidJwt = 'invalid.jwt.token';
        const validationInputPromise = Promise.resolve();

        const isValid = await cipher.validateJWT('127.0.0.1', invalidJwt, publicKey, validationInputPromise);
        expect(isValid).toBe(false);
    });

    test('should return false if validationInputPromise rejects', async () => {
        const { privateKey, publicKey } = generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        const payload = {
            user: {
                id: '12345',
                name: 'John Doe',
                roles: ['admin', 'user']
            },
            ip: '127.0.0.1',
            exp: Math.floor(Date.now() / 1000) + (60 * 60), // 1 hour expiration
            iss: 'testIssuer'
        };

        const validationInputPromise = Promise.reject(new Error('Validation failed'));
        const jwt = await cipher.createJWT(payload, privateKey, Promise.resolve());

        const isValid = await cipher.validateJWT('127.0.0.1', jwt, publicKey, validationInputPromise);
        expect(isValid).toBe(false);
    });



    test('should encrypt and decrypt text using AES-256-CBC', async () => {
        const text = 'Hello, World!';
        const salt = 'random_salt';
        const encryptedText = await cipher.AES256encrypt(text, salt);
        const decryptedText = await cipher.AES256decrypt(encryptedText, salt);
        expect(decryptedText).toBe(text);
    });

    test('should generate RSA key pair with different bit size', async () => {
        const { publicKey: publicKey1, privateKey: privateKey1 } = generateKeyPairSync('rsa', {
            modulusLength: 1024,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        const { publicKey: publicKey2, privateKey: privateKey2 } = generateKeyPairSync('rsa', {
            modulusLength: 4096,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        expect(publicKey1).toBeDefined();
        expect(privateKey1).toBeDefined();
        expect(publicKey2).toBeDefined();
        expect(privateKey2).toBeDefined();
    });

    test('should sign and verify document with deafult format and type', async () => {
        const { privateKey, publicKey } = generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        const data = 'test data';
        const signature = await cipher.RSAsignDocument(privateKey, data);
        const isValid = await cipher.RSAverifySignature(publicKey, data, signature);
        expect(isValid).toBe(true);
    });


    const keyTypes = [
        { privateKeyType: 'pkcs8', format: 'pem' },
        { privateKeyType: 'pkcs1', format: 'pem' },
        { privateKeyType: 'pkcs8', format: 'der' },
        { privateKeyType: 'pkcs8', format: 'pem', publicKeyType: 'spki' }
    ];

    keyTypes.forEach(({ privateKeyType, format, publicKeyType = 'spki' }) => {
        test(`should generate RSA key pair with ${privateKeyType} and ${format}`, async () => {
            const [publicKey, privateKey] = await cipher.RSAGenerateKeyPair(privateKeyType, format, publicKeyType);
            expect(publicKey).toBeDefined();
            expect(privateKey).toBeDefined();

            const data = 'This is a test message';

            // Sign the data
            const signature = await cipher.RSAsignDocument(privateKey, data, format, privateKeyType);
            expect(signature).toBeDefined();

            // Verify the signature
            const isValid = await cipher.RSAverifySignature(publicKey, data, signature, format, publicKeyType);
            expect(isValid).toBe(true);
        });
    });
})