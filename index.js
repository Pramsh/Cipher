const crypto = require('crypto');
const { Cipher } = require('./Cypher');
const c = new Cipher();
// Function to generate RSA keys and sign a variable's content
async function generateRSAKeyAndSign(content) {

    // Convert the content to a buffer if it's not already
    const  [ publicKey, privateKey ] = await c.RSAGenerateKeyPair()
    const signature = await c.RSAsignDocument(privateKey, content)
    return {
        signature: signature, 
        publicKey: publicKey  
    };
}

const action = async() => {
    // Example variable content to sign
    const content = 'This is a secret message';
    
    // Generate RSA keys and sign the content
    const { signature, publicKey } = await generateRSAKeyAndSign(content);
    
    console.log('Signature:', signature);
    console.log('Public Key:', publicKey);
    
    // Verify the signature
    // const isVerified = verifySignature(content, signature, publicKey);
    const isVerified = await c.RSAverifySignature(publicKey, content, signature)
    console.log('Signature Verified:', isVerified);

}
action()
