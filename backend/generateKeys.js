const forge = require('node-forge');

// Generar un par de claves RSA
const keys = forge.pki.rsa.generateKeyPair({ bits: 2048 });

// Obtener la clave pública y privada en formato PEM
const publicKeyPem = forge.pki.publicKeyToPem(keys.publicKey);
const privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);

// Imprimir las claves generadas
console.log('Clave pública:');
console.log(publicKeyPem);

console.log('\nClave privada:');
console.log(privateKeyPem);
