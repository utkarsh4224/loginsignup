const crypto = require('crypto');
const key = crypto.randomBytes(32).toString('hex'); // Generates a 32-byte key
console.log(key); // Output the key to use in your .env file
