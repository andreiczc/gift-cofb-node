const addon = require("../gift_cofb");

const plaintext = new Uint8Array([65, 66, 67]);
const key = new Uint8Array([
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
]);
const nonce = new Uint8Array([
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
]);
const ad = new Uint8Array([]);

const ciphertext = addon.encrypt(plaintext, key, nonce, ad);

const plaintextHex = addon.decrypt(ciphertext, key, nonce, ad);
let plaintextRestored = "";
plaintextHex.forEach(
  (value) => (plaintextRestored += String.fromCharCode(value))
);

console.log(`Restored plaintext ${plaintextRestored}`);
