const addon = require("./build/Debug/addon");

function encrypt(plaintext, key, nonce, ad) {
  return addon.encrypt(plaintext, key, nonce, ad);
}

module.exports = { encrypt };
