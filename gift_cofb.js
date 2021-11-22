const gift_cofb = require("./build/Debug/gift-cofb");

/**
 *
 * @param {Array} array
 * @returns {String} value in hex
 */
const decimal2Hex = (array) => {
  let accumulator = "";
  array.forEach(
    (value) => (accumulator += value.toString(16).padStart(2, "0"))
  );

  return accumulator;
};

/**
 * Encrypt using the GIFT-COFB lightweight crypto cipher. All params must be in decimal
 *
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {Uint8Array} ad
 * @returns {Uint8Array} ciphertext as an array
 */
function encrypt(plaintext, key, nonce, ad) {
  if (
    plaintext.constructor !== Uint8Array ||
    key.constructor !== Uint8Array ||
    nonce.constructor !== Uint8Array ||
    ad.constructor !== Uint8Array
  ) {
    throw "Invalid arguments";
  }

  const plaintextHex = decimal2Hex(plaintext);
  const keyHex = decimal2Hex(key);
  const nonceHex = decimal2Hex(nonce);
  const adHex = decimal2Hex(ad);

  const ciphertext = gift_cofb.encrypt(plaintextHex, keyHex, nonceHex, adHex);

  const result = new Uint8Array(ciphertext.length / 2);
  const tokens = ciphertext.match(/.{2}/g);

  tokens.forEach((value, idx) => (result[idx] = parseInt(value, 16)));

  return result;
}

/**
 * Decrypt using the GIFT-COFB lightweight crypto cipher. All params must be in decimal
 *
 * @param {Uint8Array} ciphertext
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {Uint8Array} ad
 * @returns {Uint8Array} plaintext as an array
 */
function decrypt(ciphertext, key, nonce, ad) {
  if (
    ciphertext.constructor !== Uint8Array ||
    key.constructor !== Uint8Array ||
    nonce.constructor !== Uint8Array ||
    ad.constructor !== Uint8Array
  ) {
    throw "Invalid arguments";
  }

  const ciphertextHex = decimal2Hex(ciphertext);
  const keyHex = decimal2Hex(key);
  const nonceHex = decimal2Hex(nonce);
  const adHex = decimal2Hex(ad);

  const plaintext = gift_cofb.decrypt(ciphertextHex, keyHex, nonceHex, adHex);

  const result = new Uint8Array(plaintext.length / 2);
  const tokens = plaintext.match(/.{2}/g);

  tokens.forEach((value, idx) => (result[idx] = parseInt(value, 16)));

  return result;
}

module.exports = { encrypt, decrypt };
