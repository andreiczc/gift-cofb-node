#include <utility>

extern "C" {
#include "gift_cofb.h"
}

#include "cipher.hpp"

std::unique_ptr<byte[]> encrypt(const byte *plaintext,
                                const size_t plaintextLength,
                                const byte *additionalData,
                                const size_t additionalDataLength,
                                const byte *nonce, const byte *key) {
  auto result = std::unique_ptr<byte[]>(new byte[plaintextLength + BLOCK_SIZE]);
  auto resultSize = 0ull;

  crypto_aead_encrypt(result.get(), &resultSize, plaintext, plaintextLength,
                      additionalData, additionalDataLength, nonce, key);

  return result;
}