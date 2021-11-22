#ifndef _CIPHER_HPP
#define _CIPHER_HPP

#include <memory>

#define byte unsigned char

std::unique_ptr<byte[]> encrypt(const byte *plaintext,
                                const size_t plaintextLength,
                                const byte *additionalData,
                                const size_t additionalDataLength,
                                const byte *nonce, const byte *key);

std::unique_ptr<byte[]> decrypt(const byte *ciphertext,
                                const size_t ciphertextLength,
                                const byte *additionalData,
                                const size_t additionalDataLength,
                                const byte *nonce, const byte *key);

#endif // _CIPHER_HPP