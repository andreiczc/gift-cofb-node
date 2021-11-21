#ifndef _GIFT_COFB_H
#define _GIFT_COFB_H

#define BLOCK_SIZE 16
#define COFB_ENCRYPT 1
#define COFB_DECRYPT 0
#define CRYPTO_BYTES 64
#define PAYLOAD_LENGTH 150

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *npub, const unsigned char *k);

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                        const unsigned char *c, unsigned long long clen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *npub, const unsigned char *k);

#endif // _GIFT_COFB_H