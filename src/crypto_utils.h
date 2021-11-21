#ifndef _CRYPTO_UTILS_H
#define _CRYPTO_UTILS_H

void ascii2byte(const char *hexstring, unsigned char *bytearray);

void byte2ascii(unsigned char *bytearray, short inputLen, char *hexstring);

#endif // _CRYPTO_UTILS_H