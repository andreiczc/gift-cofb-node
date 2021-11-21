#include <stdio.h>

#include "crypto_utils.h"

static unsigned char ascii2byte_digit(char input) {
  if (input >= '0' && input <= '9') {
    input -= 48;
  } else if (input >= 'A' && input <= 'Z') {
    input -= 55;
  } else {
    input -= 87;
  }

  return input;
}

static char byte2ascii_digit(unsigned char input) {
  if (input < 10) {
    input += 48;
  } else {
    input += 55;
  }

  return input;
}

void ascii2byte(const char *hexstring, unsigned char *bytearray) {
  int idx = 0;

  while (*hexstring) {
    char major = ascii2byte_digit(hexstring[0]);
    char minor = ascii2byte_digit(hexstring[1]);

    bytearray[idx++] = major * 16 + minor;

    hexstring += 2 * sizeof(char);
  }
}

void byte2ascii(unsigned char *bytearray, short inputLen, char *hexstring) {
  for (short i = 0; i < inputLen; ++i) {
    int hexIdx = i * 2;

    short major = bytearray[i] / 16;
    short minor = bytearray[i] % 16;

    hexstring[hexIdx] = byte2ascii_digit(major);
    hexstring[hexIdx + 1] = byte2ascii_digit(minor);
  }
}