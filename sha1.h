#ifndef SHA1_H
#define SHA1_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

void sha1(uint8_t *message, size_t message_len, uint8_t *digest);
#endif
