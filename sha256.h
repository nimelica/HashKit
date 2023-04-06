#ifndef SHA256_H
#define SHA256_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

void sha256(uint8_t *message, size_t message_len, uint8_t *digest);
uint32_t ROTR(uint32_t x, uint32_t n);

#endif
