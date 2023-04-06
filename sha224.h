#ifndef SHA224_H
#define SHA224_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

void sha224(uint8_t *message, size_t message_len, uint8_t *digest);
uint32_t ROTRIGHT(uint32_t x, uint32_t n);

#endif
     
