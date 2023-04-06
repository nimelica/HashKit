#ifndef MD5_H
#define MD5_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

uint32_t bytes_to_uint32(const uint8_t *bytes);
void uint32_to_little_endian_bytes(uint32_t val, uint8_t *bytes);
void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest);
#endif
