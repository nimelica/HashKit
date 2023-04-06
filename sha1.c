#include "sha1.h"

#define LEFT_ROTATE(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
// Initialize Constants
#define A 0x67452301
#define B 0xEFCDAB89
#define C 0x98BADCFE
#define D 0x10325476
#define E 0xC3D2E1F0

void sha1(uint8_t *message, size_t message_len, uint8_t *digest) {
    uint32_t h0, h1, h2, h3, h4;
    uint64_t ml;
    uint8_t padded_msg[64]; //64 bytes because that's the size of the blocks 
    size_t padded_len;
    uint32_t w[80];
    uint32_t a, b, c, d, e, f, k, temp;
    size_t i, j;

    // Initialize variables
    h0 = A;
    h1 = B;
    h2 = C;
    h3 = D;
    h4 = E;

    // Pre-processing
    // Calculate padded length
    padded_len = message_len;
    // Incrementing new_len by 1 until it becomes congruent to 448 bits modulo 512 bits
    while (padded_len % 64 != 56) {
        padded_len++;
    }
    padded_len += 8; //(add one byte)

    // Copy message to padded message buffer
    memcpy(padded_msg, message, message_len);
    padded_msg[message_len] = 0x80;

    // add +1 to initial_len because we have already added the '1' bit in the previous step to the end of the initial_msg. This means that we need to start appending '0' bits from the next index 
    for (i = message_len + 1; i < padded_len - 8; i++) {
        padded_msg[i] = 0x00;
    }

    // Add message length to padded message buffer
    // big-endian byte order
    ml = (uint64_t)message_len * 8;
    for (i = 0; i < 8; i++) {
       padded_msg[padded_len - 8 + i] = (uint8_t)(ml >> (56 - (i * 8)));
    }
    // Process message in 512-bit chunks
    for (i = 0; i < padded_len; i += 64) {
        // Break chunk into sixteen 32-bit big-endian words
        for (j = 0; j < 16; j++) {
            w[j] = (padded_msg[i + j * 4] << 24) |
                   (padded_msg[i + j * 4 + 1] << 16) |
                   (padded_msg[i + j * 4 + 2] << 8) |
                   (padded_msg[i + j * 4 + 3]);
        }

        // Extend sixteen 32-bit words into eighty 32-bit words
        for (j = 16; j < 80; j++) {
            w[j] = LEFT_ROTATE((w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16]), 1);
        }

        // Initialize hash value for this chunk
        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;

        // Main loop
        for (j = 0; j < 80; j++) {
            if (j <= 19) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (j <= 39) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (j <= 59) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
        temp = LEFT_ROTATE(a, 5) + f + e + k + w[j];
        e = d;
        d = c;
        c = LEFT_ROTATE(b, 30);
        b = a;
        a = temp;
    }
    // Add this chunk's hash to result so far
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
}   
    // Store hash value as bytes in output buffer
    digest[0] = (uint8_t)(h0 >> 24);
    digest[1] = (uint8_t)(h0 >> 16);
    digest[2] = (uint8_t)(h0 >> 8);
    digest[3] = (uint8_t)h0;
    digest[4] = (uint8_t)(h1 >> 24);
    digest[5] = (uint8_t)(h1 >> 16);
    digest[6] = (uint8_t)(h1 >> 8);
    digest[7] = (uint8_t)h1;
    digest[8] = (uint8_t)(h2 >> 24);
    digest[9] = (uint8_t)(h2 >> 16);
    digest[10] = (uint8_t)(h2 >> 8);
    digest[11] = (uint8_t)h2;
    digest[12] = (uint8_t)(h3 >> 24);
    digest[13] = (uint8_t)(h3 >> 16);
    digest[14] = (uint8_t)(h3 >> 8);
    digest[15] = (uint8_t)h3;
    digest[16] = (uint8_t)(h4 >> 24);
    digest[17] = (uint8_t)(h4 >> 16);
    digest[18] = (uint8_t)(h4 >> 8);
    digest[19] = (uint8_t)h4;
}
 
