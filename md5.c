#include "md5.h"

static uint32_t k[] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                       0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                       0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                       0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                       0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                       0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                       0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                       0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                       0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                       0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                       0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                       0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                       0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                       0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                       0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                       0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};


// the per-round shift amounts
const uint32_t r[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                      5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
 
// leftrotate
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

#define A 0x67452301
#define B 0xefcdab89
#define C 0x98badcfe
#define D 0x10325476

// Convert from bytes (little-endian) to 32-bit unsigned integer
uint32_t bytes_to_uint32(const uint8_t *bytes) {
    uint32_t val = 0;
    val |= ((uint32_t) bytes[0]);
    val |= ((uint32_t) bytes[1]) << 8;
    val |= ((uint32_t) bytes[2]) << 16;
    val |= ((uint32_t) bytes[3]) << 24;
    return val;
}

void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest) {
    uint32_t h0, h1, h2, h3;
 
    // Message (to prepare)
    uint8_t *msg = NULL;
    uint32_t w[16];
    uint32_t a, b, c, d, i, f, g, temp;
 
    // Initialize variables 
    h0 = A;
    h1 = B;
    h2 = C;
    h3 = D;
 
    //Pre-processing:
    //append "1" bit to message    
    //append "0" bits until message length in bits ≡ 448 (mod 512)
    //append little-endian at the end
 
    size_t new_len = initial_len + 1; //(byte)
    while (new_len % (512/8) != (448/8)) {
	    new_len++;
    }

    msg = (uint8_t*)malloc(new_len + 8);
    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 0x80; // append the "1" bit; most significant bit is "first"

    for (size_t i = initial_len + 1; i < new_len; i++) {
	    msg[i] = 0;
    }
    
    uint64_t msg_len_bits = initial_len * 8;
    // Append the length in little-endian format
    // Since each byte has 8 bits, we need to shift the integer right by 8, 16, 24, and so on to extract the individual bytes.
    msg[new_len] = (uint8_t)msg_len_bits;
    msg[new_len+1] = (uint8_t)(msg_len_bits >> 8);
    msg[new_len+2] = (uint8_t)(msg_len_bits >> 16);
    msg[new_len+3] = (uint8_t)(msg_len_bits >> 24);
    msg[new_len+4] = (uint8_t)(msg_len_bits >> 32);
    msg[new_len+5] = (uint8_t)(msg_len_bits >> 40);
    msg[new_len+6] = (uint8_t)(msg_len_bits >> 48);
    msg[new_len+7] = (uint8_t)(msg_len_bits >> 56);

    // Process the message in successive 512-bit chunks:
    // loop through each 64 byte --> 512 bits (so pad is gonna divided as 512 bits)
    for(size_t offset=0; offset<new_len; offset += 64) {
 
        // break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
        for (i = 0; i < 16; i++)
            w[i] = bytes_to_uint32(msg + offset + i*4);
 
        // Initialize hash value for this chunk:
        a = h0;
        b = h1;
        c = h2;
        d = h3;
 
        // Main loop:
        for(i = 0; i<64; i++) {
 
            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5*i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3*i + 5) % 16;          
            } else {
                f = c ^ (b | (~d));
                g = (7*i) % 16;
            }
 
            temp = d;
            d = c;
            c = b;
            b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
            a = temp;
        }
 
        // Concatenate hash values to form 128-bit hash value
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }
 
    // cleanup
    free(msg);
 
    //var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
    uint32_to_little_endian_bytes(h0, digest);
    uint32_to_little_endian_bytes(h1, digest + 4);
    uint32_to_little_endian_bytes(h2, digest + 8);
    uint32_to_little_endian_bytes(h3, digest + 12);
}

void uint32_to_little_endian_bytes(uint32_t val, uint8_t *bytes) {
    // Extract the least significant byte and store it at the first index of the byte array
    bytes[0] = (uint8_t) val;
    // Extract the second least significant byte and store it at the second index of the byte array
    bytes[1] = (uint8_t) (val >> 8);
    // Extract the third least significant byte and store it at the third index of the byte array
    bytes[2] = (uint8_t) (val >> 16);
    // Extract the most significant byte and store it at the fourth index of the byte array
    bytes[3] = (uint8_t) (val >> 24);
}


