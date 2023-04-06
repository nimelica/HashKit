#include "sha256.h"

#define A 0x6a09e667
#define B 0xbb67ae85
#define C 0x3c6ef372
#define D 0xa54ff53a
#define E 0x510e527f
#define F 0x9b05688c
#define G 0x1f83d9ab
#define H 0x5be0cd19

// define constants
static uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


uint32_t ROTR(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

void sha256(uint8_t *message, size_t message_len, uint8_t *digest) {
    // Pre-processing: padding the input message.
    uint8_t padded_msg[64];
    size_t padded_len;
    size_t i, j;
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h, temp1, temp2;
    uint32_t h0, h1, h2, h3, h4, h5, h6, h7;

    // Initialize variables
    h0 = A;
    h1 = B;
    h2 = C;
    h3 = D;
    h4 = E;
    h5 = F;
    h6 = G;
    h7 = H;

    // 1) Pre-processing
    // 1.a) Calculate padded length
    padded_len = ((message_len + 8) / 64 + 1) * 64;

    // 1.b) Copy message to padded message buffer
    memset(padded_msg, 0, padded_len);
    memcpy(padded_msg, message, message_len);

    // 1.c) add +0 to initial_len because we have already added the '1' bit in the previous step to the end of the initial_msg. This means that we need to start appending '0' bits from the next index 
    padded_msg[message_len] = 0x80;

    // 1.d) Add message length to padded message buffer
    // big-endian byte order
    uint64_t bits_len = (uint64_t) message_len * 8;
    padded_msg[padded_len - 8] = (bits_len >> 56) & 0xff;
    padded_msg[padded_len - 7] = (bits_len >> 48) & 0xff;
    padded_msg[padded_len - 6] = (bits_len >> 40) & 0xff;
    padded_msg[padded_len - 5] = (bits_len >> 32) & 0xff;
    padded_msg[padded_len - 4] = (bits_len >> 24) & 0xff;
    padded_msg[padded_len - 3] = (bits_len >> 16) & 0xff;
    padded_msg[padded_len - 2] = (bits_len >> 8) & 0xff;
    padded_msg[padded_len - 1] = bits_len & 0xff;

    // 2) Process message in 512-bit chunks
    for (i = 0; i < padded_len; i += 64) {
         for (j = 0; j < 16; j++) {
              w[j] = (uint32_t)(padded_msg[i + j * 4] << 24) |
                 (uint32_t)(padded_msg[i + j * 4 + 1] << 16) |
                 (uint32_t)(padded_msg[i + j * 4 + 2] << 8) |
                 (uint32_t)(padded_msg[i + j * 4 + 3]);
         }

         for (j = 16; j < 64; j++) {
             // s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)
             uint32_t s0 = ROTR(w[j-15], 7) ^ ROTR(w[j-15], 18) ^ (w[j-15] >> 3);
             
// s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
             uint32_t s1 = ROTR(w[j-2], 17) ^ ROTR(w[j-2], 19) ^ (w[j-2] >> 10);
             // w[i] := w[i-16] + s0 + w[i-7] + s1
             w[j] = w[j-16] + s0 + w[j-7] + s1;
         } 

         a = h0;
         b = h1;
         c = h2;
         d = h3;
         e = h4;
         f = h5;
         g = h6;
         h = h7;
         
         for (j = 0; j < 64; j++) {
             //S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
             uint32_t S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
             //ch := (e and f) xor ((not e) and g)
             uint32_t ch = (e & f) ^ ((~e) & g);
             //temp1 := h + S1 + ch + k[i] + w[i]
             temp1 = h + S1 + ch + k[j] + w[j];
             //S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
             uint32_t S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
             //maj := (a and b) xor (a and c) xor (b and c)
             uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
             //temp2 := S0 + maj
             temp2 = S0 + maj;

             // Update working variables
             h = g;
             g = f;
             f = e;
             e = d + temp1;
             d = c;
             c = b;
             b = a;
             a = temp1 + temp2;
         }

         h0 += a;
         h1 += b;
         h2 += c;
         h3 += d;
         h4 += e;
         h5 += f;
         h6 += g;
         h7 += h;
    }
    //Produce the final hash value (big-endian):
    //digest := hash := h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7
    // Step 5: Produce the final hash value (big-endian)
    // Produce the final hash value
    // Produce the final hash value (big-endian)
    uint32_t hh[] = {h0, h1, h2, h3, h4, h5, h6, h7};

    for (int i = 0; i < 8; i++) {
        digest[i*4] = (hh[i] >> 24) & 0xff;
        digest[i*4+1] = (hh[i] >> 16) & 0xff;
        digest[i*4+2] = (hh[i] >> 8) & 0xff;
        digest[i*4+3] = hh[i] & 0xff;
    }
    /*
    digest[0] = (h0 >> 24) & 0xff;
    digest[1] = (h0 >> 16) & 0xff;
    digest[2] = (h0 >> 8) & 0xff;
    digest[3] = h0 & 0xff;
    digest[4] = (h1 >> 24) & 0xff;
    digest[5] = (h1 >> 16) & 0xff;
    digest[6] = (h1 >> 8) & 0xff;
    digest[7] = h1 & 0xff;
    digest[8] = (h2 >> 24) & 0xff;
    digest[9] = (h2 >> 16) & 0xff;
    digest[10] = (h2 >> 8) & 0xff;
    digest[11] = h2 & 0xff;
    digest[12] = (h3 >> 24) & 0xff;
    digest[13] = (h3 >> 16) & 0xff;
    digest[14] = (h3 >> 8) & 0xff;
    digest[15] = h3 & 0xff;
    digest[16] = (h4 >> 24) & 0xff;
    digest[17] = (h4 >> 16) & 0xff;
    digest[18] = (h4 >> 8) & 0xff;
    digest[19] = h4 & 0xff;
    digest[20] = (h5 >> 24) & 0xff;
    digest[21] = (h5 >> 16) & 0xff;
    digest[22] = (h5 >> 8) & 0xff;
    digest[23] = h5 & 0xff;
    digest[24] = (h6 >> 24) & 0xff;
    digest[25] = (h6 >> 16) & 0xff;
    digest[26] = (h6 >> 8) & 0xff;
    digest[27] = h6 & 0xff;
    digest[28] = (h7 >> 24) & 0xff;
    digest[29] = (h7 >> 16) & 0xff;
    digest[30] = (h7 >> 8) & 0xff;
    digest[31] = h7 & 0xff;
*/
}


