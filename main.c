#include <stdio.h>
#include "sha256.h"
#include "sha224.h"
#include "sha1.h"
#include "md5.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: ./main <string>\n");
        return 1;
    }

    char *input = argv[1];
    printf("\n");
    printf("Message is: %s\n", input);
    uint8_t sha1_digest[20];
    uint8_t md5_digest[16];
    uint8_t sha256_digest[32];
    uint8_t sha224_digest[32];

    sha1((uint8_t*)input, strlen(input), sha1_digest);
    md5((uint8_t*)input, strlen(input), md5_digest);
    sha256((uint8_t*)input, strlen(input), sha256_digest);
    sha224((uint8_t*)input, strlen(input), sha224_digest);

    printf("MD5 digest: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", md5_digest[i]);
    }
    printf("\n");

    printf("SHA1 digest: ");
    for (int i = 0; i < 20; i++) {
        printf("%02x", sha1_digest[i]);
    }
    printf("\n");

    printf("SHA256 digest: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", sha256_digest[i]);
    }
    printf("\n");

    printf("SHA224 digest: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", sha224_digest[i]);
    }
    printf("\n");
    printf("\n");
    return 0;
}

