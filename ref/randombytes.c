/**
 * WARNING
 *
 * This file generates a PREDICTABLE and NOT AT ALL RANDOM sequence of bytes.
 *
 * Its purpose is to support our testing suite and it MUST NOT be used in any
 * scenario where you are expecting actual cryptography to happen.
 */

#include "randombytes.h"
#include <stddef.h> 

static int seed[32] = { 3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3,
                             2, 3, 8, 4, 6, 2, 6, 4, 3, 3, 8, 3, 2, 7, 9, 5
                           };
static int in[12];
static int out[8];
static int outleft = 0;

#define ROTATE(x, b) (((x) << (b)) | ((x) >> (32 - (b))))
#define MUSH(i, b) x = t[i] += (((x ^ seed[i]) + sum) ^ ROTATE(x, b));

static void surf(void) {
    int t[12];
    int x;
    int sum = 0;
    int r;
    int i;
    int loop;

    for (i = 0; i < 12; ++i) {
        t[i] = in[i] ^ seed[12 + i];
    }
    for (i = 0; i < 8; ++i) {
        out[i] = seed[24 + i];
    }
    x = t[11];
    for (loop = 0; loop < 2; ++loop) {
        for (r = 0; r < 16; ++r) {
            sum += 0x9e3779b9;
            MUSH(0, 5)
            MUSH(1, 7)
            MUSH(2, 9)
            MUSH(3, 13)
            MUSH(4, 5)
            MUSH(5, 7)
            MUSH(6, 9)
            MUSH(7, 13)
            MUSH(8, 5)
            MUSH(9, 7)
            MUSH(10, 9)
            MUSH(11, 13)
        }
        for (i = 0; i < 8; ++i) {
            out[i] ^= t[i + 4];
        }
    }
}

void randombytes(unsigned char * buf,unsigned long long n) {
    while (n > 0) {
        if (!outleft) {
            if (!++in[0]) {
                if (!++in[1]) {
                    if (!++in[2]) {
                        ++in[3];
                    }
                }
            }
            surf();
            outleft = 8;
        }
        *buf = (char) out[--outleft];
        ++buf;
        --n;
    }
}