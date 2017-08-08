/*
 *  ghetto asr passphrase
 *
 *  Copyright (c) 2015 xerub
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#define DKIOCGETBLOCKSIZE                     _IOR('d', 24, uint32_t)
#define DKIOCGETBLOCKCOUNT                    _IOR('d', 25, uint64_t)

static inline uint64_t
u32_to_u64(uint32_t msq, uint32_t lsq)
{
    uint64_t ms = (uint64_t)msq;
    uint64_t ls = (uint64_t)lsq;
    return ls | (ms << 32);
}

int
compar(const void *a, const void *b)
{
    unsigned int _a = *(const unsigned int *)a;
    unsigned int _b = *(const unsigned int *)b;
    if (_a > _b) {
        return 1;
    }
    if (_a < _b) {
        return 0;
    }
    return 0;
}

char *
getpassp(const char *ramdisk, const char *platform)
{
    int fd;
    unsigned long long ramdiskSize;
    unsigned long long v15;
    char v20;
    signed int v21;
    unsigned int v22;
    unsigned int v23;
    unsigned int offsetInBlocks;
    unsigned int chunkInBlocks;
    unsigned int offsetInBytes;
    unsigned int v36;
    unsigned int v38;
    unsigned int v39;
    char *p;
    unsigned long long ramdiskSizeInBlocks;
    char *buf;
#ifdef __APPLE__
    unsigned long long blockCount;
    unsigned int blockSize;
#endif
    SHA256_CTX ctx;
    int v54[10];
    unsigned long long v55[4];
    unsigned int salt[4];
    char pass[65];
    unsigned char digest[32];
    unsigned char md[20];
    int i, j, k;
    unsigned int left;

    fd = open(ramdisk, 0);
    if (fd < 0) {
        fprintf(stderr, "Couldn't open device %s: %s\n", ramdisk, strerror(errno));
        return NULL;
    }
#if 0//def __APPLE__
    if (ioctl(fd, DKIOCGETBLOCKSIZE, &blockSize) <= -1) {
        fprintf(stderr, "Couldn't get block size\n");
        close(fd);
        return NULL;
    }
    if (ioctl(fd, DKIOCGETBLOCKCOUNT, &blockCount) <= -1) {
        fprintf(stderr, "Couldn't get block count\n");
        close(fd);
        return NULL;
    }

    ramdiskSize = blockSize * blockCount;
#else
{
    struct stat st;
    assert(fstat(fd, &st) == 0);
    ramdiskSize = st.st_size;
}
#endif

    if (ramdiskSize >= 0x100000000) {
        fprintf(stderr, "Device %s is larger than 4 GB\n", ramdisk);
        close(fd);
        return NULL;
    }

    ramdiskSizeInBlocks = ramdiskSize >> 9;

    v55[0] = 0xAD79D29DE5E2AC9EULL;
    v55[1] = 0xE6AF2EB19E23925BULL;
    v55[2] = 0x3F1375B4BD88815CULL;
    v55[3] = 0x3BDFF4E5564A9F87ULL;

    SHA1((const unsigned char *)platform, strlen(platform), md);

    v15 = u32_to_u64((md[0] << 24) | (md[1] << 16) | (md[2] << 8) | md[3], (md[4] << 24) | (md[5] << 16) | (md[6] << 8) | md[7]);
    v55[0] += v15;
    v55[1] += v15;
    v55[2] += v15;
    v55[3] += v15;

    for (i = 0; i < 4; i++) {
        salt[i] = v55[i] % ramdiskSize & 0xFFFFFE00;
    }

    qsort(salt, 4, 4, compar);

    v20 = 1;
    v21 = 0;
    k = 0;
    while (v21 < 4) {
        if (v20 & 1) {
            v54[2 * k] = salt[v21];
            v54[2 * k + 1] = 0;
        }
        v22 = salt[v21++];
        if (v21 < 4) {
            v23 = salt[v21] - v22;
            if (v23 < 0x4000) {
                v54[2 * k + 1] += v23;
                v20 = 0;
                continue;
            }
        }
        left = ramdiskSize - v22;
        if (left > 0x4000) {
            left = 0x4000;
        }
        v54[2 * k + 1] += left;
        v20 = 1;
        k++;
    }

    if (ramdiskSize - salt[3] < 0x4000) {
        memmove(&v54[2], v54, 8 * k);
        v54[0] = 0;
        v54[1] = salt[3] + 0x4000 - ramdiskSize;
    }

    buf = malloc(0x100000);
    if (!buf) {
        perror("Couldn't read device");
        close(fd);
        return NULL;
    }

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, v55, 32);
    j = 0;
    for (offsetInBlocks = 0; offsetInBlocks < ramdiskSizeInBlocks; offsetInBlocks += chunkInBlocks) {
        chunkInBlocks = ramdiskSizeInBlocks - offsetInBlocks;

        if (chunkInBlocks > 2048) {
            chunkInBlocks = 2048;
        }

        if (pread(fd, buf, chunkInBlocks << 9, offsetInBlocks << 9) < 0) {
            fprintf(stderr, "Error reading from device %s at offset %X\n", ramdisk, offsetInBlocks << 9);
            break;
        }

        SHA256_Update(&ctx, buf, chunkInBlocks << 9);

        offsetInBytes = offsetInBlocks << 9;
        v36 = (chunkInBlocks << 9) + offsetInBytes;

        for (i = j; i < k; i++) {
            v38 = v54[2 * i];
            v39 = v54[2 * i + 1] + v38;
            if (offsetInBytes >= v39) {
                j = i + 1;
            } else {
                if (v36 <= v38) {
                    break;
                }
                if (offsetInBytes > v38) {
                    v38 = offsetInBytes;
                }
                if (v36 < v39) {
                    v39 = (chunkInBlocks << 9) + offsetInBytes;
                }
                SHA256_Update(&ctx, buf + v38 - offsetInBytes, v39 - v38);
            }
        }
    }

    SHA256_Final(digest, &ctx);

    for (p = pass, i = 0; i < 32; i++, p += 2) {
        snprintf(p, 3, "%02X", digest[i]);
    }

    free(buf);
    close(fd);
    return strdup(pass);
}
