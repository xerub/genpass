/*
 *  asr passphrase to rootfs key
 *
 *  Copyright (c) 2010 xerub
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


#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <arpa/inet.h>


#if 1/* little-endian */
#define SWAP64(x) x = (uint64_t)(               \
    ((uint64_t)(((uint8_t *)&(x))[0]) << 56) |  \
    ((uint64_t)(((uint8_t *)&(x))[1]) << 48) |  \
    ((uint64_t)(((uint8_t *)&(x))[2]) << 40) |  \
    ((uint64_t)(((uint8_t *)&(x))[3]) << 32) |  \
    ((uint64_t)(((uint8_t *)&(x))[4]) << 24) |  \
    ((uint64_t)(((uint8_t *)&(x))[5]) << 16) |  \
    ((uint64_t)(((uint8_t *)&(x))[6]) <<  8) |  \
    ((uint64_t)(((uint8_t *)&(x))[7]) <<  0))
#else
#define SWAP64(x) x = *(uint64_t *)&x
#endif
#define SWAP32(x) x = ntohl(x)


#define PACKED __attribute__((packed))

typedef struct {
    uint32_t kdf_algorithm;
    uint32_t kdf_prng_algorithm;
    uint32_t kdf_iteration_count;
    uint32_t kdf_salt_len; /* in bytes */
    uint8_t  kdf_salt[32];
    uint32_t blob_enc_iv_size;
    uint8_t  blob_enc_iv[32];
    uint32_t blob_enc_key_bits;
    uint32_t blob_enc_algorithm;
    uint32_t blob_enc_padding;
    uint32_t blob_enc_mode;
    uint32_t encrypted_keyblob_size;
    uint8_t  encrypted_keyblob[0x30];
    uint8_t  filler[512 - 0x30];
} PACKED blob_t;

typedef struct {
    uint32_t type;
    uint64_t offset;
    uint64_t size;
} PACKED entry_t;

typedef struct {
    unsigned char sig[8];
    uint32_t version;
    uint32_t enc_iv_size;
    uint32_t unk1;
    uint32_t unk2;
    uint32_t unk3;
    uint32_t unk4;
    uint32_t unk5;
    unsigned char uuid[16];
    uint32_t blocksize;
    uint64_t datasize;
    uint64_t dataoffset;
    uint32_t nentries;
    /* entry_t entries[]; */
} PACKED cencrypted_v2_pwheader;


static void
print_hex(const uint8_t *data, uint32_t len)
{
    uint32_t i;
    int more = 0;
    if (len > 64) {
        len = 64;
        more = 1;
    }
    for (i = 0; i < len; i++) {
        if ((i & 7) == 0) {
            printf("\n\t");
        } else {
            printf(" ");
        }
        printf("%02x", data[i]);
    }
    printf("\n");
    if (more) {
        printf("\t...\n");
    }
}


static void
print_key(const char *name, const uint8_t *data, uint32_t len)
{
    uint32_t i;
    printf("%s: ", name);
    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}


static int
check_blob(blob_t *blob, uint8_t *passphrase)
{
    int rv;
    EVP_CIPHER_CTX ctx;
    uint8_t out[0x30];
    int outlen, tmplen;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_DecryptInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, passphrase, &passphrase[24]);
    EVP_DecryptUpdate(&ctx, out, &outlen, blob->encrypted_keyblob, 0x30);
    rv = EVP_DecryptFinal_ex(&ctx, out + outlen, &tmplen);
    EVP_CIPHER_CTX_cleanup(&ctx);
    if (rv) {
        print_key("vfdecrypt key", out, 0x24);
        return 0;
    }
    return -1;
}


static int
parse_v2_header(const char *filename, uint8_t *passphrase)
{
    FILE *f;
    size_t sz;
    uint32_t i;
    entry_t *entries;
    cencrypted_v2_pwheader hdr;

    int rv = -1;

    f = fopen(filename, "rb");
    if (f == NULL) {
        return -1;
    }

    sz = sizeof(cencrypted_v2_pwheader);
    sz = fread(&hdr, 1, sz, f);
    if (sz != sizeof(cencrypted_v2_pwheader)) {
        fclose(f);
        return -1;
    }

    SWAP32(hdr.version);
    SWAP32(hdr.blocksize);
    SWAP64(hdr.datasize);
    SWAP64(hdr.dataoffset);
    SWAP32(hdr.nentries);

    if (hdr.version != 2) {
        fclose(f);
        return -1;
    }

#if VERBOSE
    printf("sig\t%.8s\n", hdr.sig);
    printf("blocksize\t0x%"PRIX32"\n", hdr.blocksize);
    printf("datasize\t%"PRIu64"\n", hdr.datasize);
    printf("dataoffset\t%"PRIu64"\n", hdr.dataoffset);
#endif

    sz = hdr.nentries * sizeof(entry_t);
    entries = malloc(hdr.nentries * sizeof(entry_t));
    if (entries == NULL) {
        fclose(f);
        return -1;
    }

    sz = fread(entries, 1, sz, f);
    if (sz != hdr.nentries * sizeof(entry_t)) {
        free(entries);
        fclose(f);
        return -1;
    }

    for (i = 0; /*rv != 0 && XXX keep trying*/ i < hdr.nentries; i++) {
        uint8_t *buf;

        SWAP32(entries[i].type);
        SWAP64(entries[i].offset);
        SWAP64(entries[i].size);

        fseeko(f, entries[i].offset, SEEK_SET);
        if (ftello(f) != entries[i].offset) {
            /* XXX error */
            continue;
        }
        sz = entries[i].size;
        buf = malloc(sz);
        if (buf == NULL) {
            /* XXX error */
            continue;
        }

        sz = fread(buf, 1, sz, f);
        if (sz != entries[i].size) {
            /* XXX error */
            free(buf);
            continue;
        }

        switch (entries[i].type) {
            case 1: {
                blob_t *blob = (blob_t *)buf;
                SWAP32(blob->kdf_algorithm);
                SWAP32(blob->kdf_prng_algorithm);
                SWAP32(blob->kdf_iteration_count);
                SWAP32(blob->kdf_salt_len);
                SWAP32(blob->blob_enc_iv_size);
                SWAP32(blob->blob_enc_key_bits);
                SWAP32(blob->blob_enc_algorithm);
                SWAP32(blob->blob_enc_padding);
                SWAP32(blob->blob_enc_mode);
                SWAP32(blob->encrypted_keyblob_size);
#if VERBOSE
                /* 103: CSSM_ALGID_PKCS5_PBKDF2 */
                printf("keyDerivationAlgorithm      %lu\n", (unsigned long)blob->kdf_algorithm);
                printf("keyDerivationPRNGAlgorithm  %lu\n", (unsigned long)blob->kdf_prng_algorithm);
                /* by default the iteration count should be 1000 iterations */
                printf("keyDerivationIterationCount %lu\n", (unsigned long)blob->kdf_iteration_count);
                printf("keyDerivationSaltSize       %lu\n", (unsigned long)blob->kdf_salt_len);
                printf("keyDerivationSalt"); print_hex(blob->kdf_salt, blob->kdf_salt_len);
                printf("blobEncryptionIVSize        %lu\n", (unsigned long)blob->blob_enc_iv_size);
                printf("blobEncryptionIV"); print_hex(blob->blob_enc_iv, blob->blob_enc_iv_size);
                printf("blobEncryptionKeySizeInBits %lu\n", (unsigned long)blob->blob_enc_key_bits);
                /*  17: CSSM_ALGID_3DES_3KEY_EDE */
                printf("blobEncryptionAlgorithm     %lu\n", (unsigned long)blob->blob_enc_algorithm);
                /*   7: CSSM_PADDING_PKCS7 */
                printf("blobEncryptionPadding       %lu\n", (unsigned long)blob->blob_enc_padding);
                /*   6: CSSM_ALGMODE_CBCPadIV8 */
                printf("blobEncryptionMode          %lu\n", (unsigned long)blob->blob_enc_mode);
                printf("encryptedBlobSize           %lu\n", (unsigned long)blob->encrypted_keyblob_size);
                printf("encryptedBlob"); print_hex(blob->encrypted_keyblob, blob->encrypted_keyblob_size);
#endif
                rv &= check_blob(blob, passphrase);
                break;
            }
#if VERBOSE
            default:
                printf("entry%d", entries[i].type); print_hex(buf, entries[i].size);
                break;
#endif
        }

        free(buf);
    }

    free(entries);
    fclose(f);
    return rv;
}


static inline uint8_t *
hexToInts(const char *hex, size_t *bytes)
{
    size_t i;
    uint8_t *buffer;
    *bytes = strlen(hex) / 2;
    buffer = malloc(*bytes);
    if (buffer != NULL) {
        for (i = 0; i < *bytes; i++, hex += 2) {
            unsigned int x;
            sscanf(hex, "%2x", &x);
            buffer[i] = x;
        }
    }
    return buffer;
}


#include "asr4.c"


int
main(int argc, char **argv)
{
    int rv;
    char *pass;
    size_t passlength;
    uint8_t *passphrase;
    if (argc != 4) {
        fprintf(stderr, "usage: %s <platform> <ramdisk.dmg> <rootfs.dmg>\n", argv[0]);
        return -1;
    }
    pass = getpassp(argv[2], argv[1]);
    if (!pass) {
        return -1;
    }
    printf("asr passphrase: %s\n", pass);
    passphrase = hexToInts(pass, &passlength);
    rv = parse_v2_header(argv[3], passphrase);
    free(passphrase);
    free(pass);
    return rv;
}
