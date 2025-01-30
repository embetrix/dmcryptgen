/*
 * Based on mtd-utils:
 *
 * Copyright (C) 2017 sigma star gmbh
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Richard Weinberger <richard@sigma-star.at>
 *          David Oberhollenzer <david.oberhollenzer@sigma-star.at>
 */

/*
 * Based on Linux:
 *
 * lib/hexdump.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <byteswap.h>
#include <linux/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define SECTOR_SIZE 512
#define FS_IV_SIZE 16

#define t64(x) ({ \
	uint64_t __b = (x); \
	(__LITTLE_ENDIAN==__BYTE_ORDER) ? __b : bswap_64(__b); \
})
#define cpu_to_le64(x) ((__le64){t64(x)})

static int do_hash(const EVP_MD *md, const unsigned char *in, size_t len, unsigned char *out)
{
	unsigned int out_len;
	EVP_MD_CTX *mdctx = EVP_MD_CTX_create();

	if (!mdctx)
		return -1;

	if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
		return -1;

	if(EVP_DigestUpdate(mdctx, in, len) != 1)
		return -1;

	if(EVP_DigestFinal_ex(mdctx, out, &out_len) != 1)
		return -1;

	EVP_MD_CTX_destroy(mdctx);

	return 0;
}

static int check_iv_key_size(const EVP_CIPHER *cipher, size_t key_len,
			     size_t iv_len)
{
	if ((size_t)EVP_CIPHER_key_length(cipher) != key_len) {
		fprintf(stderr,"Cipher key length mismatch. Expected %lu, got %d\n",
			(unsigned long)key_len, EVP_CIPHER_key_length(cipher));
		return -1;
	}

	if (iv_len && (size_t)EVP_CIPHER_iv_length(cipher) != iv_len) {
		fprintf(stderr,"Cipher IV length mismatch. Expected %lu, got %d\n",
			(unsigned long)iv_len, EVP_CIPHER_key_length(cipher));
		return -1;
	}

	return 0;
}

static ssize_t do_encrypt(const EVP_CIPHER *cipher,
			const void *plaintext, size_t size,
			const void *key, size_t key_len,
			const void *iv, size_t iv_len,
			void *ciphertext)
{
	int ciphertext_len, len;
	EVP_CIPHER_CTX *ctx;

	if (check_iv_key_size(cipher, key_len, iv_len))
		return -1;

	if (!(ctx = EVP_CIPHER_CTX_new()))
		goto fail;

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1)
		goto fail_ctx;

	if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, size) != 1)
		goto fail_ctx;

	ciphertext_len = len;

	if (cipher == EVP_aes_256_xts()) {
		if (EVP_EncryptFinal(ctx, ciphertext + ciphertext_len, &len) != 1)
			goto fail_ctx;

		ciphertext_len += len;
	}

	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
fail_ctx:
	ERR_print_errors_fp(stderr);
	EVP_CIPHER_CTX_free(ctx);
	return -1;
fail:
	ERR_print_errors_fp(stderr);
	return -1;
}

static size_t gen_essiv256_salt(const void *iv, size_t iv_len, const void *key, size_t key_len, void *salt)
{       
	size_t ret;
	const EVP_CIPHER *cipher;
	void *sha256 = calloc(EVP_MD_size(EVP_sha256()), 1);

	if (!sha256) {
		fprintf(stderr, "Out of memory!\n");
		return -1;
	}

	cipher = EVP_aes_256_ecb();
	if (!cipher) {
		fprintf(stderr,"OpenSSL: Cipher AES-256-ECB is not supported\n");
		return -1;
	}

	if (do_hash(EVP_sha256(), key, key_len, sha256) != 0) {
		fprintf(stderr,"sha256 failed\n");
		return -1;
	}

	ret = do_encrypt(cipher, iv, iv_len, sha256, EVP_MD_size(EVP_sha256()), NULL, 0, salt);
	if (ret != iv_len) {
		fprintf(stderr,"Unable to compute ESSIV salt, return value %zi instead of %zi\n", ret, iv_len);
		return -1;
	}

	free(sha256);

	return ret;
}

static ssize_t encrypt_sector(const void *plaintext, size_t size, const void *key,
			      uint64_t sector, void *ciphertext,
			      const EVP_CIPHER *cipher)
{
	size_t key_len, ivsize;
	void *tweak;
	struct {
		uint64_t index;
		uint8_t padding[FS_IV_SIZE - sizeof(uint64_t)];
	} iv;

	ivsize = EVP_CIPHER_iv_length(cipher);
	key_len = EVP_CIPHER_key_length(cipher);

	iv.index = cpu_to_le64(sector);
	memset(iv.padding, 0, sizeof(iv.padding));

	if (cipher == EVP_aes_128_cbc()) {
		tweak = alloca(ivsize);
		gen_essiv256_salt(&iv, FS_IV_SIZE, key, key_len, tweak);
	} else {
		tweak = &iv;
	}

	return do_encrypt(cipher, plaintext, SECTOR_SIZE, key, key_len, tweak,
			  ivsize, ciphertext);
}

static int hex_to_bin(char ch)
{
	if ((ch >= '0') && (ch <= '9'))
		return ch - '0';
	ch = tolower(ch);
	if ((ch >= 'a') && (ch <= 'f'))
		return ch - 'a' + 10;
	return -1;
}

static int hex2bin(unsigned char *dst, const char *src, size_t count)
{
	while (count--) {
		int hi = hex_to_bin(*src++);
		int lo = hex_to_bin(*src++);

		if ((hi < 0) || (lo < 0))
			return -1;

		*dst++ = (hi << 4) | lo;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int fd;
	int ret;
	int total_sectors;
	unsigned long sector;
	char buf[SECTOR_SIZE];
	char crbuf[SECTOR_SIZE];
	struct stat stbuf;
	unsigned char key[16] = {0};

	if (argc != 3) {
		fprintf(stderr, "Usage: %s IMAGE KEY\n", argv[0]);
		return 1;
	}

	if (strlen(argv[2]) != 32) {
		fprintf(stderr, "Supplied key too short!\n");
		return 1;
	}

	ret = hex2bin(key, argv[2], 16);
	if (ret == -1) {
		fprintf(stderr, "Unable to read key\n");
		return 1;
	}

	fd = open(argv[1], O_RDWR);
	if (fd == -1) {
		fprintf(stderr, "Unable to open %s: %m\n", argv[1]);
		return 1;
	}

	ret = fstat(fd, &stbuf);
	if (ret == -1) {
		fprintf(stderr, "Unable to stat %s: %m\n", argv[1]);
		return 1;
	}

	total_sectors = stbuf.st_size / SECTOR_SIZE;

	for (sector = 0; sector < total_sectors; sector++) {
		ret = pread(fd, buf, SECTOR_SIZE, SECTOR_SIZE * sector);
		if (ret != SECTOR_SIZE) {
			fprintf(stderr, "Unable to read sector %lu from disk image: %i\n", sector, ret);
			ret = 1;
			goto out;
		}

		ret = encrypt_sector(buf, SECTOR_SIZE, key, sector, crbuf, EVP_aes_128_cbc());
		if (ret < 0) {
			fprintf(stderr, "Unable to encrypt sector %lu: %i\n", sector, ret);
			ret = 1;
			goto out;
		}

		ret = pwrite(fd, crbuf, SECTOR_SIZE, SECTOR_SIZE * sector);
		if (ret != SECTOR_SIZE) {
			fprintf(stderr, "Unable to write sector %lu to disk image: %i\n", sector, ret);
			ret = 1;
			goto out;
		}
	}

	ret = 0;

out:
	fsync(fd);
	close(fd);
	OPENSSL_cleanse(key, sizeof(key));

	return ret;
}
