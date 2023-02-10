/*
 * Vanitygen, vanity bitcoin address generator
 * Copyright (C) 2011 <samr7@cs.washington.edu>
 *
 * Vanitygen is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version. 
 *
 * Vanitygen is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Vanitygen.  If not, see <http://www.gnu.org/licenses/>.
 */

#if defined(_WIN32)
#define _USE_MATH_DEFINES
#endif /* defined(_WIN32) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <ctype.h>

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

#include "pattern.h"
#include "util.h"
#include "sph_groestl.h"
#include "sha3.h"
#include "ticker.h"

const char *vg_b58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const signed char vg_b58_reverse_map[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
	-1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
	-1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
	47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

void
fdumphex(FILE *fp, const unsigned char *src, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		fprintf(fp, "%02x", src[i]);
	}
	printf("\n");
}

void
fdumpbn(FILE *fp, const BIGNUM *bn)
{
	char *buf;
	buf = BN_bn2hex(bn);
	fprintf(fp, "%s\n", buf ? buf : "0");
	if (buf)
		OPENSSL_free(buf);
}

void
dumphex(const unsigned char *src, size_t len)
{
	fdumphex(stdout, src, len);
}

void
dumpbn(const BIGNUM *bn)
{
	fdumpbn(stdout, bn);
}

/*
 * Key format encode/decode
 */



void
vg_b58_encode_check(void *buf, size_t len, char *result)
{
	unsigned char hash1[32];
	unsigned char hash2[32];
	unsigned char groestlhash1[64];
	unsigned char groestlhash2[64];

	int d, p;

	BN_CTX *bnctx;
	BIGNUM *bn, *bndiv, *bntmp;
	BIGNUM *bna, *bnb, *bnbase, *bnrem;
	unsigned char *binres;
	int brlen, zpfx;

	bnctx = BN_CTX_new();
	bna = BN_new();
	bnb = BN_new();
	bnbase = BN_new();
	bnrem = BN_new();
	BN_set_word(bnbase, 58);

	bn = bna;
	bndiv = bnb;

	brlen = (2 * len) + 4;
	binres = (unsigned char*) malloc(brlen);
	memcpy(binres, buf, len);

	if(!GRSFlag)
	{
		SHA256(binres, len, hash1);
		SHA256(hash1, sizeof(hash1), hash2);
		memcpy(&binres[len], hash2, 4);
	}
	else
	{
		sph_groestl512_context ctx;
		
		sph_groestl512_init(&ctx);
		sph_groestl512(&ctx, binres, len);
		sph_groestl512_close(&ctx, groestlhash1);
		
		sph_groestl512_init(&ctx);
		sph_groestl512(&ctx, groestlhash1, sizeof(groestlhash1));
		sph_groestl512_close(&ctx, groestlhash2);
		memcpy(&binres[len], groestlhash2, 4);
	}

	BN_bin2bn(binres, len + 4, bn);

	for (zpfx = 0; zpfx < (len + 4) && binres[zpfx] == 0; zpfx++);

	p = brlen;
	while (!BN_is_zero(bn)) {
		BN_div(bndiv, bnrem, bn, bnbase, bnctx);
		bntmp = bn;
		bn = bndiv;
		bndiv = bntmp;
		d = BN_get_word(bnrem);
		binres[--p] = vg_b58_alphabet[d];
	}

	while (zpfx--) {
		binres[--p] = vg_b58_alphabet[0];
	}

	memcpy(result, &binres[p], brlen - p);
	result[brlen - p] = '\0';

	free(binres);
	BN_clear_free(bna);
	BN_clear_free(bnb);
	BN_clear_free(bnbase);
	BN_clear_free(bnrem);
	BN_CTX_free(bnctx);
}

#define skip_char(c) \
	(((c) == '\r') || ((c) == '\n') || ((c) == ' ') || ((c) == '\t'))

int
vg_b58_decode_check(const char *input, void *buf, size_t len)
{
	int i, l, c;
	unsigned char *xbuf = NULL;
	BIGNUM *bn, *bnw, *bnbase;
	BN_CTX *bnctx;
	unsigned char hash1[32], hash2[32];
	unsigned char groestlhash1[64];
	unsigned char groestlhash2[64];
	int zpfx;
	int res = 0;

	bn = BN_new();
	bnw = BN_new();
	bnbase = BN_new();
	BN_set_word(bnbase, 58);
	bnctx = BN_CTX_new();

	/* Build a bignum from the encoded value */
	l = strlen(input);
	for (i = 0; i < l; i++) {
		if (skip_char(input[i]))
			continue;
		c = vg_b58_reverse_map[(int)input[i]];
		if (c < 0)
			goto out;
		BN_clear(bnw);
		BN_set_word(bnw, c);
		BN_mul(bn, bn, bnbase, bnctx);
		BN_add(bn, bn, bnw);
	}

	/* Copy the bignum to a byte buffer */
	for (i = 0, zpfx = 0; input[i]; i++) {
		if (skip_char(input[i]))
			continue;
		if (input[i] != vg_b58_alphabet[0])
			break;
		zpfx++;
	}
	c = BN_num_bytes(bn);
	l = zpfx + c;
	if (l < 5)
		goto out;
	xbuf = (unsigned char *) malloc(l);
	if (!xbuf)
		goto out;
	if (zpfx)
		memset(xbuf, 0, zpfx);
	if (c)
		BN_bn2bin(bn, xbuf + zpfx);

	/* Check the hash code */
	l -= 4;

	if(!GRSFlag)
	{
		SHA256(xbuf, l, hash1);
		SHA256(hash1, sizeof(hash1), hash2);
		if (memcmp(hash2, xbuf + l, 4))
			goto out;
	}
	else
	{
		sph_groestl512_context ctx;
		
		sph_groestl512_init(&ctx);
		sph_groestl512(&ctx, xbuf, l);
		sph_groestl512_close(&ctx, groestlhash1);
		
		sph_groestl512_init(&ctx);
		sph_groestl512(&ctx, groestlhash1, sizeof(groestlhash1));
		sph_groestl512_close(&ctx, groestlhash2);

		if (memcmp(groestlhash2, xbuf + l, 4))
			goto out;
	}

	/* Buffer verified */
	if (len) {
		if (len > l)
			len = l;
		memcpy(buf, xbuf, len);
	}
	res = l;

out:
	if (xbuf)
		free(xbuf);
	BN_clear_free(bn);
	BN_clear_free(bnw);
	BN_clear_free(bnbase);
	BN_CTX_free(bnctx);
	return res;
}

void
vg_encode_address(const EC_POINT *ppoint, const EC_GROUP *pgroup,
		  int addrtype, int addrformat, char *result)
{
	// For ETH
	if (addrtype == ADDR_TYPE_ETH) {
		unsigned char eckey_buf[128];
		unsigned char addr_buf[20];
		EC_POINT_point2oct(pgroup, ppoint,
						   POINT_CONVERSION_UNCOMPRESSED, eckey_buf,
						   sizeof(eckey_buf), NULL);
		// Save ETH address into addr_buf
		eth_pubkey2addr(eckey_buf, addrformat, addr_buf);
		memcpy(result, "0x", 2);
		eth_encode_checksum_addr(addr_buf, 20, result+2, 40); // mixed-case checksum address
		result[42] = '\0';
		return;
	}
	unsigned char eckey_buf[128], *pend;
	unsigned char binres[21] = {0,};
	unsigned char hash1[32];

	pend = eckey_buf;

	EC_POINT_point2oct(pgroup,
			   ppoint,
			   POINT_CONVERSION_UNCOMPRESSED,
			   eckey_buf,
			   sizeof(eckey_buf),
			   NULL);
	pend = eckey_buf + 0x41;
	binres[0] = addrtype;
	if (TRXFlag == 1) {
		// See: https://secretscan.org/PrivateKeyTron
		SHA3_256(hash1, eckey_buf + 1, 64); // skip 1 byte (the leading 0x04) in uncompressed public key
		memcpy(&binres[1], hash1 + 12, 20); // skip first 12 bytes in public key hash
	} else {
		SHA256(eckey_buf, pend - eckey_buf, hash1);
		RIPEMD160(hash1, sizeof(hash1), &binres[1]);
	}

	vg_b58_encode_check(binres, sizeof(binres), result);
}

void
vg_encode_address_compressed(const EC_POINT *ppoint, const EC_GROUP *pgroup,
		  int addrtype, char *result)
{
	unsigned char eckey_buf[128], *pend;
	unsigned char binres[21] = {0,};
	unsigned char hash1[32];

	pend = eckey_buf;

	EC_POINT_point2oct(pgroup,
			   ppoint,
			   POINT_CONVERSION_COMPRESSED,
			   eckey_buf,
			   sizeof(eckey_buf),
			   NULL);
	pend = eckey_buf + 0x21;
	binres[0] = addrtype;
	SHA256(eckey_buf, pend - eckey_buf, hash1);
	RIPEMD160(hash1, sizeof(hash1), &binres[1]);

	vg_b58_encode_check(binres, sizeof(binres), result);
}

void
vg_encode_script_address(const EC_POINT *ppoint, const EC_GROUP *pgroup,
			 int addrtype, char *result)
{
	unsigned char script_buf[69];
	unsigned char *eckey_buf = script_buf + 2;
	unsigned char binres[21] = {0,};
	unsigned char hash1[32];

	script_buf[ 0] = 0x51;  // OP_1
	script_buf[ 1] = 0x41;  // pubkey length
	// gap for pubkey
	script_buf[67] = 0x51;  // OP_1
	script_buf[68] = 0xae;  // OP_CHECKMULTISIG

	EC_POINT_point2oct(pgroup,
			   ppoint,
			   POINT_CONVERSION_UNCOMPRESSED,
			   eckey_buf,
			   65,
			   NULL);
	binres[0] = addrtype;
	SHA256(script_buf, 69, hash1);
	RIPEMD160(hash1, sizeof(hash1), &binres[1]);

	vg_b58_encode_check(binres, sizeof(binres), result);
}

void
vg_encode_privkey(const EC_KEY *pkey, int privtype, char *result)
{
	unsigned char eckey_buf[128];
	const BIGNUM *bn;
	int nbytes;

	bn = EC_KEY_get0_private_key(pkey);

	eckey_buf[0] = privtype;
	nbytes = BN_num_bytes(bn);
	assert(nbytes <= 32);
	if (nbytes < 32)
		memset(eckey_buf + 1, 0, 32 - nbytes);
	BN_bn2bin(bn, &eckey_buf[33 - nbytes]);

	// For ETH
	if (privtype == PRIV_TYPE_ETH) {
		size_t len=64;
		memcpy(result, "0x", 2);
		hex_enc(result + 2, &len, eckey_buf + 1, 32);
		result[len+2] = '\0';
		return;
	}
	if (strncmp(ticker, "TRX", 3) == 0) {
		// For tron, private key is just hex string without prefix 0x
		char *buf = BN_bn2hex(bn); // Must be freed later using OPENSSL_free
		strcpy(result, buf);
		if (buf) OPENSSL_free(buf);
		return;
	}

	vg_b58_encode_check(eckey_buf, 33, result);
}

void
vg_encode_privkey_compressed(const EC_KEY *pkey, int privtype, char *result)
{
	unsigned char eckey_buf[128];
	const BIGNUM *bn;
	int nbytes;

	bn = EC_KEY_get0_private_key(pkey);

	eckey_buf[0] = privtype;
	nbytes = BN_num_bytes(bn);
	assert(nbytes <= 32);
	if (nbytes < 32)
		memset(eckey_buf + 1, 0, 32 - nbytes);
	BN_bn2bin(bn, &eckey_buf[33 - nbytes]);
	eckey_buf[33] = 1;

	vg_b58_encode_check(eckey_buf, 34, result);
}

int
vg_set_privkey(const BIGNUM *bnpriv, EC_KEY *pkey)
{
	const EC_GROUP *pgroup;
	EC_POINT *ppnt;
	int res;

	pgroup = EC_KEY_get0_group(pkey);
	ppnt = EC_POINT_new(pgroup);

	res = (ppnt &&
	       EC_KEY_set_private_key(pkey, bnpriv) &&
	       EC_POINT_mul(pgroup, ppnt, bnpriv, NULL, NULL, NULL) &&
	       EC_KEY_set_public_key(pkey, ppnt));

	if (ppnt)
		EC_POINT_free(ppnt);

	if (!res)
		return 0;

	assert(EC_KEY_check_key(pkey));
	return 1;
}

int
vg_decode_privkey(const char *b58encoded, EC_KEY *pkey, int *addrtype)
{
	BIGNUM *bnpriv;
	unsigned char ecpriv[48];
	int res, ret;

	res = vg_b58_decode_check(b58encoded, ecpriv, sizeof(ecpriv));
	if (res < 33 || res > 34)
		return 0;

	ret = res - 32;

	bnpriv = BN_new();
	BN_bin2bn(ecpriv + 1, 32, bnpriv);
	res = vg_set_privkey(bnpriv, pkey);
	BN_clear_free(bnpriv);
	*addrtype = ecpriv[0];
	return ret;
}

#if OPENSSL_VERSION_NUMBER < 0x10000000L
/* The generic PBKDF2 function first appeared in OpenSSL 1.0 */
/* ====================================================================
 * Copyright (c) 1999-2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
int
PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
		  const unsigned char *salt, int saltlen, int iter,
		  const EVP_MD *digest,
		  int keylen, unsigned char *out)
{
	unsigned char digtmp[EVP_MAX_MD_SIZE], *p, itmp[4];
	int cplen, j, k, tkeylen, mdlen;
	unsigned long i = 1;
	HMAC_CTX hctx;

	mdlen = EVP_MD_size(digest);
	if (mdlen < 0)
		return 0;

	HMAC_CTX_init(&hctx);
	p = out;
	tkeylen = keylen;
	if(!pass)
		passlen = 0;
	else if(passlen == -1)
		passlen = strlen(pass);
	while(tkeylen)
		{
		if(tkeylen > mdlen)
			cplen = mdlen;
		else
			cplen = tkeylen;
		/* We are unlikely to ever use more than 256 blocks (5120 bits!)
		 * but just in case...
		 */
		itmp[0] = (unsigned char)((i >> 24) & 0xff);
		itmp[1] = (unsigned char)((i >> 16) & 0xff);
		itmp[2] = (unsigned char)((i >> 8) & 0xff);
		itmp[3] = (unsigned char)(i & 0xff);
		HMAC_Init_ex(&hctx, pass, passlen, digest, NULL);
		HMAC_Update(&hctx, salt, saltlen);
		HMAC_Update(&hctx, itmp, 4);
		HMAC_Final(&hctx, digtmp, NULL);
		memcpy(p, digtmp, cplen);
		for(j = 1; j < iter; j++)
			{
			HMAC(digest, pass, passlen,
				 digtmp, mdlen, digtmp, NULL);
			for(k = 0; k < cplen; k++)
				p[k] ^= digtmp[k];
			}
		tkeylen-= cplen;
		i++;
		p+= cplen;
		}
	HMAC_CTX_cleanup(&hctx);
	return 1;
}
#endif  /* OPENSSL_VERSION_NUMBER < 0x10000000L */


typedef struct {
	int mode;
	int iterations;
	const EVP_MD *(*pbkdf_hash_getter)(void);
	const EVP_CIPHER *(*cipher_getter)(void);
} vg_protkey_parameters_t;

static const vg_protkey_parameters_t protkey_parameters[] = {
	{ 0, 4096,  EVP_sha256, EVP_aes_256_cbc },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 0, 0, NULL, NULL },
	{ 1, 4096,  EVP_sha256, EVP_aes_256_cbc },
};

static int
vg_protect_crypt(int parameter_group,
		 unsigned char *data_in, int data_in_len,
		 unsigned char *data_out,
		 const char *pass, int enc)
{
	EVP_CIPHER_CTX *ctx = NULL;
	unsigned char *salt;
	unsigned char keymaterial[EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH + 
				  EVP_MAX_MD_SIZE];
	unsigned char hmac[EVP_MAX_MD_SIZE];
	int hmac_len = 0, hmac_keylen = 0;
	int salt_len;
	int plaintext_len = 32;
	int ciphertext_len;
	int pkcs7_padding = 1;
	const vg_protkey_parameters_t *params;
	const EVP_CIPHER *cipher;
	const EVP_MD *pbkdf_digest;
	const EVP_MD *hmac_digest;
	unsigned int hlen;
	int opos, olen, oincr, nbytes;
	int ipos;
	int ret = 0;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		goto out;

	if (parameter_group < 0) {
		if (enc)
			parameter_group = 0;
		else
			parameter_group = data_in[0];
	} else {
		if (!enc && (parameter_group != data_in[0]))
			goto out;
	}

	if (parameter_group > (sizeof(protkey_parameters) / 
			       sizeof(protkey_parameters[0])))
		goto out;
	params = &protkey_parameters[parameter_group];

	if (!params->iterations || !params->pbkdf_hash_getter)
		goto out;

	pbkdf_digest = params->pbkdf_hash_getter();
	cipher = params->cipher_getter();

	if (params->mode == 0) {
		/* Brief encoding */
		salt_len = 4;
		hmac_len = 8;
		hmac_keylen = 16;
		ciphertext_len = ((plaintext_len + EVP_CIPHER_block_size(cipher) - 1) /
				  EVP_CIPHER_block_size(cipher)) * EVP_CIPHER_block_size(cipher);
		pkcs7_padding = 0;
		hmac_digest = EVP_sha256();
	} else {
		/* PKCS-compliant encoding */
		salt_len = 8;
		ciphertext_len = ((plaintext_len + EVP_CIPHER_block_size(cipher)) /
				  EVP_CIPHER_block_size(cipher)) * EVP_CIPHER_block_size(cipher);
		hmac_digest = NULL;
	}

	if (!enc && (data_in_len != (1 + ciphertext_len + hmac_len + salt_len)))
		goto out;

	if (!pass || !data_out) {
		/* Format check mode */
		ret = plaintext_len;
		goto out;
	}

	if (!enc) {
		salt = data_in + 1 + ciphertext_len + hmac_len;
	} else if (salt_len) {
		salt = data_out + 1 + ciphertext_len + hmac_len;
		RAND_bytes(salt, salt_len);
	} else {
		salt = NULL;
	}

	PKCS5_PBKDF2_HMAC((const char *) pass, strlen(pass) + 1,
			  salt, salt_len,
			  params->iterations,
			  pbkdf_digest,
			  EVP_CIPHER_key_length(cipher) + EVP_CIPHER_iv_length(cipher) + hmac_keylen,
			  keymaterial);

	if (!EVP_CipherInit(ctx, cipher,
			    keymaterial,
			    keymaterial + EVP_CIPHER_key_length(cipher),
			    enc)) {
		fprintf(stderr, "ERROR: could not configure cipher\n");
		goto out;
	}

	if (!pkcs7_padding)
		EVP_CIPHER_CTX_set_padding(ctx, 0);

	if (!enc) {
		opos = 0;
		olen = plaintext_len;
		nbytes = ciphertext_len;
		ipos = 1;
	} else {
		data_out[0] = parameter_group;
		opos = 1;
		olen = 1 + ciphertext_len + hmac_len + salt_len - opos;
		nbytes = plaintext_len;
		ipos = 0;
	}

	oincr = olen;
	if (!EVP_CipherUpdate(ctx, data_out + opos, &oincr,
			      data_in + ipos, nbytes))
		goto invalid_pass;
	opos += oincr;
	olen -= oincr;
	oincr = olen;
	if (!EVP_CipherFinal(ctx, data_out + opos, &oincr))
		goto invalid_pass;
	opos += oincr;

	if (hmac_len) {
		hlen = sizeof(hmac);
		HMAC(hmac_digest,
		     keymaterial + EVP_CIPHER_key_length(cipher) + EVP_CIPHER_iv_length(cipher),
		     hmac_keylen,
		     enc ? data_in : data_out, plaintext_len,
		     hmac, &hlen);
		if (enc) {
			memcpy(data_out + 1 + ciphertext_len, hmac, hmac_len);
		} else if (memcmp(hmac,
				  data_in + 1 + ciphertext_len,
				  hmac_len))
			goto invalid_pass;
	}

	if (enc) {
		if (opos != (1 + ciphertext_len)) {
			fprintf(stderr, "ERROR: plaintext size mismatch\n");
			goto out;
		}
		opos += hmac_len + salt_len;
	} else if (opos != plaintext_len) {
		fprintf(stderr, "ERROR: plaintext size mismatch\n");
		goto out;
	}

	ret = opos;

	if (0) {
	invalid_pass:
		fprintf(stderr, "ERROR: Invalid password\n");
	}

out:
	OPENSSL_cleanse(hmac, sizeof(hmac));
	OPENSSL_cleanse(keymaterial, sizeof(keymaterial));
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	return ret;
}

int
vg_protect_encode_privkey(char *out,
			  const EC_KEY *pkey, int keytype,
			  int parameter_group,
			  const char *pass)
{
	unsigned char ecpriv[64];
	unsigned char ecenc[128];
	const BIGNUM *privkey;
	int nbytes;
	int restype;

	restype = (keytype & 1) ? 79 : 32;

	privkey = EC_KEY_get0_private_key(pkey);
	nbytes = BN_num_bytes(privkey);
	if (nbytes < 32)
		memset(ecpriv, 0, 32 - nbytes);
	BN_bn2bin(privkey, ecpriv + 32 - nbytes);

	nbytes = vg_protect_crypt(parameter_group,
				  ecpriv, 32,
				  &ecenc[1], pass, 1);
	if (nbytes <= 0)
		return 0;

	OPENSSL_cleanse(ecpriv, sizeof(ecpriv));

	ecenc[0] = restype;
	vg_b58_encode_check(ecenc, nbytes + 1, out);
	nbytes = strlen(out);
	return nbytes;
}


int
vg_protect_decode_privkey(EC_KEY *pkey, int *keytype,
			  const char *encoded, const char *pass)
{
	unsigned char ecpriv[64];
	unsigned char ecenc[128];
	BIGNUM *bn;
	int restype;
	int res;

	res = vg_b58_decode_check(encoded, ecenc, sizeof(ecenc));

	if ((res < 2) || (res > sizeof(ecenc)))
		return 0;

	switch (ecenc[0]) {
	case 32:  restype = 128; break;
	case 79:  restype = 239; break;
	default:
		return 0;
	}

	if (!vg_protect_crypt(-1,
			      ecenc + 1, res - 1,
			      pkey ? ecpriv : NULL,
			      pass, 0))
		return 0;

	res = 1;
	if (pkey) {
		bn = BN_new();
		BN_bin2bn(ecpriv, 32, bn);
		res = vg_set_privkey(bn, pkey);
		BN_clear_free(bn);
		OPENSSL_cleanse(ecpriv, sizeof(ecpriv));
	}

	*keytype = restype;
	return res;
}

/*
 * Besides the bitcoin-adapted formats, we also support PKCS#8.
 */
int
vg_pkcs8_encode_privkey(char *out, int outlen,
			const EC_KEY *pkey, const char *pass)
{
	EC_KEY *pkey_copy = NULL;
	EVP_PKEY *evp_key = NULL;
	PKCS8_PRIV_KEY_INFO *pkcs8 = NULL;
	X509_SIG *pkcs8_enc = NULL;
	BUF_MEM *memptr;
	BIO *bio = NULL;
	int res = 0;

	pkey_copy = EC_KEY_dup(pkey);
	if (!pkey_copy)
		goto out;
	evp_key = EVP_PKEY_new();
	if (!evp_key || !EVP_PKEY_set1_EC_KEY(evp_key, pkey_copy))
		goto out;
	pkcs8 = EVP_PKEY2PKCS8(evp_key);
	if (!pkcs8)
		goto out;

	bio = BIO_new(BIO_s_mem());
	if (!bio)
		goto out;

	if (!pass) {
		res = PEM_write_bio_PKCS8_PRIV_KEY_INFO(bio, pkcs8);

	} else {
		pkcs8_enc = PKCS8_encrypt(-1,
					  EVP_aes_256_cbc(),
					  pass, strlen(pass),
					  NULL, 0,
					  4096,
					  pkcs8);
		if (!pkcs8_enc)
			goto out;
		res = PEM_write_bio_PKCS8(bio, pkcs8_enc);
	}

	BIO_get_mem_ptr(bio, &memptr);
	res = memptr->length;
	if (res < outlen) {
		memcpy(out, memptr->data, res);
		out[res] = '\0';
	} else {
		memcpy(out, memptr->data, outlen - 1);
		out[outlen-1] = '\0';
	}

out:
	if (bio)
		BIO_free(bio);
	if (pkey_copy)
		EC_KEY_free(pkey_copy);
	if (evp_key)
		EVP_PKEY_free(evp_key);
	if (pkcs8)
		PKCS8_PRIV_KEY_INFO_free(pkcs8);
	if (pkcs8_enc)
		X509_SIG_free(pkcs8_enc);
	return res;
}

int
vg_pkcs8_decode_privkey(EC_KEY *pkey, const char *pem_in, const char *pass)
{
	EC_KEY *pkey_in = NULL;
	EC_KEY *test_key = NULL;
	EVP_PKEY *evp_key = NULL;
	PKCS8_PRIV_KEY_INFO *pkcs8 = NULL;
	X509_SIG *pkcs8_enc = NULL;
	BIO *bio = NULL;
	int res = 0;

	bio = BIO_new_mem_buf((char *)pem_in, strlen(pem_in));
	if (!bio)
		goto out;

	pkcs8_enc = PEM_read_bio_PKCS8(bio, NULL, NULL, NULL);
	if (pkcs8_enc) {
		if (!pass)
			return -1;
		pkcs8 = PKCS8_decrypt(pkcs8_enc, pass, strlen(pass));

	} else {
		(void) BIO_reset(bio);
		pkcs8 = PEM_read_bio_PKCS8_PRIV_KEY_INFO(bio, NULL, NULL, NULL);
	}

	if (!pkcs8)
		goto out;
	evp_key = EVP_PKCS82PKEY(pkcs8);
	if (!evp_key)
		goto out;
	pkey_in = EVP_PKEY_get1_EC_KEY(evp_key);
	if (!pkey_in)
		goto out;

	/* Expect a specific curve */
	test_key = EC_KEY_new_by_curve_name(NID_secp256k1);
	if (!test_key ||
	    EC_GROUP_cmp(EC_KEY_get0_group(pkey_in),
			 EC_KEY_get0_group(test_key),
			 NULL))
		goto out;

	if (!EC_KEY_copy(pkey, pkey_in))
		goto out;

	res = 1;

out:
	if (bio)
		BIO_free(bio);
	if (test_key)
		EC_KEY_free(pkey_in);
	if (evp_key)
		EVP_PKEY_free(evp_key);
	if (pkcs8)
		PKCS8_PRIV_KEY_INFO_free(pkcs8);
	if (pkcs8_enc)
		X509_SIG_free(pkcs8_enc);
	return res;
}


int
vg_decode_privkey_any(EC_KEY *pkey, int *addrtype, const char *input,
		      const char *pass)
{
	int res;

	// For ETH, private key is just hex string
	// For TRON, private key is just hex string
	if (*addrtype == ADDR_TYPE_ETH || strncmp(ticker, "TRX", 3) == 0) {
		BIGNUM * bnpriv = BN_new();

		uint8_t bin[64];
		size_t binsz = 64;

		hex_dec(bin, &binsz, input, strlen(input));

		BN_bin2bn((const unsigned char *)bin, binsz, bnpriv);
		res = vg_set_privkey(bnpriv, pkey);
		BN_clear_free(bnpriv);
		return res;
	}

	if ((res = vg_decode_privkey(input, pkey, addrtype)))
		return res;
	if (vg_protect_decode_privkey(pkey, addrtype, input, NULL)) {
		if (!pass)
			return -1;
		return vg_protect_decode_privkey(pkey, addrtype, input, pass);
	}
	res = vg_pkcs8_decode_privkey(pkey, input, pass);
	if (res > 0) {
		/* Assume main network address */
		*addrtype = 128;
	}
	return res;
}


int
vg_read_password(char *buf, size_t size)
{
	return !EVP_read_pw_string(buf, size, "Enter new password:", 1);
}


/*
 * Password complexity checker
 * Heavily inspired by, but a simplification of "How Secure Is My Password?",
 * http://howsecureismypassword.net/
 */
static unsigned char ascii_class[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	5, 4, 5, 4, 4, 4, 4, 5, 4, 4, 4, 4, 5, 4, 5, 5,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 5, 5, 5, 4, 5, 5,
	4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 5, 5, 5, 4, 4,
	5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 5, 5, 5, 5, 0,
};

int
vg_check_password_complexity(const char *pass, int verbose)
{
	int i, len;
	int classes[6] = { 0, };
	const char *crackunit = "seconds";
	int char_complexity = 0;
	double crackops, cracktime;
	int weak;

	/*
	 * This number reflects a resourceful attacker with
	 * USD >$20K in 2011 hardware
	 */
	const int rate = 250000000;

	/* Consider the password weak if it can be cracked in <1 year */
	const int weak_threshold = (60*60*24*365);

	len = strlen(pass);
	for (i = 0; i < len; i++) {
		if (pass[i] > sizeof(ascii_class))
			/* FIXME: skip the rest of the UTF8 char */
			classes[5]++;
		else if (!ascii_class[(int)pass[i]])
			continue;
		else
			classes[(int)ascii_class[(int)pass[i]] - 1]++;
	}

	if (classes[0])
		char_complexity += 26;
	if (classes[1])
		char_complexity += 26;
	if (classes[2])
		char_complexity += 10;
	if (classes[3])
		char_complexity += 14;
	if (classes[4])
		char_complexity += 19;
	if (classes[5])
		char_complexity += 32;  /* oversimplified */

	/* This assumes brute-force and oversimplifies the problem */
	crackops = pow((double)char_complexity, (double)len);
	cracktime = (crackops * (1 - (1/M_E))) / rate;
	weak = (cracktime < weak_threshold);

	if (cracktime > 60.0) {
		cracktime /= 60.0;
		crackunit = "minutes";
		if (cracktime > 60.0) {
			cracktime /= 60.0;
			crackunit = "hours";
			if (cracktime > 24.0) {
				cracktime /= 24;
				crackunit = "days";
				if (cracktime > 365.0) {
					cracktime /= 365.0;
					crackunit = "years";
				}
			}
		}
	}

	/* Complain by default about weak passwords */
	if ((weak && (verbose > 0)) || (verbose > 1)) {
		if (cracktime < 1.0) {
			fprintf(stderr,
				"Estimated password crack time: >1 %s\n",
			       crackunit);
		} else if (cracktime < 1000000) {
			fprintf(stderr,
				"Estimated password crack time: %.1f %s\n",
				cracktime, crackunit);
		} else {
			fprintf(stderr,
				"Estimated password crack time: %e %s\n",
				cracktime, crackunit);
		}
		if (!classes[0] && !classes[1] && classes[2] &&
		    !classes[3] && !classes[4] && !classes[5]) {
			fprintf(stderr,
				"WARNING: Password contains only numbers\n");
		}
		else if (!classes[2] && !classes[3] && !classes[4] &&
			 !classes[5]) {
			if (!classes[0] || !classes[1]) {
				fprintf(stderr,
					"WARNING: Password contains "
					"only %scase letters\n",
					classes[0] ? "lower" : "upper");
			} else {
				fprintf(stderr,
					"WARNING: Password contains "
					"only letters\n");
			}
		}
	}

	return !weak;
}


/*
 * Pattern file reader
 * Absolutely disgusting, unable to free the pattern list when it's done
 */

int
vg_read_file(FILE *fp, char ***result, int *rescount)
{
	int ret = 1;

	char **patterns;
	char *buf = NULL, *obuf, *pat;
	const int blksize = 16*1024;
	int nalloc = 16;
	int npatterns = 0;
	int count, pos;

	patterns = (char**) malloc(sizeof(char*) * nalloc);
	count = 0;
	pos = 0;

	while (1) {
		obuf = buf;
		buf = (char *) malloc(blksize);
		if (!buf) {
			ret = 0;
			break;
		}
		if (pos < count) {
			memcpy(buf, &obuf[pos], count - pos);
		}
		pos = count - pos;
		count = fread(&buf[pos], 1, blksize - pos, fp);
		if (count < 0) {
			fprintf(stderr,
				"Error reading file: %s\n", strerror(errno));
			ret = 0;
		}
		if (count <= 0)
			break;
		count += pos;
		pat = buf;

		while (pos < count) {
			if ((buf[pos] == '\r') || (buf[pos] == '\n')) {
				buf[pos] = '\0';
				if (pat) {
					if (npatterns == nalloc) {
						nalloc *= 2;
						patterns = (char**)
							realloc(patterns,
								sizeof(char*) *
								nalloc);
					}
					patterns[npatterns] = pat;
					npatterns++;
					fprintf(stderr,	"\rLoading Pattern #%d: %s", npatterns, pat);
					pat = NULL;
				}
			}
			else if (!pat) {
				pat = &buf[pos];
			}
			pos++;
		}

		pos = pat ? (pat - buf) : count;
	}			

	*result = patterns;
	*rescount = npatterns;
	fprintf(stderr,	"\n");
	return ret;
}

char
*strtok_r_keep_empty_fields(char *str, const char *delims, char **store) {
	char *ret;

	if (str == NULL) str = *store;

	if (*str == '\0') return NULL;

	ret = str;
	str += strcspn(str, delims);

	if (*str != '\0') {
		*str++ = '\0';
	}

	*store = str;
	return ret;
}

void
vg_print_alicoin_help_msg() {
	char line[1024];
	char *coinsymbol, *coinname, *prefix;
	char *save;
	char *part;
	int partindex;
	FILE *fp = fopen("base58prefix.txt","r");
	if( fp == NULL ) {
		fprintf(stderr,	"Read base58prefix.txt fail: %s\n", strerror(errno));
		return;
	}
	// read file line by line
	while (fgets(line, 1024, fp)) {
		if (!strcmp(line,"\n")) continue; // skip empty line
		if (!strcmp(line,"\r\n")) continue; // skip empty line in MS system
		if (!strncmp(line,"#", 1)) continue; // skip line start with #
		partindex = 0;
		part = strtok_r_keep_empty_fields(line, ",", &save);
		while (part != NULL) {
			partindex++;
			if (partindex == 1) {
				coinsymbol = part;
			} else if (partindex == 2) {
				coinname = part;
			} else if (partindex == 3) {
				prefix = part;
			}
			part = strtok_r_keep_empty_fields(NULL, ",", &save);
		}
		if (partindex < 4) {
			fprintf(stderr,	"Invalid line found in base58prefix.txt\n");
			continue;
		}
		fprintf(stderr,	"%s : %s : %s\n", coinsymbol, coinname, prefix);
	}
}

int
vg_get_altcoin(char *altcoin, int *addrtype, int *privtype, char **hrp)
{
	char line[1024];
	char *save;
	char *part;
	int partindex;
	FILE *fp = fopen("base58prefix.txt","r");
	if( fp == NULL ) {
		fprintf(stderr,	"Read base58prefix.txt fail: %s\n", strerror(errno));
		return 1;
	}
	// read file line by line
	while (fgets(line, 1024, fp)) {
		// remove trailing newline (LF, CR, CRLF) from line
		if (strlen(line) > 0 && line[strlen(line)-1] == '\r') {
			line[strlen(line)-1] ='\0';
		}
		if (strlen(line) > 0 && line[strlen(line)-1] == '\n') {
			line[strlen(line)-1] ='\0';
		}
		if (!strncmp(altcoin, line, strlen(altcoin)) && line[strlen(altcoin)] == ',') {
			// find coin at line beginning
			partindex = 0;
			part = strtok_r_keep_empty_fields(line, ",", &save);
			while (part != NULL) {
				partindex++;
				if (partindex == 4) {
					// parse addrtype
					*addrtype = (int)strtol(part, NULL, 0);
				} else if (partindex == 5) {
					// parse privtype
					*privtype = (int)strtol(part, NULL, 0);
				} else if (partindex == 6) {
					if (hrp != NULL) {
						*hrp = strdup(part);
					}
				}
				part = strtok_r_keep_empty_fields(NULL, ",", &save);
			}
            if (partindex < 4) {
                fprintf(stderr,	"Cannot find coin %s: invalid line found in base58prefix.txt\n", altcoin);
                return 1;
            }
			return 0;
		}
	}
	fprintf(stderr,	"Cannot find coin %s in base58prefix.txt\n", altcoin);
	return 1;
}

#if !defined(_WIN32)
int
count_processors(void)
{
#if defined(__APPLE__)
    int count = sysconf(_SC_NPROCESSORS_ONLN);
#else
    FILE *fp;
	char buf[512];
	int count = 0;

	fp = fopen("/proc/cpuinfo", "r");
	if (!fp)
		return -1;

	while (fgets(buf, sizeof(buf), fp)) {
		if (!strncmp(buf, "processor\t", 10))
			count += 1;
	}
	fclose(fp);
#endif
    return count;
}
#endif

static const char hexdig[] = "0123456789abcdef";

// An example:
// input: hex[4] = {0x31, 0x32, 0x61, 0x62}
// output: bin[2] = {0x12, 0xab}
int
hex_dec(void *bin, size_t *binszp, const char *hex, size_t hexsz)
{
	size_t binsz = *binszp;
	const unsigned char *hexu = (const unsigned char *)hex;
	uint8_t *binu = (uint8_t *)bin;
	size_t i;

	if (!hexsz) hexsz = strlen((const char *)hex);
	if (hexsz & 1) return -1;
	if (*hexu == '0' && (hexu[1] | 0x20) == 'x') {
		hexu += 2;
		hexsz -= 2;
	}
	if (hexsz == 0 || binsz < hexsz/2) return -1;
	binsz = hexsz/2;
	for(i=0;i<binsz;i++,binu++) {
		if (!isxdigit(*hexu)) return -1;
		if (isdigit(*hexu)) *binu = (*hexu - '0') << 4; else {
			*binu = ((*hexu | 0x20) - 'a' + 10) << 4;
		}
		hexu++;
		if (!isxdigit(*hexu)) return -1;
		if (isdigit(*hexu)) *binu |= (*hexu - '0'); else {
			*binu |= ((*hexu | 0x20) - 'a' + 10);
		}
		hexu++;
	}

	*binszp = binsz;

	return 0;
}

// An example:
// input: data[2] = {0x12, 0xab}
// output: hex[4] = {0x31, 0x32, 0x61, 0x62}
int
hex_enc(char *hex, size_t *hexszp, const void *data, size_t binsz)
{
	const uint8_t *bin = (const uint8_t *)data;
	size_t i, len;
	if (*hexszp < binsz*2) { return -1; }
	len = 0;
	for(i=0;i<binsz;i++,bin++) {
		*hex++ = hexdig[*bin >> 4];
		len++;
		*hex++ = hexdig[*bin & 0xf];
		len++;
	}
	*hexszp = len;

	return 0;
}

// pubkey_buf must be equal or greater than 65 bytes
// out_buf must be equal or greater than 20 bytes
void
eth_pubkey2addr(const unsigned char* pubkey_buf, int addrformat, unsigned char *out_buf)
{
	unsigned char hash1[32], ethrlp_buf[23];

	SHA3_256(hash1, pubkey_buf + 1, 64); // skip 1 byte (the leading 0x04) in uncompressed public key
	memcpy(out_buf, hash1 + 12, 20); // skip first 12 bytes in public key hash, out_buf store eth address
	if (addrformat == VCF_CONTRACT) {
		// Compute eth contract address with nonce 0, see:
		// https://ethereum.stackexchange.com/questions/760/how-is-the-address-of-an-ethereum-contract-computed
		ethrlp_buf[0] = 0xd6;
		ethrlp_buf[1] = 0x94;
		memcpy(ethrlp_buf + 2, out_buf, 20);
		ethrlp_buf[22] = 0x80;

		SHA3_256(hash1, ethrlp_buf, 23);
		memcpy(out_buf, hash1 + 12, 20); // out_buf store eth contract address
	}
	// printf("public key: ");
	// dumphex(pubkey_buf, 65);
	// printf("address: ");
	// dumphex(out_buf, 20);
}

static char upper[128] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 0, 0, 0, 0, 0, 0,
	0, 'A', 'B', 'C', 'D', 'E', 'F', 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 'A', 'B', 'C', 'D', 'E', 'F', 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static char lower[128] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 0, 0, 0, 0, 0, 0,
    0, 'a', 'b', 'c', 'd', 'e', 'f', 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 'a', 'b', 'c', 'd', 'e', 'f', 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

// input is 20-byte binary address
// output is 40-byte hex string address
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
void
eth_encode_checksum_addr(void * input, int inlen, char *output, int outlen)
{
	assert(inlen >= 20);
	assert(outlen >= 40);
	int i;
	unsigned char input_hex[40];
	unsigned char hash1[32];
	char hash1_hex[64];
	size_t len = 40;
	hex_enc((char *)input_hex, &len, input, 20);
	SHA3_256(hash1, input_hex, 40);
	len = 64;
	hex_enc(hash1_hex, &len, hash1, 32);
	for (i=0; i<40; i++) {
		if (hash1_hex[i] >= '8' + 0) {
			// Convert 'a'-'f' to uppercase 'A'-'F'; keep '0'-'9' untouched.
			output[i] = upper[input_hex[i] + 0]; // `+ 0` for avoid compiler warning
		} else {
			output[i] = lower[input_hex[i] + 0];
		}
	}
}

// Like memcpy, but length specified by bits (rather than bytes)
void copy_nbits(unsigned char *dst, unsigned char *src, int nbits) {
	// An example:
	// dst(input):  MMMMMMMM NNNNNNNN
	// src:         IIIIIIII JJJJJJJJ
	// nbits: 11
	// dst(output): IIIIIIII JJJNNNNN
	int nbytes = (nbits / 8) + 1; // (11 / 8) + 1 = 2
	int extra_nbits = nbytes * 8 - nbits; // 2 * 8 - 11 = 5
	char tab[8] = {0, 1, 3 /* 2 bits 1 */, 7 /* 3 bits 1 */, 15 /* 4 bits 1 */, 31 /* 5 bits 1 */,
				   63 /* 6 bits 1 */, 127 /* 7 bits 1 */};
	unsigned char backup = dst[nbytes - 1]; // NNNNNNNN
	memcpy(dst, src, nbytes);
	unsigned char after = dst[nbytes - 1]; // JJJJJJJJ
	dst[nbytes - 1] = (backup & tab[extra_nbits])  // 000NNNNN
					| (after & ~tab[extra_nbits]); // JJJ00000
}
