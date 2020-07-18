#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#if !defined(_WIN32)
#include <unistd.h>
#else
#include "winglue.h"
#endif

#include "pattern.h"
#include "util.h"
#include "ticker.h"
char ticker[10];

const char *version = VANITYGEN_VERSION;

int GRSFlag = 0;

static void
usage(const char *progname)
{
	fprintf(stderr,
"Vanitygen keyconv %s\n"
"Usage: %s [-8] [-e|-E <password>] [-c <key>] [<key>]\n"
"-G            Generate a key pair and output the full public key\n"
"-8            Output key in PKCS#8 form\n"
"-F <format>   Output address in the given format (compressed)\n"
"-e            Encrypt output key, prompt for password\n"
"-E <password> Encrypt output key with <password> (UNSAFE)\n"
"-c <key>      Combine private key parts to make complete private key\n"
"-C <altcoin>  Decrypt an address for specific altcoin, use \"-C LIST\" to view\n"
"              a list of all available altcoins, argument is case sensitive!\n"
"-d            Decrypt output key, prompt for password\n"
"-X <version>  Public key version (for altcoins)\n"
"-Y <version>  Private key version (-X provides public key)\n"
"-v            Verbose output\n",
		version, progname);
}


int
main(int argc, char **argv)
{
	char pwbuf[128];
	char ecprot[128];
	char pbuf[1024];
	const char *key_in;
	const char *pass_in = NULL;
	const char *key2_in = NULL;
	EC_KEY *pkey;
	int parameter_group = -1;
	int addrtype = 0;
	int privtype = 128;
	int addrtype_opt = addrtype;
	int privtype_opt = privtype;
	int addrtype_override = 0;
	int pkcs8 = 0;
	int pass_prompt = 0;
	int compressed = 0;
	int verbose = 0;
	int generate = 0;
	int decrypt = 0;
	int opt;
	int res;

	while ((opt = getopt(argc, argv, "C:8E:ec:vGX:Y:dF:")) != -1) {
		switch (opt) {
/*BEGIN ALTCOIN GENERATOR*/

		case 'C':
			strcpy(ticker, optarg);
			strcat(ticker, " ");
			addrtype_override = 1;
			/* Start AltCoin Generator */
			if (strcmp(optarg, "LIST")== 0) {
				fprintf(stderr,
					"Usage example \"./oclvanitygen -C LTC Lfoo\"\n"
					"List of Available Alt-Coins for Address Generation\n"
					"---------------------------------------------------\n"
					"Argument(UPPERCASE) : Coin : Address Prefix\n"
					"---------------\n"
					"ETH : Ethereum : 0x\n"
					);
				vg_print_alicoin_help_msg();
				return 1;
			}
			else
			if (strcmp(optarg, "ETH")== 0) {
				fprintf(stderr,
						"Generating/Decrypting ETH Address\n");
				addrtype_opt = ADDR_TYPE_ETH;
				privtype_opt = PRIV_TYPE_ETH;
				break;
			}
			else {
				// Read from base58prefix.txt
				fprintf(stderr, "Generating/Decrypting %s Address\n", optarg);
				if (vg_get_altcoin(optarg, &addrtype_opt, &privtype_opt)) {
					return 1;
				}
				if (strcmp(optarg, "GRS")== 0) {
					GRSFlag = 1;
				}
			}
			break;

/*END ALTCOIN GENERATOR*/
		case '8':
			pkcs8 = 1;
			break;
		case 'E':
			if (pass_prompt) {
				usage(argv[0]);
				return 1;
			}
			pass_in = optarg;
			if (!vg_check_password_complexity(pass_in, 1))
				fprintf(stderr,
					"WARNING: Using weak password\n");
			break;
		case 'e':
			if (pass_in) {
				usage(argv[0]);
				return 1;
			}
			pass_prompt = 1;
			break;
		case 'c':
			key2_in = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'G':
			generate = 1;
			break;
		case 'd':
			decrypt = 1;
			break;
		case 'X':
			addrtype_opt = atoi(optarg);
			privtype_opt = addrtype + 128;
			addrtype_override = 1;
			break;
		case 'Y':
			privtype_opt = atoi(optarg);
			addrtype_override = 1;
			break;
		case 'F':
                        if (!strcmp(optarg, "compressed")) {
                                compressed = 1;
			}
                        else {
				fprintf(stderr,
					"Invalid choice '%s'\n", optarg);
				return 1;
			}
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}
	if (addrtype_override)
	{
		addrtype = addrtype_opt;
		privtype = privtype_opt;
	}


	OpenSSL_add_all_algorithms();

	pkey = EC_KEY_new_by_curve_name(NID_secp256k1);

	if (generate) {
		unsigned char *pend = (unsigned char *) pbuf;
		EC_KEY_generate_key(pkey);
		res = i2o_ECPublicKey(pkey, &pend);
		fprintf(stderr, "Pubkey (hex): ");
		dumphex((unsigned char *)pbuf, res);
		fprintf(stderr, "Privkey (hex): ");
		dumpbn(EC_KEY_get0_private_key(pkey));
		vg_encode_address(EC_KEY_get0_public_key(pkey),
				  EC_KEY_get0_group(pkey),
				  addrtype, 0, ecprot);
		printf("Address: %s\n", ecprot);
		vg_encode_privkey(pkey, privtype, ecprot);
		printf("Privkey: %s\n", ecprot);
		return 0;
	}

	if (optind >= argc) {
		res = fread(pbuf, 1, sizeof(pbuf) - 1, stdin);
		pbuf[res] = '\0';
		key_in = pbuf;
	} else {
		key_in = argv[optind];
	}

	if (decrypt) {
		if (EVP_read_pw_string(pwbuf, sizeof(pwbuf),
				       "Enter import password:", 0) ||
		    !vg_protect_decode_privkey(pkey, &privtype, key_in, pwbuf))
			return 1;
		res = 1;
	} else
		res = vg_decode_privkey_any(pkey, &privtype, key_in, NULL);

	if (!res) {
		fprintf(stderr, "ERROR: Unrecognized key format\n");
		return 1;
	}

	if (res == 2) {
		compressed = 1;
	}

	if (key2_in) {
		BN_CTX *bnctx;
		BIGNUM *bntmp, *bntmp2;
		EC_KEY *pkey2;

		pkey2 = EC_KEY_new_by_curve_name(NID_secp256k1);
		res = vg_decode_privkey_any(pkey2, &privtype, key2_in, NULL);
		if (res < 0) {
			if (EVP_read_pw_string(pwbuf, sizeof(pwbuf),
					       "Enter import password:", 0) ||
			    !vg_decode_privkey_any(pkey2, &privtype,
						   key2_in, pwbuf))
				return 1;
		}

		if (!res) {
			fprintf(stderr, "ERROR: Unrecognized key format\n");
			return 1;
		}

		if (res == 2) {
			compressed = 1;
		}

		bntmp = BN_new();
		bntmp2 = BN_new();
		bnctx = BN_CTX_new();
		EC_GROUP_get_order(EC_KEY_get0_group(pkey), bntmp2, NULL);
		BN_mod_add(bntmp,
			   EC_KEY_get0_private_key(pkey),
			   EC_KEY_get0_private_key(pkey2),
			   bntmp2,
			   bnctx);
		vg_set_privkey(bntmp, pkey);
		EC_KEY_free(pkey2);
		BN_clear_free(bntmp);
		BN_clear_free(bntmp2);
		BN_CTX_free(bnctx);
	}

	if (pass_prompt) {
		res = EVP_read_pw_string(pwbuf, sizeof(pwbuf),
					 "Enter password:", 1);
		if (res)
			return 1;
		pass_in = pwbuf;
		if (!vg_check_password_complexity(pwbuf, 1))
			fprintf(stderr, "WARNING: Using weak password\n");
	}

	if (addrtype_override)
	{
		addrtype = addrtype_opt;
		privtype = privtype_opt;
	}

	if (verbose) {
		unsigned char *pend = (unsigned char *) pbuf;
		res = i2o_ECPublicKey(pkey, &pend);
		fprintf(stderr, "Pubkey (hex): ");
		dumphex((unsigned char *)pbuf, res);
		fprintf(stderr, "Privkey (hex): ");
		dumpbn(EC_KEY_get0_private_key(pkey));
	}

	if (pkcs8) {
		res = vg_pkcs8_encode_privkey(pbuf, sizeof(pbuf),
					      pkey, pass_in);
		if (!res) {
			fprintf(stderr,
				"ERROR: Could not encode private key\n");
			return 1;
		}
		printf("%s", pbuf);
	}

	else if (pass_in) {
		res = vg_protect_encode_privkey(ecprot, pkey, privtype,
						parameter_group, pass_in);

		if (!res) {
			fprintf(stderr, "ERROR: could not password-protect "
				"private key\n");
			return 1;
		}

		vg_encode_address(EC_KEY_get0_public_key(pkey),
				  EC_KEY_get0_group(pkey),
				  addrtype, 0, pwbuf);
		printf("Address: %s\n", pwbuf);
		printf("Protkey: %s\n", ecprot);
	}

	else {
		if (compressed) {
			vg_encode_address_compressed(EC_KEY_get0_public_key(pkey),
						     EC_KEY_get0_group(pkey),
						     addrtype, ecprot);
			printf("Address: %s\n", ecprot);
			vg_encode_privkey_compressed(pkey, privtype, ecprot);
			printf("Privkey: %s\n", ecprot);
		} else {
			vg_encode_address(EC_KEY_get0_public_key(pkey),
					  EC_KEY_get0_group(pkey),
					  addrtype, 0, ecprot);
			printf("Address: %s\n", ecprot);
			vg_encode_privkey(pkey, privtype, ecprot);
			printf("Privkey: %s\n", ecprot);
		}
	}

	OPENSSL_cleanse(pwbuf, sizeof(pwbuf));

	EC_KEY_free(pkey);
	return 0;
}
