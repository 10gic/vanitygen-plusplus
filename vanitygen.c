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

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <time.h>
#include <pthread.h>

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "pattern.h"
#include "util.h"
#include "ed25519.h"
#include "simplevanitygen.h"

#include "ticker.h"
char ticker[10];

int GRSFlag = 0;

const char *version = VANITYGEN_VERSION;


/*
 * Address search thread main loop
 */

void *
vg_thread_loop(void *arg)
{
	unsigned char hash_buf[128];
	unsigned char *eckey_buf;
	unsigned char hash1[32];

	int i, c, len, output_interval;
	int hash_len;

	const BN_ULONG rekey_max = 10000000;
	BN_ULONG npoints, rekey_at, nbatch;

	vg_context_t *vcp = (vg_context_t *) arg;
	EC_KEY *pkey = NULL;
	const EC_GROUP *pgroup;
	const EC_POINT *pgen;
	const int ptarraysize = 256;
	EC_POINT *ppnt[ptarraysize];
	EC_POINT *pbatchinc;

	vg_test_func_t test_func = vcp->vc_test;
	vg_exec_context_t ctx;
	vg_exec_context_t *vxcp;

	struct timeval tvstart;


	memset(&ctx, 0, sizeof(ctx));
	vxcp = &ctx;

	vg_exec_context_init(vcp, &ctx);

	pkey = vxcp->vxc_key;
	pgroup = EC_KEY_get0_group(pkey);
	pgen = EC_GROUP_get0_generator(pgroup);

	for (i = 0; i < ptarraysize; i++) {
		ppnt[i] = EC_POINT_new(pgroup);
		if (!ppnt[i]) {
			fprintf(stderr, "ERROR: out of memory?\n");
			exit(1);
		}
	}
	pbatchinc = EC_POINT_new(pgroup);
	if (!pbatchinc) {
		fprintf(stderr, "ERROR: out of memory?\n");
		exit(1);
	}

	BN_set_word(vxcp->vxc_bntmp, ptarraysize);
	EC_POINT_mul(pgroup, pbatchinc, vxcp->vxc_bntmp, NULL, NULL,
		     vxcp->vxc_bnctx);
	EC_POINT_make_affine(pgroup, pbatchinc, vxcp->vxc_bnctx);

	npoints = 0;
	rekey_at = 0;
	nbatch = 0;
	vxcp->vxc_key = pkey;
	vxcp->vxc_binres[0] = vcp->vc_addrtype;
	c = 0;
	output_interval = 1000;
	gettimeofday(&tvstart, NULL);

	if (vcp->vc_format == VCF_SCRIPT) {
		hash_buf[ 0] = 0x51;  // OP_1
		hash_buf[ 1] = 0x41;  // pubkey length
		// gap for pubkey
		hash_buf[67] = 0x51;  // OP_1
		hash_buf[68] = 0xae;  // OP_CHECKMULTISIG
		eckey_buf = hash_buf + 2;
		hash_len = 69;

	} else {
		eckey_buf = hash_buf;
		hash_len = (vcp->vc_compressed)?33:65;
	}

	while (!vcp->vc_halt) {
		if (++npoints >= rekey_at) {
			vg_exec_context_upgrade_lock(vxcp);
		regen_key:
			/* Generate a new random private key */
			EC_KEY_generate_key(pkey);
			if (vcp->vc_privkey_prefix_nbits > 0) {
				/* Adjust private key to meet the requirement of privkey prefix (specified by option -Z) */
				BIGNUM *pkbn = BN_dup(EC_KEY_get0_private_key(pkey));
				unsigned char pkey_arr[32];
				assert(BN_bn2bin(pkbn, pkey_arr) < 33);
				copy_nbits((unsigned char *) pkey_arr, (unsigned char *)vcp->vc_privkey_prefix, vcp->vc_privkey_prefix_nbits);
				BN_bin2bn(pkey_arr, 32, pkbn);
				if (BN_is_zero(pkbn)) {
					fprintf(stderr, "the generated private key is zero, regenerate it\n");
					goto regen_key;
				}
				// FIXME: private key (pbkn) may be too big if prefix specified by -Z has many FF
				EC_KEY_set_private_key(pkey, pkbn); /* set private key in pkey */

				EC_POINT *origin = EC_POINT_new(pgroup);
				/* EC_POINT_mul: compute public_key = k * private_key
				   here, origin is public_key, pkbn is private_key
				   save public_key into 2nd param (origin) */
				EC_POINT_mul(pgroup, origin, pkbn, NULL, NULL, vxcp->vxc_bnctx);
				EC_KEY_set_public_key(pkey, origin); /* set public key in pkey */
			}
			npoints = 0;

			/* Determine rekey interval */
			EC_GROUP_get_order(pgroup, vxcp->vxc_bntmp,
					   vxcp->vxc_bnctx);
			BN_sub(vxcp->vxc_bntmp2,
			       vxcp->vxc_bntmp,
			       EC_KEY_get0_private_key(pkey));
			rekey_at = BN_get_word(vxcp->vxc_bntmp2);
			if ((rekey_at == 0xffffffffL) || (rekey_at > rekey_max))
				rekey_at = rekey_max;
			assert(rekey_at > 0);

			EC_POINT_copy(ppnt[0], EC_KEY_get0_public_key(pkey));
			vg_exec_context_downgrade_lock(vxcp);

			npoints++;
			vxcp->vxc_delta = 0;

			if (vcp->vc_pubkey_base)
				EC_POINT_add(pgroup,
					     ppnt[0],
					     ppnt[0],
					     vcp->vc_pubkey_base,
					     vxcp->vxc_bnctx);

			for (nbatch = 1;
			     (nbatch < ptarraysize) && (npoints < rekey_at);
			     nbatch++, npoints++) {
				EC_POINT_add(pgroup,
					     ppnt[nbatch],
					     ppnt[nbatch-1],
					     pgen, vxcp->vxc_bnctx);
			}

		} else {
			/*
			 * Common case
			 *
			 * EC_POINT_add() can skip a few multiplies if
			 * one or both inputs are affine (Z_is_one).
			 * This is the case for every point in ppnt, as
			 * well as pbatchinc.
			 */
			assert(nbatch == ptarraysize);
			for (nbatch = 0;
			     (nbatch < ptarraysize) && (npoints < rekey_at);
			     nbatch++, npoints++) {
				/* compute public keys from continuous private key,
				   save public keys into array ppnt */
				EC_POINT_add(pgroup,
					     ppnt[nbatch],
					     ppnt[nbatch],
					     pbatchinc,
					     vxcp->vxc_bnctx);
			}
		}

		/*
		 * The single most expensive operation performed in this
		 * loop is modular inversion of ppnt->Z.  There is an
		 * algorithm implemented in OpenSSL to do batched inversion
		 * that only does one actual BN_mod_inverse(), and saves
		 * a _lot_ of time.
		 *
		 * To take advantage of this, we batch up a few points,
		 * and feed them to EC_POINTs_make_affine() below.
		 */

		EC_POINTs_make_affine(pgroup, nbatch, ppnt, vxcp->vxc_bnctx);

		for (i = 0; i < nbatch; i++, vxcp->vxc_delta++) {
			/* Hash the public key */
			len = EC_POINT_point2oct(pgroup, ppnt[i],
						 (vcp->vc_compressed)?POINT_CONVERSION_COMPRESSED:POINT_CONVERSION_UNCOMPRESSED,
						 eckey_buf,
						 (vcp->vc_compressed)?33:65,
						 vxcp->vxc_bnctx);
			assert(len == 65 || len == 33);
			if (vcp->vc_addrtype == ADDR_TYPE_ETH) {
				// Save ETH address into vxcp->vxc_binres
				eth_pubkey2addr(eckey_buf, vxcp->vxc_vc->vc_format, vxcp->vxc_binres);
			} else {
				SHA256(hash_buf, hash_len, hash1);
				RIPEMD160(hash1, sizeof(hash1), &vxcp->vxc_binres[1]);
			}

			switch (test_func(vxcp)) {
			case 1:
				npoints = 0;
				rekey_at = 0;
				i = nbatch;
				break;
			case 2:
				goto out;
			default:
				break;
			}
		}

		c += i;
		if (c >= output_interval) {
			output_interval = vg_output_timing(vcp, c, &tvstart);
			if (output_interval > 250000)
				output_interval = 250000;
			c = 0;
		}

		vg_exec_context_yield(vxcp);
	}

out:
	vg_exec_context_del(&ctx);
	vg_context_thread_exit(vcp);

	for (i = 0; i < ptarraysize; i++)
		if (ppnt[i])
			EC_POINT_free(ppnt[i]);
	if (pbatchinc)
		EC_POINT_free(pbatchinc);
	return NULL;
}

int
start_threads(vg_context_t *vcp, int nthreads)
{
	pthread_t thread;

	if (nthreads <= 0) {
		/* Determine the number of threads */
		nthreads = count_processors();
		if (nthreads <= 0) {
			fprintf(stderr,
				"ERROR: could not determine processor count\n");
			nthreads = 1;
		}
	}

	if (vcp->vc_verbose > 1) {
		fprintf(stderr, "Using %d worker thread(s)\n", nthreads);
	}

	while (--nthreads) {
		if (pthread_create(&thread, NULL, vg_thread_loop, vcp))
			return 0;
	}

	vg_thread_loop(vcp);
	return 1;
}


void
usage(const char *name)
{
	fprintf(stderr,
"Vanitygen %s (" OPENSSL_VERSION_TEXT ")\n"
"Usage: %s [-vqnrik1NT] [-t <threads>] [-f <filename>|-] [<pattern>...]\n"
"Generates a bitcoin receiving address matching <pattern>, and outputs the\n"
"address and associated private key.  The private key may be stored in a safe\n"
"location or imported into a bitcoin client to spend any balance received on\n"
"the address.\n"
"By default, <pattern> is interpreted as an exact prefix.\n"
"\n"
"Options:\n"
"-v            Verbose output\n"
"-q            Quiet output\n"
"-n            Simulate\n"
"-r            Use regular expression match instead of prefix\n"
"              (Feasibility of expression is not checked)\n"
"-i            Case-insensitive prefix search\n"
"-k            Keep pattern and continue search after finding a match\n"
"-1            Stop after first match\n"
"-a <amount>   Stop after generating <amount> addresses/keys\n"
"-C <altcoin>  Generate an address for specific altcoin, use \"-C LIST\" to view\n"
"              a list of all available altcoins, argument is case sensitive!\n"
"-X <version>  Generate address with the given version\n"
"-Y <version>  Specify private key version (-X provides public key)\n"
"-F <format>   Generate address with the given format (pubkey, compressed, script)\n"
"-P <pubkey>   Use split-key method with <pubkey> as base public key\n"
"-e            Encrypt private keys, prompt for password\n"
"-E <password> Encrypt private keys with <password> (UNSAFE)\n"
"-t <threads>  Set number of worker threads (Default: number of CPUs)\n"
"-f <file>     File containing list of patterns, one per line\n"
"              (Use \"-\" as the file name for stdin)\n"
"-o <file>     Write pattern matches to <file>\n"
"-s <file>     Seed random number generator from <file>\n"
"-Z <prefix>   Private key prefix in hex (1Address.io Dapp front-running protection)\n"
"-l <nbits>    Specify number of bits in prefix, only relevant when -Z is specified\n"
"-z            Format output of matches in CSV(disables verbose mode)\n"
"              Output as [COIN],[PREFIX],[ADDRESS],[PRIVKEY]\n",
version, name);
}

#define MAX_FILE 4

int
main(int argc, char **argv)
{
	int addrtype = 0;
	int scriptaddrtype = 5;
	int privtype = 128;
	int pubkeytype;
	enum vg_format format = VCF_PUBKEY;
	int regex = 0;
	int caseinsensitive = 0;
	int verbose = 1;
	int simulate = 0;
	int remove_on_match = 1;
	int only_one = 0;
	int numpairs = 0;
	int csv = 0;
	int prompt_password = 0;
	int opt;
	char *seedfile = NULL;
	char pwbuf[128];
	const char *result_file = NULL;
	const char *key_password = NULL;
	char **patterns;
	int npatterns = 0;
	int nthreads = 0;
	vg_context_t *vcp = NULL;
	EC_POINT *pubkey_base = NULL;
	char privkey_prefix[32];
	int privkey_prefix_length = 0;
	int privkey_prefix_nbits = 0;

	FILE *pattfp[MAX_FILE], *fp;
	int pattfpi[MAX_FILE];
	int npattfp = 0;
	int pattstdin = 0;
	int compressed = 0;

	int i;

	while ((opt = getopt(argc, argv, "vqnrik1ezE:P:C:X:Y:F:t:h?f:o:s:Z:a:l:")) != -1) {
		switch (opt) {
		case 'c':
		        compressed = 1;
		        break;
		case 'v':
			verbose = 2;
			break;
		case 'q':
			verbose = 0;
			break;
		case 'n':
			simulate = 1;
			break;
		case 'r':
			regex = 1;
			break;
		case 'i':
			caseinsensitive = 1;
			break;
		case 'k':
			remove_on_match = 0;
			break;
		case 'a':
			remove_on_match = 0;
			numpairs = atoi(optarg);
			break;
		case '1':
			only_one = 1;
			break;
		case 'z':
			csv = 1;
			break;

/*BEGIN ALTCOIN GENERATOR*/

		case 'C':
			strcpy(ticker, optarg);
			strcat(ticker, " ");
			/* Start AltCoin Generator */
			if (strcmp(optarg, "LIST")== 0) {
				fprintf(stderr,
					"Usage example \"./vanitygen++ -C ETH 0x1234\"\n"
					"List of Available Alt-Coins for Address Generation\n"
					"---------------------------------------------------\n"
					"Argument(UPPERCASE) : Coin : Address Prefix\n"
					"---------------\n"
					"ETH : Ethereum : 0x\n"
					"XLM : Stellar Lumens : G\n"
					);
				vg_print_alicoin_help_msg();
				return 1;
			}
			else
			if (strcmp(optarg, "ETH")== 0) {
				fprintf(stderr,
						"Generating ETH Address\n");
				addrtype = ADDR_TYPE_ETH;
				privtype = PRIV_TYPE_ETH;
				break;
			}
			else
			if (strcmp(optarg, "XLM")== 0) {
				fprintf(stderr,
						"Generating XLM Address\n");
				addrtype = ADDR_TYPE_XLM;
				privtype = PRIV_TYPE_XLM;
			}
			else {
				// Read from base58prefix.txt
				fprintf(stderr, "Generating %s Address\n", optarg);
				if (vg_get_altcoin(optarg, &addrtype, &privtype)) {
					return 1;
				}
                if (strcmp(optarg, "GRS")== 0) {
                    GRSFlag = 1;
                }
			}
			break;

/*END ALTCOIN GENERATOR*/

		case 'X':
			addrtype = atoi(optarg);
			privtype = 128 + addrtype;
			scriptaddrtype = addrtype;
			break;
		case 'Y':
			/* Overrides privtype of 'X' but leaves all else intact */
			privtype = atoi(optarg);
			break;
		case 'F':
			if (!strcmp(optarg, "contract"))
				format = VCF_CONTRACT;
			else
			if (!strcmp(optarg, "script"))
				format = VCF_SCRIPT;
			else
			if (!strcmp(optarg, "p2wpkh"))
				format = VCF_P2WPKH;
			else
			if (!strcmp(optarg, "p2tr"))
				format = VCF_P2TR;
			else
			if (!strcmp(optarg, "compressed"))
				compressed = 1;
			else
			if (strcmp(optarg, "pubkey")) {
				fprintf(stderr,
					"Invalid format '%s'\n", optarg);
				return 1;
			}
			break;
		case 'P': {
			if (pubkey_base != NULL) {
				fprintf(stderr,
					"Multiple base pubkeys specified\n");
				return 1;
			}
			EC_KEY *pkey = vg_exec_context_new_key();
			pubkey_base = EC_POINT_hex2point(
				EC_KEY_get0_group(pkey),
				optarg, NULL, NULL);
			EC_KEY_free(pkey);
			if (pubkey_base == NULL) {
				fprintf(stderr,
					"Invalid base pubkey\n");
				return 1;
			}
			break;
		}

		case 'e':
			prompt_password = 1;
			break;
		case 'E':
			key_password = optarg;
			break;
		case 't':
			nthreads = atoi(optarg);
			if (nthreads == 0) {
				fprintf(stderr,
					"Invalid thread count '%s'\n", optarg);
				return 1;
			}
			break;
		case 'f':
			if (npattfp >= MAX_FILE) {
				fprintf(stderr,
					"Too many input files specified\n");
				return 1;
			}
			if (!strcmp(optarg, "-")) {
				if (pattstdin) {
					fprintf(stderr, "ERROR: stdin "
						"specified multiple times\n");
					return 1;
				}
				fp = stdin;
			} else {
				fp = fopen(optarg, "r");
				if (!fp) {
					fprintf(stderr,
						"Could not open %s: %s\n",
						optarg, strerror(errno));
					return 1;
				}
			}
			pattfp[npattfp] = fp;
			pattfpi[npattfp] = caseinsensitive;
			npattfp++;
			break;
		case 'o':
			if (result_file) {
				fprintf(stderr,
					"Multiple output files specified\n");
				return 1;
			}
			result_file = optarg;
			break;
		case 's':
			if (seedfile != NULL) {
				fprintf(stderr,
					"Multiple RNG seeds specified\n");
				return 1;
			}
			seedfile = optarg;
			break;
		case 'Z':
			assert(strlen(optarg) % 2 == 0);
			privkey_prefix_length = strlen(optarg)/2;
			for (i = 0; i < privkey_prefix_length; i++) {
				int value; // Can't sscanf directly to char array because of overlapping on Win32
				sscanf(&optarg[i*2], "%2x", &value);
				privkey_prefix[i] = value;
			}
			break;
		case 'l':
			privkey_prefix_nbits = atoi(optarg);
			if (privkey_prefix_nbits == 0) {
				fprintf(stderr, "Invalid number of bits `%s` specified\n", optarg);
				return 1;
			}
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

#if OPENSSL_VERSION_NUMBER < 0x10000000L
	/* Complain about older versions of OpenSSL */
	if (verbose > 0) {
		fprintf(stderr,
			"WARNING: Built with " OPENSSL_VERSION_TEXT "\n"
			"WARNING: Use OpenSSL 1.0.0d+ for best performance\n");
	}
#endif

	if (addrtype == ADDR_TYPE_XLM) {
#if OPENSSL_VERSION_NUMBER < 0x10101000L
        fprintf(stderr, "OpenSSL 1.1.1 (or higher) is required for XLM\n");
#else
	    if (optind >= argc) {
			usage(argv[0]);
			return 1;
		}
		patterns = &argv[optind];
		printf("XLM patterns %s\n", *patterns);

        vg_context_ed25519_t *vc_ed25519 = NULL;
        vc_ed25519 = (vg_context_ed25519_t *) malloc(sizeof(*vc_ed25519));
		vc_ed25519->vc_verbose = verbose;
		vc_ed25519->vc_addrtype = addrtype;
		vc_ed25519->vc_privtype = privtype;
		vc_ed25519->vc_result_file = result_file;
		vc_ed25519->vc_numpairs = numpairs;
		if (vc_ed25519->vc_numpairs == 0) {
            vc_ed25519->vc_numpairs = 1;
		}
		vc_ed25519->pattern = *patterns;
        vc_ed25519->match_location = 1; // match begin location

        size_t pattern_len = strlen(vc_ed25519->pattern);

        if (vc_ed25519->vc_addrtype == ADDR_TYPE_XLM) {
            if (pattern_len > 56) { // The max length of XLM address is 56
                fprintf(stderr, "The pattern is too long for XLM address\n");
                return 1;
            }
        }
        if (regex) {
            fprintf(stderr, "WARNING: only ^ and $ is supported in regular expressions currently\n");
            if (vc_ed25519->pattern[0] == '^') {
                vc_ed25519->match_location = 1; // match begin location
                // skip first char '^'
				vc_ed25519->pattern = vc_ed25519->pattern + 1;
            } else if (vc_ed25519->pattern[pattern_len-1] == '$') {
                vc_ed25519->match_location = 2; // match end location
                // remove last char '$'
				vc_ed25519->pattern[pattern_len-1] = '\0';
            } else {
                vc_ed25519->match_location = 0; // match any location
            }
        }

        if (vc_ed25519->match_location == 1 && vc_ed25519->pattern[0] != 'G') {
            fprintf(stderr, "Prefix '%s' not possible\n", vc_ed25519->pattern);
            fprintf(stderr, "Hint: Run vanitygen++ with \"-C LIST\" for a list of valid prefixes.  Also note that many coins only allow certain characters as the second character in the prefix.\n");
            return 1;
        }

		if (nthreads <= 0) {
			/* Determine the number of threads */
			nthreads = count_processors();
			if (nthreads <= 0) {
				fprintf(stderr, "ERROR: could not determine processor count\n");
				nthreads = 1;
			}

			if (nthreads > ed25519_max_threads) {
				fprintf(stderr, "WARNING: too many threads\n");
				nthreads = ed25519_max_threads;
			}
		}
		vc_ed25519->vc_thread_num = nthreads;
		vc_ed25519->vc_start_time = (unsigned long)time(NULL);

		if (!start_threads_ed25519(vc_ed25519))
			return 1;
#endif
		return 0;
	}

	if (format == VCF_P2WPKH || format == VCF_P2TR) {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		fprintf(stderr, "OpenSSL 3.0 (or higher) is required for P2WPKH or P2TR address\n");
		return 1;
#else
		if (optind >= argc) {
			usage(argv[0]);
			return 1;
		}
		patterns = &argv[optind];
		printf("Pattern: %s\n", *patterns);

		vg_context_simplevanitygen_t *vc_simplevanitygen = NULL;
		vc_simplevanitygen = (vg_context_simplevanitygen_t *) malloc(sizeof(*vc_simplevanitygen));
		vc_simplevanitygen->vc_format = format;
		vc_simplevanitygen->vc_verbose = verbose;
		vc_simplevanitygen->vc_addrtype = addrtype;
		vc_simplevanitygen->vc_privtype = privtype;
		vc_simplevanitygen->vc_result_file = result_file;
		vc_simplevanitygen->vc_numpairs = numpairs;
		if (vc_simplevanitygen->vc_numpairs == 0) {
			vc_simplevanitygen->vc_numpairs = 1;
		}
		vc_simplevanitygen->pattern = *patterns;
		vc_simplevanitygen->match_location = 1; // By default, match begin location

		size_t pattern_len = strlen(vc_simplevanitygen->pattern);

		if (regex) {
			fprintf(stderr, "WARNING: only ^ and $ is supported in regular expressions currently\n");
			if (vc_simplevanitygen->pattern[0] == '^') {
				vc_simplevanitygen->match_location = 1; // match begin location
				// skip first char '^'
				vc_simplevanitygen->pattern = vc_simplevanitygen->pattern + 1;
			} else if (vc_simplevanitygen->pattern[pattern_len-1] == '$') {
				vc_simplevanitygen->match_location = 2; // match end location
				// remove last char '$'
				vc_simplevanitygen->pattern[pattern_len-1] = '\0';
			} else {
				vc_simplevanitygen->match_location = 0; // match any location
			}
		}

		if (vc_simplevanitygen->match_location == 1) {
			if (vc_simplevanitygen->vc_format == VCF_P2WPKH && strncmp(vc_simplevanitygen->pattern, "bc1q", strlen("bc1q")) != 0) {
				fprintf(stderr, "Prefix '%s' not possible, address must starts with bc1q for p2wpkh\n", vc_simplevanitygen->pattern);
				return 1;
			} else if (vc_simplevanitygen->vc_format == VCF_P2TR && strncmp(vc_simplevanitygen->pattern, "bc1p", strlen("bc1p")) != 0) {
				fprintf(stderr, "Prefix '%s' not possible, address must starts with bc1p for p2tr\n", vc_simplevanitygen->pattern);
				return 1;
			}
		}

		if (nthreads <= 0) {
			/* Determine the number of threads */
			nthreads = count_processors();
			if (nthreads <= 0) {
				fprintf(stderr, "ERROR: could not determine processor count\n");
				nthreads = 1;
			}

			if (nthreads > simplevanitygen_max_threads) {
				fprintf(stderr, "WARNING: too many threads\n");
				nthreads = simplevanitygen_max_threads;
			}
		}
		vc_simplevanitygen->vc_thread_num = nthreads;
		vc_simplevanitygen->vc_start_time = (unsigned long)time(NULL);

		if (!start_threads_simplevanitygen(vc_simplevanitygen))
			return 1;

		return 0;
#endif
	}

	/* Option -Z can be used with or without option -l
	   but, option -l must use together with option -Z */
	if (privkey_prefix_length == 0) { /* -Z not specified */
		if (privkey_prefix_nbits > 0) { /* -l specified */
			fprintf(stderr, "-l must use together with -Z)\n");
			return 1;
		}
	} else if (privkey_prefix_length > 0) { /* -Z specified */
		if (privkey_prefix_nbits == 0) { /* -l not specified */
			privkey_prefix_nbits = privkey_prefix_length * 8;
		} else if (privkey_prefix_nbits > 0) { /* -l specified */
			if (privkey_prefix_nbits > privkey_prefix_length * 8) {
				fprintf(stderr, "bits (specified by -l) is too big, must small than bits of prefix (%d bits)\n", privkey_prefix_length * 8);
				return 1;
			}
		}
	}

	if (caseinsensitive && regex)
		fprintf(stderr,
			"WARNING: case insensitive mode incompatible with "
			"regular expressions\n");

	pubkeytype = addrtype;
	if (format == VCF_SCRIPT)
	{
		if (scriptaddrtype == -1)
		{
			fprintf(stderr,
				"Address type incompatible with script format\n");
			return 1;
		}
		addrtype = scriptaddrtype;
	}

	if (seedfile) {
		opt = -1;
#if !defined(_WIN32)
		{	struct stat st;
			if (!stat(seedfile, &st) &&
			    (st.st_mode & (S_IFBLK|S_IFCHR))) {
				opt = 32;
		} }
#endif
		opt = RAND_load_file(seedfile, opt);
		if (!opt) {
			fprintf(stderr, "Could not load RNG seed %s\n", optarg);
			return 1;
		}
		if (verbose > 0) {
			fprintf(stderr,
				"Read %d bytes from RNG seed file\n", opt);
		}
	}

	if (regex) {
		vcp = vg_regex_context_new(addrtype, privtype);

	} else {
		vcp = vg_prefix_context_new(addrtype, privtype,
					    caseinsensitive);
	}

	vcp->vc_compressed = compressed;
	vcp->vc_verbose = verbose;
	vcp->vc_result_file = result_file;
	vcp->vc_remove_on_match = remove_on_match;
	vcp->vc_numpairs = numpairs;
	vcp->vc_csv = csv;
	vcp->vc_only_one = only_one;
	vcp->vc_format = format;
	vcp->vc_pubkeytype = pubkeytype;
	vcp->vc_pubkey_base = pubkey_base;
	memcpy(vcp->vc_privkey_prefix, privkey_prefix, privkey_prefix_length);
	vcp->vc_privkey_prefix_nbits = privkey_prefix_nbits;

	vcp->vc_output_match = vg_output_match_console;
	vcp->vc_output_timing = vg_output_timing_console;

	if (!npattfp) {
		if (optind >= argc) {
			usage(argv[0]);
			return 1;
		}
		patterns = &argv[optind];
		npatterns = argc - optind;

		if (!vg_context_add_patterns(vcp,
					     (const char ** const) patterns,
					     npatterns))
		return 1;
	}

	for (i = 0; i < npattfp; i++) {
		fp = pattfp[i];
		if (!vg_read_file(fp, &patterns, &npatterns)) {
			fprintf(stderr, "Failed to load pattern file\n");
			return 1;
		}
		if (fp != stdin)
			fclose(fp);

		if (!regex)
			vg_prefix_context_set_case_insensitive(vcp, pattfpi[i]);

		if (!vg_context_add_patterns(vcp,
					     (const char ** const) patterns,
					     npatterns))
		return 1;
	}

	if (!vcp->vc_npatterns) {
		fprintf(stderr, "No patterns to search\n");
		return 1;
	}

	if (prompt_password) {
		if (!vg_read_password(pwbuf, sizeof(pwbuf)))
			return 1;
		key_password = pwbuf;
	}
	vcp->vc_key_protect_pass = key_password;
	if (key_password) {
		if (!vg_check_password_complexity(key_password, verbose))
			fprintf(stderr,
				"WARNING: Protecting private keys with "
				"weak password\n");
	}

	if ((verbose > 0) && regex && (vcp->vc_npatterns > 1))
		fprintf(stderr,
			"Regular expressions: %ld\n", vcp->vc_npatterns);

	if (simulate)
		return 0;

	if (!start_threads(vcp, nthreads))
		return 1;
	return 0;
}
