#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <memory.h>
#include <assert.h>
#include "base32.h"
#include "util.h"
#include "simplevanitygen.h"
#include "pattern.h"
#include "segwit_addr.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>

static pthread_t TID[simplevanitygen_max_threads];

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER; // protect vc_simplevanitygen->vc_found_num

// return thread index in array TID, return -1 if not found (you need check again).
int get_thread_index1(int max_index) {
    pthread_t t = pthread_self();
    int i;
    for (i = 0; i < max_index; i++) {
        if (pthread_equal(TID[i], t) != 0) {
            return i;
        }
    }
    return -1;
}

void
output_check_info1(vg_context_simplevanitygen_t *vcp) {
    double targ;
    char linebuf[80];
    int rem, p;
    char *unit;
    unsigned long current_time = (unsigned long) time(NULL);
    unsigned long long total = 0;
    int i;
    for (i = 0; i < vcp->vc_thread_num; i++) {
        total += vcp->vc_check_count[i];
    }

    targ = total / (current_time - vcp->vc_start_time + 0.001); // plus 0.001 to avoid zero
    unit = "key/s";
    if (targ > 1000) {
        unit = "Kkey/s";
        targ /= 1000.0;
        if (targ > 1000) {
            unit = "Mkey/s";
            targ /= 1000.0;
        }
    }

    rem = sizeof(linebuf);
    p = snprintf(linebuf, rem, "[%.2f %s][total %lld]",
                 targ, unit, total);
    assert(p > 0);
    rem -= p;
    if (rem < 0)
        rem = 0;
    if (rem) {
        memset(&linebuf[sizeof(linebuf) - rem], 0x20, rem);
        linebuf[sizeof(linebuf) - 1] = '\0';
    }
    printf("\r%s", linebuf);
    fflush(stdout);
}

void *
get_public_key(EVP_PKEY *pkey, unsigned char *pub_buf, size_t buf_len, int form, size_t *output_len) {
    // See https://stackoverflow.com/questions/18155559/how-does-one-access-the-raw-ecdh-public-key-private-key-and-params-inside-opens
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    EC_POINT *ppoint = EC_KEY_get0_public_key(ec_key);
    EC_GROUP *pgroup = EC_KEY_get0_group(ec_key);
    *output_len = EC_POINT_point2oct(pgroup,
                                     ppoint,
                                     form,
                                     pub_buf,
                                     buf_len,
                                     NULL);
}

void *
get_private_key(EVP_PKEY *pkey, unsigned char *pub_buf, size_t buf_len, size_t *output_len) {
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    BIGNUM *pkbn = EC_KEY_get0_private_key(ec_key);
    *output_len = BN_bn2bin(pkbn, pub_buf);
}

void *
thread_loop_simplevanitygen(void *arg) {
    unsigned char priv_buf[32];
    unsigned char pub_buf[128];  // 65 bytes enough
    size_t pub_buf_len = 128;

    char address[128] = {'\0'};

    int find_it = 0;
    size_t pattern_len;

    int thread_index;

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

    if (EVP_PKEY_keygen_init(pctx) != 1) {
        fprintf(stderr, "EVP_PKEY_keygen_init fail\n");
        return NULL;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, SN_secp256k1, 0);
    params[1] = OSSL_PARAM_construct_end();
    EVP_PKEY_CTX_set_params(pctx, params);

    vg_context_simplevanitygen_t *vc_simplevanitygen = (vg_context_simplevanitygen_t *) arg;

    pattern_len = strlen(vc_simplevanitygen->pattern);

    check_thread_index:
    thread_index = get_thread_index1(vc_simplevanitygen->vc_thread_num);
    if (thread_index == -1) {
        // check again
        if (vc_simplevanitygen->vc_verbose > 1) {
            fprintf(stderr, "thread index not found, check again\n");
        }
        goto check_thread_index;
    }

    int output_timeout = 0;

    while (!vc_simplevanitygen->vc_halt) {
        // Generate a key-pair
        // EVP_PKEY_keygen is slow!
        if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
            fprintf(stderr, "EVP_PKEY_keygen fail\n");
            return NULL;
        }

        vc_simplevanitygen->vc_check_count[thread_index]++;
        output_timeout++;

        if (vc_simplevanitygen->vc_format == VCF_P2WPKH) {
            // Get compressed public key from EVP_PKEY
            size_t output_len = 0;
            get_public_key(pkey, pub_buf, pub_buf_len, POINT_CONVERSION_COMPRESSED, &output_len);

            unsigned char hash1[32], hash2[20];
            SHA256(pub_buf, output_len, hash1);
            RIPEMD160(hash1, sizeof(hash1), hash2);

            // Compute p2wpkh address
            segwit_addr_encode(address,
                               "bc",
                               0,
                               hash2,
                               20);
        } else if (vc_simplevanitygen->vc_format == VCF_P2TR) {
            // Get uncompressed public key from EVP_PKEY
            size_t output_len = 0;
            get_public_key(pkey, pub_buf, pub_buf_len, POINT_CONVERSION_UNCOMPRESSED, &output_len);

            if (pub_buf[64] % 2 != 0) {
                // Y is odd
                // Not implementation lift_x (see BIP340), just skip if found odd Y
                address[0] = '\0';
            } else {
                // Y is even
                unsigned char tagged_hash_preimage[32 + 32 + 32];
                size_t binsz = 32;
                // Note: SHA-256("TapTweak")=e80fe1639c9ca050e3af1b39c143c63e429cbceb15d940fbb5c5a1f4af57c5e9
                hex_dec(tagged_hash_preimage, &binsz,
                        "e80fe1639c9ca050e3af1b39c143c63e429cbceb15d940fbb5c5a1f4af57c5e9", 64);
                binsz = 32;
                hex_dec(tagged_hash_preimage + 32, &binsz,
                        "e80fe1639c9ca050e3af1b39c143c63e429cbceb15d940fbb5c5a1f4af57c5e9", 64);
                memcpy(tagged_hash_preimage + 64,
                       pub_buf + 1, // Skip first byte (0x04)
                       32); // Only get X party

                // Compute tagged hash
                unsigned char tagged_hash[32];
                SHA256(tagged_hash_preimage, 32 + 32 + 32, tagged_hash);

                // Convert to bignum
                BIGNUM *t = BN_new();
                BN_bin2bn(tagged_hash, 32, t);

                EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
                EC_GROUP *pgroup = EC_KEY_get0_group(ec_key);

                // Compute T = t * G
                EC_POINT *T = EC_POINT_new(pgroup);
                EC_POINT_mul(pgroup, T, t, NULL, NULL, NULL);

                // P = public key, if Y of public key is even
                EC_POINT *P = EC_KEY_get0_public_key(ec_key);

                // Compute tweaked pubkey Q
                // Q = P + T
                EC_POINT *Q = EC_POINT_new(pgroup);
                EC_POINT_add(pgroup, Q, P, T, NULL);

                EC_POINT_point2oct(pgroup,
                                   Q,
                                   POINT_CONVERSION_COMPRESSED,
                                   pub_buf,
                                   64,
                                   NULL);

                EC_POINT_free(Q);
                EC_POINT_free(T);
                BN_free(t);

                // Compute p2tr address
                segwit_addr_encode(address,
                                   "bc",
                                   1,
                                   pub_buf + 1, // Skip first byte (0x02 or 0x03)
                                   32); // Only get X party
            }
        }

        // Check address if match pattern
        if (vc_simplevanitygen->match_location == 0) { // any
            if (strstr((const char *) address, vc_simplevanitygen->pattern) != NULL) {
                find_it = 1;
            }
        } else if (vc_simplevanitygen->match_location == 1) { // begin
            if (strncmp(vc_simplevanitygen->pattern, (const char *) address, pattern_len) == 0) {
                find_it = 1;
            }
        } else if (vc_simplevanitygen->match_location == 2) { // end
            if (strncmp(vc_simplevanitygen->pattern, ((const char *) address) + strlen(address) - pattern_len,
                        pattern_len) == 0) {
                find_it = 1;
            }
        }
        if (find_it == 1) {
            pthread_mutex_lock(&mtx);

            if (vc_simplevanitygen->vc_found_num >= vc_simplevanitygen->vc_numpairs) {
                vc_simplevanitygen->vc_halt = 1;
                pthread_mutex_unlock(&mtx);
                goto out;
            }

            vc_simplevanitygen->vc_found_num++;

            printf("\rBTC Address: %s\n", address);

            // get private key from EVP_PKEY
            size_t output_len = 0;
            get_private_key(pkey, (unsigned char *) &priv_buf, pub_buf_len, &output_len);

            fprintf(stdout, "BTC Privkey (hex): ");
            dumphex(priv_buf, output_len);

            vc_simplevanitygen->vc_halt = 1;

            if (vc_simplevanitygen->vc_result_file) {
                FILE *fp = fopen(vc_simplevanitygen->vc_result_file, "a");
                if (!fp) {
                    fprintf(stderr, "ERROR: could not open result file: %s\n", strerror(errno));
                } else {
                    fprintf(fp, "Pattern: %s\n", vc_simplevanitygen->pattern);
                    fprintf(fp, "BTC Address: %s\n", address);
                    fprintf(fp, "BTC Privkey (hex): ");
                    fdumphex(fp, priv_buf, output_len);
                    fclose(fp);
                }
            }

            pthread_mutex_unlock(&mtx);
        }

        if (output_timeout > 1500) {
            output_check_info1(vc_simplevanitygen);
            output_timeout = 0;
        }
    }

    out:
    if (vc_simplevanitygen->vc_verbose > 1) {
        fprintf(stderr, "thread %d check %lld keys\n", thread_index,
                vc_simplevanitygen->vc_check_count[thread_index]);
    }
    EVP_PKEY_CTX_free(pctx);

    return NULL;
}

int start_threads_simplevanitygen(vg_context_simplevanitygen_t *vc_simplevanitygen) {
    int i;
    if (vc_simplevanitygen->vc_verbose > 1) {
        fprintf(stderr, "Using %d worker thread(s)\n", vc_simplevanitygen->vc_thread_num);
    }

    for (i = 0; i < vc_simplevanitygen->vc_thread_num; i++) {
        if (pthread_create(&TID[i], NULL, thread_loop_simplevanitygen, vc_simplevanitygen))
            return 0;
    }

    for (i = 0; i < vc_simplevanitygen->vc_thread_num; i++) {
        pthread_join(TID[i], NULL);
        // fprintf(stderr, "Thread %d terminated\n",i);
    }
    return 1;
}
#endif
