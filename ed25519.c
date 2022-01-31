#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <memory.h>
#include <assert.h>
#include "base32.h"
#include "util.h"
#include "ed25519.h"
#include "stellar.h"
#include "pattern.h"

static pthread_t TID[ed25519_max_threads];

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER; // protect vc_ed25519->vc_found_num

// return thread index in array TID, return -1 if not found (you need check again).
int get_thread_index(int max_index) {
    pthread_t t = pthread_self();
    int i;
    for (i=0; i< max_index; i++) {
        if (pthread_equal(TID[i], t) != 0) {
            return i;
        }
    }
    return -1; // pthread_create(&TID[i], ...)  // TID may not visible immediately for sub-thread
}

void
output_check_info(vg_context_ed25519_t *vcp)
{
    double targ;
    char linebuf[80];
    int rem, p;
    char *unit;
    unsigned long current_time = (unsigned long)time(NULL);
    unsigned long long total = 0;
    int i;
    for (i = 0; i < vcp->vc_thread_num; i++) {
        total += vcp->vc_check_count[i];
    }

    targ = total/(current_time - vcp->vc_start_time + 0.001); // plus 0.001 to avoid zero
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
        memset(&linebuf[sizeof(linebuf)-rem], 0x20, rem);
        linebuf[sizeof(linebuf)-1] = '\0';
    }
    printf("\r%s", linebuf);
    fflush(stdout);
}

void *
thread_loop_ed25519(void *arg)
{
#if OPENSSL_VERSION_NUMBER < 0x10101000L
    fprintf(stderr, "OpenSSL 1.1.1 (or higher) is required for ED25519, please recompile it\n");
#else
    unsigned char priv_buf[32];
    unsigned char pub_buf[32];
    unsigned char xlm_private_out[56];
    unsigned char xlm_addr_out[57]; // more 1 byte (hold '\0'), strstr need NULL terminated string
    xlm_addr_out[56] = '\0';
    int find_it = 0;
    size_t pattern_len;
    size_t buf_len = 32;
    int thread_index;

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);

    if (EVP_PKEY_keygen_init(pctx) != 1) {
        fprintf(stderr, "EVP_PKEY_keygen_init fail\n");
        return NULL;
    }

    vg_context_ed25519_t *vc_ed25519 = (vg_context_ed25519_t *) arg;

    pattern_len = strlen(vc_ed25519->pattern);

check_thread_index:
    thread_index = get_thread_index(vc_ed25519->vc_thread_num);
    if (thread_index == -1) {
        // check again
        if (vc_ed25519->vc_verbose > 1) {
            fprintf(stderr, "thread index not found, check again\n");
        }
        goto check_thread_index;
    }

    int output_timeout = 0;
    while (!vc_ed25519->vc_halt) {
        // generate a key-pair
        EVP_PKEY_keygen(pctx, &pkey);

        vc_ed25519->vc_check_count[thread_index]++;
        output_timeout++;

        // Get public key from EVP_PKEY
        // EVP_PKEY_get_raw_public_key only works for algorithms that support raw public keys.
        // Currently this is: EVP_PKEY_X25519, EVP_PKEY_ED25519, EVP_PKEY_X448 or EVP_PKEY_ED448.
        EVP_PKEY_get_raw_public_key(pkey, (unsigned char *)&pub_buf, &buf_len);
        //dumphex(pub_buf, sizeof(pub_buf));

        if (vc_ed25519->vc_addrtype == ADDR_TYPE_XLM) {
            // Generate XLM address
            strkey_encode(6 << 3, pub_buf, 32, xlm_addr_out);

            // Check address if match pattern
            if (vc_ed25519->match_location == 0) { // any
                if (strstr((const char*)xlm_addr_out, vc_ed25519->pattern) != NULL) {
                    find_it = 1;
                }
            } else if (vc_ed25519->match_location == 1) { // begin
                if (strncmp(vc_ed25519->pattern, (const char*)xlm_addr_out, pattern_len) == 0) {
                    find_it = 1;
                }
            } else if (vc_ed25519->match_location == 2) { // end
                if (strncmp(vc_ed25519->pattern, ((const char*)xlm_addr_out) + 56 - pattern_len, pattern_len) == 0) {
                    find_it = 1;
                }
            }
            if (find_it == 1) {
                pthread_mutex_lock(&mtx);

                if (vc_ed25519->vc_found_num >= vc_ed25519->vc_numpairs) {

                    vc_ed25519->vc_halt = 1;
                    pthread_mutex_unlock(&mtx);
                    goto out;
                }

                vc_ed25519->vc_found_num++;

                printf("\rXLM Address: %.56s\n", xlm_addr_out);

                // Get private key from EVP_PKEY
                // EVP_PKEY_get_raw_private_key only works for algorithms that support raw private keys.
                // Currently this is: EVP_PKEY_HMAC, EVP_PKEY_POLY1305, EVP_PKEY_SIPHASH, EVP_PKEY_X25519,
                // EVP_PKEY_ED25519, EVP_PKEY_X448 or EVP_PKEY_ED448.
                EVP_PKEY_get_raw_private_key(pkey, (unsigned char *)&priv_buf, &buf_len);
                //dumphex(priv_buf, sizeof(priv_buf));

                // Generate XLM seed (private key)
                strkey_encode(18 << 3, priv_buf, 32, xlm_private_out);

                printf("XLM Privkey: %.56s\n", xlm_private_out);
                vc_ed25519->vc_halt = 1;

                if (vc_ed25519->vc_result_file) {
                    FILE *fp = fopen(vc_ed25519->vc_result_file, "a");
                    if (!fp) {
                        fprintf(stderr, "ERROR: could not open result file: %s\n", strerror(errno));
                    } else {
                        fprintf(fp, "Pattern: %s\n", vc_ed25519->pattern);
                        fprintf(fp, "XLM Address: %.56s\n", xlm_addr_out);
                        fprintf(fp, "XLM Privkey: %.56s\n", xlm_private_out);
                        fclose(fp);
                    }
                }

                pthread_mutex_unlock(&mtx);
            }
        }

        if (output_timeout > 15000) {
            output_check_info(vc_ed25519);
            output_timeout = 0;
        }
    }

out:
    if (vc_ed25519->vc_verbose > 1) {
        fprintf(stderr, "thread %d check %lld keys\n", thread_index,
               vc_ed25519->vc_check_count[thread_index]);
    }
    EVP_PKEY_CTX_free(pctx);
#endif
    return NULL;
}

int start_threads_ed25519(vg_context_ed25519_t *vc_ed25519) {
    int i;
    if (vc_ed25519->vc_verbose > 1) {
        fprintf(stderr, "Using %d worker thread(s)\n", vc_ed25519->vc_thread_num);
    }

    for (i=0; i < vc_ed25519->vc_thread_num; i++) {
        if (pthread_create(&TID[i], NULL, thread_loop_ed25519, vc_ed25519))
            return 0;
    }

    for (i = 0; i< vc_ed25519->vc_thread_num; i++) {
        pthread_join(TID[i], NULL);
        // fprintf(stderr, "Thread %d terminated\n",i);
    }
    return 1;
}
