/*
 * oclvanitygen_ed25519.c - GPU vanity address generator for Ed25519 chains
 *
 * Supports: SOL (Solana, Base58 raw), XLM (Stellar, strkey), TON (V5R1/V4R2)
 *
 * Security: seeds are read from the OS cryptographic RNG before each batch
 * (/dev/urandom on POSIX, BCryptGenRandom on Windows; see compat.c).
 * The GPU only performs deterministic Ed25519 key derivation; all randomness
 * originates from the OS RNG.
 *
 * Usage:
 *   oclvanitygen-ed25519++ [options] <pattern>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>
#include <ctype.h>    /* isalpha, toupper, tolower, isupper */
#include <math.h>     /* exp, log, pow */
#include <assert.h>
#include <pthread.h>

/*
 * Portability layer.
 */
#include "compat.h"

/* getopt() / optind / count_processors() come from libc on POSIX and
 * from winglue.h on Windows. The pattern below mirrors keyconv.c. */
#if defined(_WIN32)
#include "winglue.h"
#else
#include <unistd.h>   /* getopt, optind, optarg */
#endif

#include <openssl/sha.h>

#include "ocled25519engine.h"
#include "util.h"
#include "stellar.h"
#include "ticker.h"
#include "crc16.h"

/* GRSFlag, TRXFlag, ticker are defined in oclvanitygen.c (or whichever main links us) */

/* =========================================================================
 * TON wallet contract constants
 * ========================================================================= */

typedef struct {
    const char *name;           /* "V5R1" or "V4R2" */
    uint8_t  si_prefix[39];     /* first 39 bytes of StateInit hash message */
    uint8_t  dc_msg_prefix[10]; /* first 10 bytes of data cell hash message */
    uint8_t  dc_carry;          /* MSB carry into pubkey byte (0x80 for V5R1) */
    int      pubkey_shift;      /* 1 = pubkey shifted 1 bit right (V5R1) */
} ton_wallet_t;

/*
 * V5R1: code from ton-blockchain/wallet-contract-v5
 *   code_hash = 20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f
 *   code_depth = 6
 *   walletId = 0x7fffff11 (mainnet, workchain 0, subwallet 0)
 *   data cell = auth(1) + seqno(32) + walletId(32) + pubkey(256) + plugins(1) = 322 bits
 */
/* Positional initialization (not designated) so this compiles under
 * MSVC's pre-C++20 mode. Fields are annotated with their names; the
 * struct definition above is the source of truth for the order. */
static const ton_wallet_t ton_v5r1 = {
    /* .name */         "V5R1",
    /* .si_prefix */    {
        0x02, 0x01, 0x34,       /* d1=2refs, d2=1, data=0x34 (00110_100) */
        0x00, 0x06,             /* code depth = 6 */
        0x00, 0x00,             /* data depth = 0 */
        /* code_hash: */
        0x20, 0x83, 0x4b, 0x7b, 0x72, 0xb1, 0x12, 0x14,
        0x7e, 0x1b, 0x2f, 0xb4, 0x57, 0xb8, 0x4e, 0x74,
        0xd1, 0xa3, 0x0f, 0x04, 0xf7, 0x37, 0xd4, 0xf6,
        0x2a, 0x66, 0x8e, 0x95, 0x52, 0xd2, 0xb7, 0x2f,
    },
    /* .dc_msg_prefix */ {
        0x00, 0x51,             /* d1=0, d2=81 */
        0x80, 0x00, 0x00, 0x00, /* auth=1, seqno=0 (first 31 bits) */
        0x3F, 0xFF, 0xFF, 0x88, /* seqno LSB + walletId bits [31:1] */
    },
    /* .dc_carry */     0x80,   /* walletId bit 0 = 1 */
    /* .pubkey_shift */ 1,
};

/*
 * V4R2: code from ton-blockchain/wallet-contract
 *   code_hash = feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0
 *   code_depth = 7
 *   walletId = 698983191 = 0x29A9A317
 *   data cell = seqno(32) + walletId(32) + pubkey(256) + plugins(1) = 321 bits
 */
static const ton_wallet_t ton_v4r2 = {
    /* .name */         "V4R2",
    /* .si_prefix */    {
        0x02, 0x01, 0x34,       /* d1=2refs, d2=1, data=0x34 */
        0x00, 0x07,             /* code depth = 7 */
        0x00, 0x00,             /* data depth = 0 */
        /* code_hash: */
        0xfe, 0xb5, 0xff, 0x68, 0x20, 0xe2, 0xff, 0x0d,
        0x94, 0x83, 0xe7, 0xe0, 0xd6, 0x2c, 0x81, 0x7d,
        0x84, 0x67, 0x89, 0xfb, 0x4a, 0xe5, 0x80, 0xc8,
        0x78, 0x86, 0x6d, 0x95, 0x9d, 0xab, 0xd5, 0xc0,
    },
    /* .dc_msg_prefix */ {
        0x00, 0x51,             /* d1=0, d2=81 */
        0x00, 0x00, 0x00, 0x00, /* seqno = 0 */
        0x29, 0xA9, 0xA3, 0x17, /* walletId = 698983191 */
    },
    /* .dc_carry */     0x00,
    /* .pubkey_shift */ 0,
};

/* File-scoped TON state (set during option parsing) */
static const ton_wallet_t *g_ton_wallet = NULL;
static int g_ton_bounceable = 0;

/* =========================================================================
 * TON address derivation
 * ========================================================================= */

static void
ton_data_cell_hash(const ton_wallet_t *w, const uint8_t *pubkey, uint8_t *hash_out)
{
    uint8_t msg[43]; /* d1(1) + d2(1) + padded_data(41) */
    memcpy(msg, w->dc_msg_prefix, 10);

    if (w->pubkey_shift) {
        /* V5R1: pubkey at 1-bit offset, MSB of byte 10 = walletId LSB */
        msg[10] = w->dc_carry | (pubkey[0] >> 1);
        for (int i = 1; i < 32; i++)
            msg[10 + i] = (uint8_t)((pubkey[i-1] << 7) | (pubkey[i] >> 1));
        msg[42] = (uint8_t)((pubkey[31] << 7) | 0x20); /* plugins=0, pad=1, 5 zeros */
    } else {
        /* V4R2: pubkey is byte-aligned */
        memcpy(msg + 10, pubkey, 32);
        msg[42] = 0x40; /* plugins=0, pad=1, 6 zeros */
    }

    SHA256(msg, 43, hash_out);
}

static void
ton_stateinit_hash(const ton_wallet_t *w, const uint8_t *data_hash, uint8_t *hash_out)
{
    uint8_t msg[71]; /* si_prefix(39) + data_hash(32) */
    memcpy(msg, w->si_prefix, 39);
    memcpy(msg + 39, data_hash, 32);
    SHA256(msg, 71, hash_out);
}

static const char b64url_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static void
base64url_encode(const uint8_t *in, size_t len, char *out)
{
    assert(len % 3 == 0);
    size_t i, j = 0;
    for (i = 0; i + 2 < len; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | in[i+2];
        out[j++] = b64url_chars[(v >> 18) & 0x3F];
        out[j++] = b64url_chars[(v >> 12) & 0x3F];
        out[j++] = b64url_chars[(v >> 6) & 0x3F];
        out[j++] = b64url_chars[v & 0x3F];
    }
    out[j] = '\0';
}

static void
ton_encode_address(const uint8_t *stateinit_hash, int bounceable, char *addr_out)
{
    uint8_t buf[36];
    buf[0] = bounceable ? 0x11 : 0x51; /* tag */
    buf[1] = 0x00;                     /* workchain 0 */
    memcpy(buf + 2, stateinit_hash, 32);
    uint16_t crc = crc16(buf, 34);
    buf[34] = (uint8_t)(crc >> 8);
    buf[35] = (uint8_t)(crc & 0xFF);
    base64url_encode(buf, 36, addr_out); /* 36 bytes → 48 chars */
}

/* Full pipeline: pubkey → TON address string */
static void
ton_address_from_pubkey(const ton_wallet_t *w, const uint8_t *pubkey,
                        int bounceable, char *addr_out)
{
    uint8_t data_hash[32], si_hash[32];
    ton_data_cell_hash(w, pubkey, data_hash);
    ton_stateinit_hash(w, data_hash, si_hash);
    ton_encode_address(si_hash, bounceable, addr_out);
}

/* =========================================================================
 * Coin registry
 * ========================================================================= */

typedef enum { ENC_BASE58_RAW, ENC_STRKEY, ENC_TON } enc_type_t;

typedef struct {
    const char *ticker;
    enc_type_t  enc;
    uint8_t     strkey_ver;  /* version byte for strkey (ignored for BASE58/TON) */
} ed25519_coin_t;

static const ed25519_coin_t coins[] = {
    { "SOL", ENC_BASE58_RAW,  0  },
    { "XLM", ENC_STRKEY,     48  },  /* 6 << 3 = 48 = G-address */
    { "TON", ENC_TON,         0  },
};
#define NUM_COINS ((int)(sizeof(coins)/sizeof(coins[0])))

static const ed25519_coin_t *
find_coin(const char *name)
{
    for (int i = 0; i < NUM_COINS; i++) {
        if (strcasecmp(coins[i].ticker, name) == 0)
            return &coins[i];
    }
    return NULL;
}

/* =========================================================================
 * Address encoding
 * ========================================================================= */

/* Max address length: TON = 48 chars; XLM = 56 chars; SOL ≤ 44 chars */
#define MAX_ADDR_LEN 64

static void
encode_address(const ed25519_coin_t *coin, const uint8_t *pubkey, char *addr)
{
    if (coin->enc == ENC_BASE58_RAW) {
        vg_b58_encode_raw(pubkey, 32, addr);
    } else if (coin->enc == ENC_TON) {
        ton_address_from_pubkey(g_ton_wallet, pubkey, g_ton_bounceable, addr);
    } else {
        /* ENC_STRKEY: stellar strkey encoding */
        strkey_encode(coin->strkey_ver, pubkey, 32, (uint8_t *)addr);
    }
}

/* =========================================================================
 * Seed increment: advance a 32-byte little-endian counter by n
 * ========================================================================= */

static void
advance_seed(uint8_t *seed, uint32_t n)
{
    uint32_t carry = n;
    for (int j = 0; j < 32 && carry; j++) {
        carry += seed[j];
        seed[j] = (uint8_t)(carry & 0xFF);
        carry >>= 8;
    }
}

/* =========================================================================
 * Pattern matching
 *
 * The pattern uses '*' as a wildcard:
 *   AAAA       prefix match
 *   *pump      suffix match
 *   AAAA*pump  prefix + suffix
 *   *cafe*     match anywhere
 *
 * parse_pattern() splits the pattern into prefix/suffix/anywhere.
 * ========================================================================= */

typedef struct {
    char prefix[MAX_ADDR_LEN];
    char suffix[MAX_ADDR_LEN];
    char anywhere[MAX_ADDR_LEN];
    size_t prefix_len;
    size_t suffix_len;
    size_t anywhere_len;
} parsed_pattern_t;

static int
parse_pattern(const char *pattern, parsed_pattern_t *pp)
{
    memset(pp, 0, sizeof(*pp));
    size_t len = strlen(pattern);
    if (len == 0) return -1;

    const char *star = strchr(pattern, '*');
    if (!star) {
        /* No wildcard: prefix match */
        strncpy(pp->prefix, pattern, MAX_ADDR_LEN - 1);
        pp->prefix_len = len;
        return 0;
    }

    /* *pattern* → anywhere */
    if (pattern[0] == '*' && len > 1 && pattern[len - 1] == '*') {
        size_t inner = len - 2;
        if (inner == 0 || inner >= MAX_ADDR_LEN) return -1;
        memcpy(pp->anywhere, pattern + 1, inner);
        pp->anywhere[inner] = '\0';
        pp->anywhere_len = inner;
        return 0;
    }

    /* *suffix → suffix match */
    if (pattern[0] == '*') {
        strncpy(pp->suffix, pattern + 1, MAX_ADDR_LEN - 1);
        pp->suffix_len = len - 1;
        return 0;
    }

    /* prefix* → prefix match (trailing * is optional/explicit) */
    if (pattern[len - 1] == '*' && strchr(pattern, '*') == &pattern[len - 1]) {
        size_t plen = len - 1;
        if (plen >= MAX_ADDR_LEN) return -1;
        memcpy(pp->prefix, pattern, plen);
        pp->prefix[plen] = '\0';
        pp->prefix_len = plen;
        return 0;
    }

    /* prefix*suffix → both */
    size_t plen = (size_t)(star - pattern);
    size_t slen = len - plen - 1;
    if (plen >= MAX_ADDR_LEN || slen >= MAX_ADDR_LEN) return -1;
    memcpy(pp->prefix, pattern, plen);
    pp->prefix[plen] = '\0';
    pp->prefix_len = plen;
    memcpy(pp->suffix, star + 1, slen);
    pp->suffix[slen] = '\0';
    pp->suffix_len = slen;
    return 0;
}

/*
 * Validate that every character in the pattern can appear in the coin's
 * address alphabet.  With case-insensitive mode, a character is valid if
 * either its upper or lower case form is in the alphabet.
 *
 * Returns 0 on success, or prints an error and returns -1.
 */
static const char *b58_alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const char *b32_alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static const char *b64url_alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int
char_in_alphabet(char c, const char *alphabet)
{
    return strchr(alphabet, c) != NULL;
}

static int
validate_pattern_str(const char *pat, size_t len,
                     const char *alphabet, int ci, const char *label)
{
    for (size_t i = 0; i < len; i++) {
        char c = pat[i];
        int valid;
        if (ci && isalpha((unsigned char)c))
            valid = char_in_alphabet(toupper((unsigned char)c), alphabet) ||
                    char_in_alphabet(tolower((unsigned char)c), alphabet);
        else
            valid = char_in_alphabet(c, alphabet);
        if (!valid) {
            fprintf(stderr,
                "Error: character '%c' in %s is not valid for this address format\n",
                c, label);
            return -1;
        }
    }
    return 0;
}

static const char *
get_alphabet(const ed25519_coin_t *coin)
{
    switch (coin->enc) {
    case ENC_BASE58_RAW: return b58_alphabet;
    case ENC_STRKEY:     return b32_alphabet;
    case ENC_TON:        return b64url_alphabet;
    }
    return NULL;
}

static int
validate_pattern(const parsed_pattern_t *pp, const ed25519_coin_t *coin, int ci)
{
    const char *alphabet = get_alphabet(coin);
    if (!alphabet) {
        fprintf(stderr, "Error: unknown encoding for %s\n", coin->ticker);
        return -1;
    }

    if (pp->prefix_len > 0 &&
        validate_pattern_str(pp->prefix, pp->prefix_len, alphabet, ci, "prefix") < 0)
        return -1;
    if (pp->suffix_len > 0 &&
        validate_pattern_str(pp->suffix, pp->suffix_len, alphabet, ci, "suffix") < 0)
        return -1;
    if (pp->anywhere_len > 0 &&
        validate_pattern_str(pp->anywhere, pp->anywhere_len, alphabet, ci, "pattern") < 0)
        return -1;
    return 0;
}

/* =========================================================================
 * Difficulty estimation
 *
 * difficulty = 1 / probability_of_single_key_matching
 * For geometric distribution: P(found after N tries) = 1 - e^(-N/difficulty)
 * ========================================================================= */

/* Count how many characters in alphabet match c (considering case-insensitive) */
static int
char_match_count(char c, const char *alphabet, int ci)
{
    int count = 0;
    if (char_in_alphabet(c, alphabet))
        count++;
    if (ci && isalpha((unsigned char)c)) {
        char other = (char)(isupper((unsigned char)c) ? tolower((unsigned char)c)
                                                      : toupper((unsigned char)c));
        if (other != c && char_in_alphabet(other, alphabet))
            count++;
    }
    return count;
}

static double
estimate_difficulty(const parsed_pattern_t *pp, const ed25519_coin_t *coin,
                    int ci)
{
    const char *alphabet = get_alphabet(coin);
    if (!alphabet) return 0;
    int alpha_size = (int)strlen(alphabet);

    /* Typical address length for "anywhere" position count */
    int addr_len;
    switch (coin->enc) {
    case ENC_BASE58_RAW: addr_len = 44; break;   /* SOL: Base58(32 bytes) */
    case ENC_STRKEY:     addr_len = 56; break;   /* XLM: Base32(35 bytes) */
    case ENC_TON:        addr_len = 48; break;   /* TON: Base64url(36 bytes) */
    default:             return 0;
    }

    double prob = 1.0;

    if (pp->anywhere_len > 0) {
        /* Each character narrows the probability */
        for (size_t i = 0; i < pp->anywhere_len; i++) {
            int m = char_match_count(pp->anywhere[i], alphabet, ci);
            prob *= (double)m / alpha_size;
        }
        /* Can start at any of (addr_len - pattern_len + 1) positions */
        int positions = addr_len - (int)pp->anywhere_len + 1;
        if (positions < 1) positions = 1;
        /* Approximate: 1 - (1-p)^positions ≈ p * positions for small p */
        prob = 1.0 - pow(1.0 - prob, positions);
    } else {
        if (pp->prefix_len > 0) {
            /*
             * TON: first 2 chars (UQ/EQ) are fixed by tag+workchain,
             * so they always match and don't contribute to difficulty.
             */
            size_t start = 0;
            if (coin->enc == ENC_TON && pp->prefix_len >= 2) {
                const char *fixed = g_ton_bounceable ? "EQ" : "UQ";
                if (pp->prefix[0] == fixed[0] && pp->prefix[1] == fixed[1])
                    start = 2;
            }
            for (size_t i = start; i < pp->prefix_len; i++) {
                int m = char_match_count(pp->prefix[i], alphabet, ci);
                prob *= (double)m / alpha_size;
            }
        }
        if (pp->suffix_len > 0) {
            for (size_t i = 0; i < pp->suffix_len; i++) {
                int m = char_match_count(pp->suffix[i], alphabet, ci);
                prob *= (double)m / alpha_size;
            }
        }
    }

    return (prob > 0) ? 1.0 / prob : 0;
}

static void
format_time(double seconds, char *buf, size_t bufsz)
{
    const char *unit = "s";
    double t = seconds;
    if (t > 3600 * 24 * 365) { t /= 3600 * 24 * 365; unit = "y"; }
    else if (t > 3600 * 24)  { t /= 3600 * 24;        unit = "d"; }
    else if (t > 3600)       { t /= 3600;              unit = "h"; }
    else if (t > 60)         { t /= 60;                unit = "min"; }

    if (t > 1e6)
        snprintf(buf, bufsz, "%.1e%s", t, unit);
    else
        snprintf(buf, bufsz, "%.1f%s", t, unit);
}

static int
match_address(const char *addr, const parsed_pattern_t *pp, int ci)
{
    size_t alen = strlen(addr);

    if (pp->anywhere_len > 0) {
        if (pp->anywhere_len > alen) return 0;
        if (!ci) return strstr(addr, pp->anywhere) != NULL;
        for (size_t i = 0; i <= alen - pp->anywhere_len; i++) {
            if (strncasecmp(addr + i, pp->anywhere, pp->anywhere_len) == 0)
                return 1;
        }
        return 0;
    }

    if (pp->prefix_len > 0) {
        if (pp->prefix_len > alen) return 0;
        int ok = ci ? strncasecmp(addr, pp->prefix, pp->prefix_len) == 0
                    : strncmp(addr, pp->prefix, pp->prefix_len) == 0;
        if (!ok) return 0;
    }
    if (pp->suffix_len > 0) {
        if (pp->suffix_len > alen) return 0;
        int ok = ci ? strcasecmp(addr + alen - pp->suffix_len, pp->suffix) == 0
                    : strcmp(addr + alen - pp->suffix_len, pp->suffix) == 0;
        if (!ok) return 0;
    }
    return 1;
}

/* =========================================================================
 * Usage / help
 * ========================================================================= */

static void
usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -C <COIN> [options] <pattern>\n"
        "\n"
        "Pattern uses '*' as wildcard:\n"
        "  AAAA          prefix match\n"
        "  '*pump'       suffix match\n"
        "  'AAAA*pump'   prefix + suffix\n"
        "  '*cafe*'      match anywhere\n"
        "\n"
        "Ed25519 options:\n"
        "  -C <COIN>     Coin (required): SOL | XLM | TON\n"
        "  -i            Case-insensitive match\n"
        "  -t <threads>  CPU match threads (default: nproc-1)\n"
        "\n"
        "TON options:\n"
        "  -W <version>  Wallet version: v5r1 (default) | v4r2\n"
        "                Bounceable (EQ) vs non-bounceable (UQ) is auto-detected\n"
        "                from the pattern prefix\n"
        "\n"
        "Examples:\n"
        "  %s -C SOL AAAA                # SOL prefix\n"
        "  %s -C SOL '*pump'             # SOL suffix\n"
        "  %s -C TON UQAbc               # TON non-bounceable prefix\n"
        "  %s -C TON EQAbc               # TON bounceable prefix\n"
        "  %s -C TON 'UQAbc*xyz'         # TON prefix + suffix\n"
        "  %s -C TON -W v4r2 UQAbc       # TON V4R2 wallet\n"
        "  %s -C TON -i -a 5 UQAbc       # case-insensitive, 5 matches\n"
        "\n",
        prog, prog, prog, prog, prog, prog, prog, prog);
}

/* =========================================================================
 * Find kernel file: try same dir as argv[0], then current directory
 * ========================================================================= */

static int
find_kernel_path(const char *argv0, char *out, size_t outsz)
{
    char dir[1024];
    FILE *fp;

    /* Try the directory the executable lives in. vg_dirname() abstracts
     * over POSIX dirname() vs. the manual scan needed on Windows, and
     * does not modify `argv0`. */
    vg_dirname(argv0, dir, sizeof(dir));
    snprintf(out, outsz, "%s/calc_addrs_ed25519.cl", dir);
    fp = fopen(out, "r");
    if (fp) { fclose(fp); return 0; }

    /* Fall back to the current working directory. */
    snprintf(out, outsz, "calc_addrs_ed25519.cl");
    fp = fopen(out, "r");
    if (fp) { fclose(fp); return 0; }

    return -1;
}

/* =========================================================================
 * Multithreaded CPU matching
 * ========================================================================= */

#define MAX_MATCHES_PER_THREAD 64

typedef struct {
    char addr[MAX_ADDR_LEN];
    uint8_t seed[32];
    uint8_t pubkey[32];
} match_result_t;

typedef struct {
    /* Input (set by main thread each batch) */
    const uint8_t      *pubkeys;
    const uint8_t      *seeds;
    size_t              start_k;
    size_t              end_k;
    uint32_t            keys_per_item;
    const ed25519_coin_t *coin;
    const parsed_pattern_t *pp;
    int                 case_insens;
    int                *global_found;
    int                 max_found;
    /* Output */
    int                 local_found;
    match_result_t      matches[MAX_MATCHES_PER_THREAD];
} match_work_t;

static void *
match_thread_func(void *arg)
{
    match_work_t *w = (match_work_t *)arg;
    w->local_found = 0;
    char addr[MAX_ADDR_LEN];

    for (size_t k = w->start_k; k < w->end_k; k++) {
        if (vg_atomic_load_int(w->global_found) >= w->max_found)
            break;

        const uint8_t *pubkey = w->pubkeys + k * 32;
        encode_address(w->coin, pubkey, addr);

        if (match_address(addr, w->pp, w->case_insens)) {
            int idx = w->local_found;
            if (idx >= MAX_MATCHES_PER_THREAD)
                break;

            snprintf(w->matches[idx].addr, MAX_ADDR_LEN, "%s", addr);
            memcpy(w->matches[idx].pubkey, pubkey, 32);

            /* Recover the seed */
            size_t wi = k / w->keys_per_item;
            uint32_t ko = (uint32_t)(k % w->keys_per_item);
            memcpy(w->matches[idx].seed, w->seeds + wi * 32, 32);
            advance_seed(w->matches[idx].seed, ko);

            w->local_found++;
            vg_atomic_inc_int(w->global_found);
        }
    }
    return NULL;
}

/* =========================================================================
 * Main
 * ========================================================================= */

static volatile int g_stop = 0;
static void sig_handler(int sig) { (void)sig; g_stop = 1; }

int
ocl_ed25519_main(int argc, char *argv[])
{
    /* Defaults */
    const ed25519_coin_t *coin = NULL;
    int platform_idx  = 0;
    int device_idx    = 0;
    int do_list       = 0;
    int max_found     = 1;
    int case_insens   = 0;
    int verbose       = 1;   /* match oclvanitygen.c (BTC path) so kernel
                              * compile / device-pick messages show up; -q
                              * still suppresses everything */
    int quiet         = 0;
    FILE *out_fp           = NULL;
    const char *out_file   = NULL;
    const char *wallet_ver = NULL;
    int nthreads = 0;   /* 0 = auto (nproc - 1) */
    int opt;

    optind = 1;  /* reset getopt (dispatched from oclvanitygen.c) */

    while ((opt = getopt(argc, argv, "C:W:t:p:d:Da:1o:ivq")) != -1) {
        switch (opt) {
        case 'C':
            coin = find_coin(optarg);
            if (!coin) {
                fprintf(stderr, "Unknown coin: %s (supported: SOL, XLM, TON)\n", optarg);
                return 1;
            }
            strncpy(ticker, coin->ticker, sizeof(ticker) - 1);
            break;
        case 'W': wallet_ver    = optarg;       break;
        case 't': nthreads      = atoi(optarg); break;
        case 'p': platform_idx  = atoi(optarg); break;
        case 'd': device_idx    = atoi(optarg); break;
        case 'D': do_list       = 1;            break;
        case 'a': max_found     = atoi(optarg); break;
        case '1': max_found     = 1;            break;
        case 'o': out_file      = optarg;       break;
        case 'i': case_insens   = 1;            break;
        case 'v': verbose       = 1;            break;
        case 'q': quiet         = 1;            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (do_list) {
        ocl_ed25519_enumerate_devices();
        return 0;
    }

    if (!coin) {
        fprintf(stderr, "Error: -C <COIN> is required (SOL, XLM, TON).\n\n");
        usage(argv[0]);
        return 1;
    }

    /* TON wallet version selection and bounceable detection.
     * Also scan argv manually for -W in case getopt stopped at the pattern
     * (POSIX getopt stops at the first non-option argument). */
    if (coin->enc == ENC_TON) {
        if (!wallet_ver) {
            for (int j = 1; j < argc - 1; j++) {
                if (strcmp(argv[j], "-W") == 0) {
                    wallet_ver = argv[j + 1];
                    break;
                }
            }
        }
        if (!wallet_ver || strcasecmp(wallet_ver, "v5r1") == 0) {
            g_ton_wallet = &ton_v5r1;
        } else if (strcasecmp(wallet_ver, "v4r2") == 0) {
            g_ton_wallet = &ton_v4r2;
        } else {
            fprintf(stderr, "Error: unknown wallet version '%s' (supported: v5r1, v4r2)\n",
                    wallet_ver);
            return 1;
        }
    }

    /* Resolve match thread count */
    if (nthreads <= 0) {
        nthreads = count_processors();
        if (nthreads > 1)
            nthreads--;  /* reserve one core for GPU/system */
        if (nthreads < 1)
            nthreads = 1;
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: no pattern specified.\n\n");
        usage(argv[0]);
        return 1;
    }

    parsed_pattern_t pp;
    if (parse_pattern(argv[optind], &pp) < 0) {
        fprintf(stderr, "Error: invalid pattern '%s'\n", argv[optind]);
        return 1;
    }
    if (validate_pattern(&pp, coin, case_insens) < 0)
        return 1;

    /* TON: auto-detect bounceable from pattern prefix */
    if (coin->enc == ENC_TON) {
        g_ton_bounceable = (pp.prefix_len >= 2 &&
                            pp.prefix[0] == 'E' && pp.prefix[1] == 'Q');
    }

    double difficulty = estimate_difficulty(&pp, coin, case_insens);

    if (!quiet) {
        if (coin->enc == ENC_TON)
            fprintf(stderr, "Searching for %s (%s) address matching: %s\n",
                    coin->ticker, g_ton_wallet->name, argv[optind]);
        else
            fprintf(stderr, "Searching for %s address matching: %s\n",
                    coin->ticker, argv[optind]);
        if (difficulty > 0)
            fprintf(stderr, "Difficulty: %.0f\n", difficulty);
        if (nthreads > 1)
            fprintf(stderr, "Match threads: %d\n", nthreads);
    }

    if (out_file) {
        out_fp = fopen(out_file, "a");
        if (!out_fp) {
            perror(out_file);
            return 1;
        }
    }

    /* Find kernel */
    char kernel_path[1024];
    if (find_kernel_path(argv[0], kernel_path, sizeof(kernel_path)) < 0) {
        fprintf(stderr,
            "Error: cannot find calc_addrs_ed25519.cl\n"
            "Run from the build directory or ensure the .cl file is next to the binary.\n");
        return 1;
    }

    /* Init OpenCL */
    ocl_ed25519_ctx_t ctx;
    if (ocl_ed25519_init(&ctx, kernel_path, platform_idx, device_idx,
                         0, 64, verbose) < 0) {
        return 1;
    }

    /* Allocate host buffers: two seed buffers for pipelining */
    size_t total_keys  = ctx.global_size * (size_t)ctx.keys_per_item;
    size_t seed_bytes  = ctx.global_size * 32;
    size_t pubkey_bytes = total_keys * 32;

    uint8_t *seeds[2];
    seeds[0]             = (uint8_t *)malloc(seed_bytes);
    seeds[1]             = (uint8_t *)malloc(seed_bytes);
    uint8_t *pubkeys_buf = (uint8_t *)malloc(pubkey_bytes);
    if (!seeds[0] || !seeds[1] || !pubkeys_buf) {
        fprintf(stderr, "Out of memory\n");
        return 1;
    }

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    uint64_t total_tried = 0;
    int      found       = 0;
    /* Monotonic-counter samples in nanoseconds. vg_monotonic_ns()
     * abstracts over clock_gettime(CLOCK_MONOTONIC) on POSIX and
     * QueryPerformanceCounter on Windows. */
    uint64_t t_start_ns = vg_monotonic_ns();
    uint64_t t_last_ns  = t_start_ns;

    /*
     * Pipeline: GPU computes batch N+1 while CPU matches batch N.
     * Seeds are read from /dev/urandom once, then advanced each batch.
     */
    int cur = 0;
    int reseed_needed = 0;
    if (vg_random_bytes(seeds[0], seed_bytes) < 0) {
        fprintf(stderr, "Failed to read OS random source\n");
        goto done;
    }

    /* First batch: no overlap possible */
    if (ocl_ed25519_launch(&ctx, seeds[0]) < 0) goto done;
    if (ocl_ed25519_await(&ctx, pubkeys_buf) < 0) goto done;

    while (!g_stop && found < max_found) {
        /* Prepare next batch seeds */
        int next = 1 - cur;
        if (reseed_needed) {
            /* After a match, reseed from the OS RNG to prevent correlation */
            if (vg_random_bytes(seeds[next], seed_bytes) < 0) {
                fprintf(stderr, "Failed to read OS random source\n");
                break;
            }
            reseed_needed = 0;
        } else {
            memcpy(seeds[next], seeds[cur], seed_bytes);
            for (size_t i = 0; i < ctx.global_size; i++)
                advance_seed(seeds[next] + i * 32, ctx.keys_per_item);
        }

        /* Launch next batch on GPU (returns immediately) */
        if (ocl_ed25519_launch(&ctx, seeds[next]) < 0) break;

        /* CPU: match results from current batch while GPU works */
        {
            int batch_found = 0;
            pthread_t *threads = NULL;
            match_work_t *works = (match_work_t *)calloc(nthreads, sizeof(match_work_t));

            /* Set up per-thread work ranges */
            size_t keys_per_thread = total_keys / nthreads;
            for (int t = 0; t < nthreads; t++) {
                works[t].pubkeys       = pubkeys_buf;
                works[t].seeds         = seeds[cur];
                works[t].start_k       = t * keys_per_thread;
                works[t].end_k         = (t == nthreads - 1) ? total_keys
                                                              : (t + 1) * keys_per_thread;
                works[t].keys_per_item = ctx.keys_per_item;
                works[t].coin          = coin;
                works[t].pp            = &pp;
                works[t].case_insens   = case_insens;
                works[t].global_found  = &batch_found;
                works[t].max_found     = max_found - found;
                works[t].local_found   = 0;
            }

            if (nthreads > 1) {
                threads = (pthread_t *)malloc((nthreads - 1) * sizeof(pthread_t));
                for (int t = 1; t < nthreads; t++)
                    pthread_create(&threads[t - 1], NULL, match_thread_func, &works[t]);
            }
            /* Main thread handles segment 0 */
            match_thread_func(&works[0]);

            if (nthreads > 1) {
                for (int t = 1; t < nthreads; t++)
                    pthread_join(threads[t - 1], NULL);
                free(threads);
            }

            /* Collect and print matches from all threads */
            for (int t = 0; t < nthreads && found < max_found; t++) {
                for (int m = 0; m < works[t].local_found && found < max_found; m++) {
                    found++;
                    reseed_needed = 1;
                    match_result_t *mr = &works[t].matches[m];

                    printf("\r\033[KAddress:    %s\n", mr->addr);
                    if (coin->enc == ENC_TON) {
                        printf("PrivKey:    ");
                        for (int j = 0; j < 32; j++) printf("%02x", mr->seed[j]);
                        printf("\n");
                        printf("PubKey:     ");
                        for (int j = 0; j < 32; j++) printf("%02x", mr->pubkey[j]);
                        printf("\n");
                        printf("Wallet:     %s\n\n", g_ton_wallet->name);
                    } else if (coin->enc == ENC_BASE58_RAW) {
                        uint8_t kp[64];
                        char kp_b58[89];
                        memcpy(kp, mr->seed, 32);
                        memcpy(kp + 32, mr->pubkey, 32);
                        vg_b58_encode_raw(kp, 64, kp_b58);
                        printf("Privkey:    %s\n\n", kp_b58);
                    } else {
                        printf("Seed (hex): ");
                        for (int j = 0; j < 32; j++) printf("%02x", mr->seed[j]);
                        printf("\n");
                        printf("Pubkey (hex): ");
                        for (int j = 0; j < 32; j++) printf("%02x", mr->pubkey[j]);
                        printf("\n\n");
                    }
                    fflush(stdout);

                    if (out_fp) {
                        fprintf(out_fp, "Address:    %s\n", mr->addr);
                        if (coin->enc == ENC_TON) {
                            fprintf(out_fp, "PrivKey:    ");
                            for (int j = 0; j < 32; j++) fprintf(out_fp, "%02x", mr->seed[j]);
                            fprintf(out_fp, "\n");
                            fprintf(out_fp, "PubKey:     ");
                            for (int j = 0; j < 32; j++) fprintf(out_fp, "%02x", mr->pubkey[j]);
                            fprintf(out_fp, "\n");
                            fprintf(out_fp, "Wallet:     %s\n\n", g_ton_wallet->name);
                        } else if (coin->enc == ENC_BASE58_RAW) {
                            uint8_t kp[64];
                            char kp_b58[89];
                            memcpy(kp, mr->seed, 32);
                            memcpy(kp + 32, mr->pubkey, 32);
                            vg_b58_encode_raw(kp, 64, kp_b58);
                            fprintf(out_fp, "Privkey:    %s\n\n", kp_b58);
                        } else {
                            fprintf(out_fp, "Seed (hex): ");
                            for (int j = 0; j < 32; j++) fprintf(out_fp, "%02x", mr->seed[j]);
                            fprintf(out_fp, "\n");
                            fprintf(out_fp, "Pubkey (hex): ");
                            for (int j = 0; j < 32; j++) fprintf(out_fp, "%02x", mr->pubkey[j]);
                            fprintf(out_fp, "\n\n");
                        }
                        fflush(out_fp);
                    }
                }
            }
            free(works);
        }

        total_tried += total_keys;

        /* Wait for GPU to finish next batch */
        if (ocl_ed25519_await(&ctx, pubkeys_buf) < 0) break;
        cur = next;


        /* Progress report every ~1 second */
        if (!quiet) {
            uint64_t t_now_ns = vg_monotonic_ns();
            double elapsed_since_last = (t_now_ns - t_last_ns) * 1e-9;
            if (elapsed_since_last >= 1.0) {
                double elapsed_total = (t_now_ns - t_start_ns) * 1e-9;
                double rate = (double)total_tried / elapsed_total;
                char eta_buf[64] = "";
                if (difficulty > 0 && rate > 0) {
                    double prob = 1.0 - exp(-(double)total_tried / difficulty);
                    /* Time to 50% probability from now */
                    double remaining = (-difficulty * log(0.5) - (double)total_tried);
                    if (remaining < 0) remaining = 0;
                    remaining /= rate;
                    format_time(remaining, eta_buf, sizeof(eta_buf));
                    fprintf(stderr,
                        "\r[%s] [%.2f Mkey/s][total %llu][Prob %.1f%%][50%% in %s]  ",
                        coin->ticker, rate / 1e6,
                        (unsigned long long)total_tried,
                        prob * 100.0, eta_buf);
                } else {
                    fprintf(stderr,
                        "\r[%s] [%.2f Mkey/s][total %llu][Found %d/%d]  ",
                        coin->ticker, rate / 1e6,
                        (unsigned long long)total_tried,
                        found, max_found);
                }
                fflush(stderr);
                t_last_ns = t_now_ns;
            }
        }
    }

done:
    if (!quiet)
        fprintf(stderr, "\n");

    /* Cleanup */
    free(seeds[0]);
    free(seeds[1]);
    free(pubkeys_buf);
    ocl_ed25519_free(&ctx);
    if (out_fp) fclose(out_fp);

    return (found >= max_found) ? 0 : 1;
}
