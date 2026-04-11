#include "pattern.c" // get_prefix_ranges is a static function in pattern.c, can't introduce it by linking pattern.o
char ticker[10];  // Fix link issue: Undefined symbols for architecture x86_64: "_ticker"

START_TEST(test_get_prefix_ranges)
{
    struct {
        int addrtype;
        const char* pattern;
        const char* result_0;
        const char* result_1;
    } tests[] = {
        { 0,
          "12",
          "0AF820335D9B3D9CF58B911D87035677FB7F528100000000",
          "15F04066BB367B39EB17223B0E06ACEFF6FEA501FFFFFFFF"
        },
        { ADDR_TYPE_ETH,
          "0xAA",
          "AA00000000000000000000000000000000000000",
          "AAFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        },
        /* TRX prefix "T" (addrtype=65=0x41): range must cover entire addrtype
         * space, with high = 0x41FF...FF (not 0x4200...00) */
        { 65,
          "T",
          "41000000000000000000000000000000000000000000000000",
          "41FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        },
    };

    size_t n = sizeof(tests) / sizeof(tests[0]);

    for (int i = 0; i < n; i++) {
        char *got;
        BIGNUM *ranges[4];
        BN_CTX *bnctx = BN_CTX_new();

        int rv = get_prefix_ranges(tests[i].addrtype, tests[i].pattern, ranges, bnctx);
        ck_assert_int_eq(0, rv);


        got = BN_bn2hex(ranges[0]);
        ck_assert_mem_eq(got, tests[i].result_0, strlen(tests[i].result_0));
        OPENSSL_free(got);

        got = BN_bn2hex(ranges[1]);
        ck_assert_mem_eq(got, tests[i].result_1, strlen(tests[i].result_1));
        OPENSSL_free(got);
    }
}
END_TEST

START_TEST(test_eth_suffix_parsing)
{
    /* Test suffix-only pattern: *dead */
    {
        vg_context_t *vcp = vg_prefix_context_new(ADDR_TYPE_ETH, PRIV_TYPE_ETH, 0);
        ck_assert_ptr_nonnull(vcp);
        const char *patterns[] = { "*dead" };
        int rv = vg_context_add_patterns(vcp, patterns, 1);
        ck_assert_int_eq(1, rv);

        vg_prefix_context_t *vcpp = (vg_prefix_context_t *)vcp;
        ck_assert_int_eq(1, vcpp->vcp_has_suffix);
        ck_assert_int_eq(4, vcpp->vcp_suffix_len);
        /* mask should have last 2 bytes set: ...0000FFFF */
        ck_assert_int_eq(0x00, vcpp->vcp_suffix_mask[17]);
        ck_assert_int_eq(0xFF, vcpp->vcp_suffix_mask[18]);
        ck_assert_int_eq(0xFF, vcpp->vcp_suffix_mask[19]);
        /* target should be ...0000DEAD */
        ck_assert_int_eq(0xDE, vcpp->vcp_suffix_target[18]);
        ck_assert_int_eq(0xAD, vcpp->vcp_suffix_target[19]);
        ck_assert_int_eq(0x00, vcpp->vcp_suffix_target[17]);

        vg_context_free(vcp);
    }

    /* Test odd-length suffix: *abc (3 hex chars = 12 bits) */
    {
        vg_context_t *vcp = vg_prefix_context_new(ADDR_TYPE_ETH, PRIV_TYPE_ETH, 0);
        const char *patterns[] = { "*abc" };
        int rv = vg_context_add_patterns(vcp, patterns, 1);
        ck_assert_int_eq(1, rv);

        vg_prefix_context_t *vcpp = (vg_prefix_context_t *)vcp;
        ck_assert_int_eq(1, vcpp->vcp_has_suffix);
        ck_assert_int_eq(3, vcpp->vcp_suffix_len);
        /* mask: last 12 bits = ...00000FFF */
        ck_assert_int_eq(0x0F, vcpp->vcp_suffix_mask[18]);
        ck_assert_int_eq(0xFF, vcpp->vcp_suffix_mask[19]);
        ck_assert_int_eq(0x00, vcpp->vcp_suffix_mask[17]);
        /* target: ...00000ABC */
        ck_assert_int_eq(0x0A, vcpp->vcp_suffix_target[18]);
        ck_assert_int_eq(0xBC, vcpp->vcp_suffix_target[19]);

        vg_context_free(vcp);
    }

    /* Test combined prefix+suffix: 0xAA*beef */
    {
        vg_context_t *vcp = vg_prefix_context_new(ADDR_TYPE_ETH, PRIV_TYPE_ETH, 0);
        const char *patterns[] = { "0xAA*beef" };
        int rv = vg_context_add_patterns(vcp, patterns, 1);
        ck_assert_int_eq(1, rv);

        vg_prefix_context_t *vcpp = (vg_prefix_context_t *)vcp;
        ck_assert_int_eq(1, vcpp->vcp_has_suffix);
        ck_assert_int_eq(4, vcpp->vcp_suffix_len);
        /* suffix target: ...0000BEEF */
        ck_assert_int_eq(0xBE, vcpp->vcp_suffix_target[18]);
        ck_assert_int_eq(0xEF, vcpp->vcp_suffix_target[19]);
        /* prefix should also be added (npatterns > 0 indicates prefix was registered) */
        ck_assert(!avl_root_empty(&vcpp->vcp_avlroot));

        vg_context_free(vcp);
    }
}
END_TEST

START_TEST(test_eth_suffix_match_verify)
{
    /* Test binary suffix match verification */
    {
        vg_context_t *vcp = vg_prefix_context_new(ADDR_TYPE_ETH, PRIV_TYPE_ETH, 1); /* case-insensitive */
        const char *patterns[] = { "*dead" };
        vg_context_add_patterns(vcp, patterns, 1);
        vg_prefix_context_t *vcpp = (vg_prefix_context_t *)vcp;

        /* Address ending with ...dead should match */
        unsigned char addr_match[20] = {0};
        addr_match[18] = 0xDE;
        addr_match[19] = 0xAD;
        ck_assert_int_eq(1, vg_prefix_check_suffix(vcpp, addr_match));

        /* Address ending with ...beef should not match */
        unsigned char addr_no[20] = {0};
        addr_no[18] = 0xBE;
        addr_no[19] = 0xEF;
        ck_assert_int_eq(0, vg_prefix_check_suffix(vcpp, addr_no));

        /* Any prefix bytes should not affect suffix match */
        unsigned char addr_prefix[20];
        memset(addr_prefix, 0xFF, 20);
        addr_prefix[18] = 0xDE;
        addr_prefix[19] = 0xAD;
        ck_assert_int_eq(1, vg_prefix_check_suffix(vcpp, addr_prefix));

        vg_context_free(vcp);
    }
}
END_TEST

START_TEST(test_trx_suffix_parsing)
{
    /* Test suffix-only pattern: *xyz */
    {
        TRXFlag = 1;
        vg_context_t *vcp = vg_prefix_context_new(65, 193, 0);
        ck_assert_ptr_nonnull(vcp);
        const char *patterns[] = { "*xyz" };
        int rv = vg_context_add_patterns(vcp, patterns, 1);
        ck_assert_int_eq(1, rv);

        vg_prefix_context_t *vcpp = (vg_prefix_context_t *)vcp;
        ck_assert_int_eq(1, vcpp->vcp_has_suffix);
        ck_assert_int_eq(3, vcpp->vcp_suffix_len);

        /* divisor = 58^3 = 195112 */
        ck_assert(vcpp->vcp_suffix_divisor == 195112ULL);

        /* target = x*58^2 + y*58 + z
         * In Base58 alphabet "123456789ABCDEFGH JKLMN PQRSTUVWXYZ abcdefghijk mnopqrstuvwxyz":
         * x=55, y=56, z=57
         * target = 55*3364 + 56*58 + 57 = 185020 + 3248 + 57 = 188325 */
        ck_assert(vcpp->vcp_suffix_b58target == 188325ULL);

        /* AVL tree should be empty (suffix-only) */
        ck_assert(avl_root_empty(&vcpp->vcp_avlroot));

        vg_context_free(vcp);
        TRXFlag = 0;
    }

    /* Test combined prefix+suffix: TJ*abc */
    {
        TRXFlag = 1;
        vg_context_t *vcp = vg_prefix_context_new(65, 193, 0);
        const char *patterns[] = { "TJ*abc" };
        int rv = vg_context_add_patterns(vcp, patterns, 1);
        ck_assert_int_eq(1, rv);

        vg_prefix_context_t *vcpp = (vg_prefix_context_t *)vcp;
        ck_assert_int_eq(1, vcpp->vcp_has_suffix);
        ck_assert_int_eq(3, vcpp->vcp_suffix_len);
        ck_assert(vcpp->vcp_suffix_divisor == 195112ULL);

        /* a=33, b=34, c=35 in Base58
         * target = 33*3364 + 34*58 + 35 = 111012 + 1972 + 35 = 113019 */
        ck_assert(vcpp->vcp_suffix_b58target == 113019ULL);

        /* Prefix should be registered in AVL tree */
        ck_assert(!avl_root_empty(&vcpp->vcp_avlroot));

        vg_context_free(vcp);
        TRXFlag = 0;
    }

    /* Test invalid Base58 character in suffix */
    {
        TRXFlag = 1;
        vg_context_t *vcp = vg_prefix_context_new(65, 193, 0);
        const char *patterns[] = { "*0OI" }; /* 0, O, I are not valid Base58 */
        int rv = vg_context_add_patterns(vcp, patterns, 1);
        ck_assert_int_eq(0, rv); /* Should fail */

        vg_context_free(vcp);
        TRXFlag = 0;
    }
}
END_TEST

START_TEST(test_trx_suffix_cpu_verify)
{
    /* Test CPU-side TRX suffix verification using a known address.
     *
     * Use a known TRX address: binres = [0x41][20-byte hash]
     * We compute the Base58Check address, take its suffix, and verify
     * that vg_prefix_check_suffix_trx matches correctly.
     */
    {
        TRXFlag = 1;

        /* Known: address "TNYpSezj43FNgFKQxenHRXbfi3j2qqfMnc"
         * version = 0x41 = 65
         * hash = a3e53e209f76e7de1e0b1eef9b1c5c9d0a2e2cf0 (example) */
        unsigned char binres[21];
        binres[0] = 0x41;
        /* Use all zeros for hash - this gives a deterministic address */
        memset(binres + 1, 0, 20);

        /* Compute the expected address */
        char addr_buf[64];
        vg_b58_encode_check(binres, 21, addr_buf);
        size_t addr_len = strlen(addr_buf);

        /* Use the last 3 chars as suffix */
        ck_assert(addr_len >= 3);
        char suffix[4];
        memcpy(suffix, addr_buf + (addr_len - 3), 3);
        suffix[3] = '\0';

        /* Build a pattern with this suffix */
        char pattern[16];
        snprintf(pattern, sizeof(pattern), "*%s", suffix);

        vg_context_t *vcp = vg_prefix_context_new(65, 193, 0);
        const char *patterns[] = { pattern };
        int rv = vg_context_add_patterns(vcp, patterns, 1);
        ck_assert_int_eq(1, rv);

        vg_prefix_context_t *vcpp = (vg_prefix_context_t *)vcp;
        /* Should match */
        ck_assert_int_eq(1, vg_prefix_check_suffix_trx(vcpp, binres));

        /* Different hash should likely not match */
        unsigned char binres2[21];
        binres2[0] = 0x41;
        memset(binres2 + 1, 0xFF, 20);
        /* This may or may not match by coincidence, so just verify
         * that the function runs without crashing. For a rigorous
         * test, we check the actual address suffix. */
        char addr_buf2[64];
        vg_b58_encode_check(binres2, 21, addr_buf2);
        size_t addr_len2 = strlen(addr_buf2);
        int should_match = (addr_len2 >= 3 &&
                           memcmp(addr_buf2 + (addr_len2 - 3), suffix, 3) == 0);
        ck_assert_int_eq(should_match,
                        vg_prefix_check_suffix_trx(vcpp, binres2));

        vg_context_free(vcp);
        TRXFlag = 0;
    }
}
END_TEST
