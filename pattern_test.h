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
