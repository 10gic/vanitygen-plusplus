START_TEST(test_segwit_addr_encode)
{
    struct valid_address_data {
        const char* expect_output_address;
        const char* hrp;
        uint8_t ver;
        const uint8_t witprog[64];
        size_t witprog_len;
    };

    static struct valid_address_data valid_address_tests[] = {
        {
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "bc",
            0,
            {
                0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4,
                0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23,
                0xf1, 0x43, 0x3b, 0xd6
            },
            20,
        },
        {
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            "tb",
            0,
            {
                0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68,
                0x04, 0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13,
                0x6c, 0x98, 0x56, 0x78, 0xcd, 0x4d, 0x27, 0xa1,
                0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32, 0x62
            },
            32
        },
        {
            "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
            "tb",
            0,
            {
                0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62,
                0x21, 0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66,
                0x36, 0x2b, 0x99, 0xd5, 0xe9, 0x1c, 0x6c, 0xe2,
                0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64, 0x33
            },
            32
        },
        {
            "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
            "tb",
            1,
            {
                0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62,
                0x21, 0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66,
                0x36, 0x2b, 0x99, 0xd5, 0xe9, 0x1c, 0x6c, 0xe2,
                0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64, 0x33
            },
            32
        },
        {
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            "bc",
            1,
            {
                0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
                0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
                0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
                0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98
            },
            32
        },
    };

    size_t n = sizeof(valid_address_tests) / sizeof(valid_address_tests[0]);


    for (int i = 0; i < n; i++) {
        char got[128] = {'\0'};

        int ret = segwit_addr_encode(got,
                                     valid_address_tests[i].hrp,
                                     valid_address_tests[i].ver,
                                     valid_address_tests[i].witprog,
                                     valid_address_tests[i].witprog_len);
        int expect_ret = 1;

        ck_assert_int_eq(ret, expect_ret);
        ck_assert_mem_eq(got,
                         valid_address_tests[i].expect_output_address,
                         strlen(valid_address_tests[i].expect_output_address));
    }
}
END_TEST

