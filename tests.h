#include "util.h"
#include "pattern.h"
#include "segwit_addr.h"
#include <check.h>

#define FROM_HEX_MAXLEN 512

const uint8_t *from_hex(const char *str) {
	static uint8_t buf[FROM_HEX_MAXLEN];
	size_t len = strlen(str) / 2;
	if (len > FROM_HEX_MAXLEN) len = FROM_HEX_MAXLEN;
	for (size_t i = 0; i < len; i++) {
		uint8_t c = 0;
		if (str[i * 2] >= '0' && str[i*2] <= '9') c += (str[i * 2] - '0') << 4;
		if ((str[i * 2] & ~0x20) >= 'A' && (str[i*2] & ~0x20) <= 'F') c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
		if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9') c += (str[i * 2 + 1] - '0');
		if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F') c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
		buf[i] = c;
	}
	return buf;
}


START_TEST(test_sample)
{
    ck_assert_int_eq(512, 512);
    ck_assert_str_eq("Hello World", "Hello World");
}
END_TEST

#include "util_test.h"
#include "segwit_addr_test.h"
#include "pattern_test.h"

Suite* create_sample_suite(void)
{
    Suite* suite = suite_create("Sample suite");
    TCase* tc;

    tc = tcase_create("sample test case");
    tcase_add_test(tc, test_sample);
    suite_add_tcase(suite, tc);

    tc = tcase_create("util hex test");
    tcase_add_test(tc, test_hex_enc);
    tcase_add_test(tc, test_hex_dec);
    suite_add_tcase(suite, tc);

	tc = tcase_create("util eth test");
	tcase_add_test(tc, test_eth_pubkey2addr);
	tcase_add_test(tc, test_eth_encode_checksum_addr);
	suite_add_tcase(suite, tc);

	tc = tcase_create("segwit addr test");
	tcase_add_test(tc, test_segwit_addr_encode);
	suite_add_tcase(suite, tc);

	tc = tcase_create("pattern func test");
	tcase_add_test(tc, test_get_prefix_ranges);
	suite_add_tcase(suite, tc);

    return suite;
}
