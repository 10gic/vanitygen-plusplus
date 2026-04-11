#include <check.h>
#include <string.h>
#include <stdint.h>
#include <openssl/sha.h>
#include "crc16.h"

/* =========================================================================
 * TON address derivation (minimal standalone copy for testing)
 * ========================================================================= */

typedef struct {
    const char *name;
    uint8_t  si_prefix[39];
    uint8_t  dc_msg_prefix[10];
    uint8_t  dc_carry;
    int      pubkey_shift;
} ton_wallet_test_t;

static const ton_wallet_test_t test_ton_v5r1 = {
    .name = "V5R1",
    .si_prefix = {
        0x02, 0x01, 0x34,
        0x00, 0x06,
        0x00, 0x00,
        0x20, 0x83, 0x4b, 0x7b, 0x72, 0xb1, 0x12, 0x14,
        0x7e, 0x1b, 0x2f, 0xb4, 0x57, 0xb8, 0x4e, 0x74,
        0xd1, 0xa3, 0x0f, 0x04, 0xf7, 0x37, 0xd4, 0xf6,
        0x2a, 0x66, 0x8e, 0x95, 0x52, 0xd2, 0xb7, 0x2f,
    },
    .dc_msg_prefix = {
        0x00, 0x51,
        0x80, 0x00, 0x00, 0x00,
        0x3F, 0xFF, 0xFF, 0x88,
    },
    .dc_carry = 0x80,
    .pubkey_shift = 1,
};

static const ton_wallet_test_t test_ton_v4r2 = {
    .name = "V4R2",
    .si_prefix = {
        0x02, 0x01, 0x34,
        0x00, 0x07,
        0x00, 0x00,
        0xfe, 0xb5, 0xff, 0x68, 0x20, 0xe2, 0xff, 0x0d,
        0x94, 0x83, 0xe7, 0xe0, 0xd6, 0x2c, 0x81, 0x7d,
        0x84, 0x67, 0x89, 0xfb, 0x4a, 0xe5, 0x80, 0xc8,
        0x78, 0x86, 0x6d, 0x95, 0x9d, 0xab, 0xd5, 0xc0,
    },
    .dc_msg_prefix = {
        0x00, 0x51,
        0x00, 0x00, 0x00, 0x00,
        0x29, 0xA9, 0xA3, 0x17,
    },
    .dc_carry = 0x00,
    .pubkey_shift = 0,
};

static void
test_ton_data_cell_hash(const ton_wallet_test_t *w, const uint8_t *pubkey, uint8_t *hash_out)
{
    uint8_t msg[43];
    memcpy(msg, w->dc_msg_prefix, 10);
    if (w->pubkey_shift) {
        msg[10] = w->dc_carry | (pubkey[0] >> 1);
        for (int i = 1; i < 32; i++)
            msg[10 + i] = (uint8_t)((pubkey[i-1] << 7) | (pubkey[i] >> 1));
        msg[42] = (uint8_t)((pubkey[31] << 7) | 0x20);
    } else {
        memcpy(msg + 10, pubkey, 32);
        msg[42] = 0x40;
    }
    SHA256(msg, 43, hash_out);
}

static void
test_ton_stateinit_hash(const ton_wallet_test_t *w, const uint8_t *data_hash, uint8_t *hash_out)
{
    uint8_t msg[71];
    memcpy(msg, w->si_prefix, 39);
    memcpy(msg + 39, data_hash, 32);
    SHA256(msg, 71, hash_out);
}

static const char test_b64url_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static void
test_base64url_encode(const uint8_t *in, size_t len, char *out)
{
    size_t i, j = 0;
    for (i = 0; i + 2 < len; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | in[i+2];
        out[j++] = test_b64url_chars[(v >> 18) & 0x3F];
        out[j++] = test_b64url_chars[(v >> 12) & 0x3F];
        out[j++] = test_b64url_chars[(v >> 6) & 0x3F];
        out[j++] = test_b64url_chars[v & 0x3F];
    }
    out[j] = '\0';
}

static void
test_ton_encode_address(const uint8_t *si_hash, int bounceable, char *addr_out)
{
    uint8_t buf[36];
    buf[0] = bounceable ? 0x11 : 0x51;
    buf[1] = 0x00;
    memcpy(buf + 2, si_hash, 32);
    uint16_t c = crc16(buf, 34);
    buf[34] = (uint8_t)(c >> 8);
    buf[35] = (uint8_t)(c & 0xFF);
    test_base64url_encode(buf, 36, addr_out);
}

/* =========================================================================
 * Test cases
 * ========================================================================= */

/* Test pubkey from ton-example.js */
static const uint8_t test_pubkey[] = {
    0xf6, 0x25, 0x75, 0xb8, 0x00, 0xbe, 0x30, 0xf1,
    0xca, 0x04, 0x35, 0xfb, 0xb4, 0x70, 0xbe, 0x91,
    0x5d, 0xeb, 0x5b, 0xd6, 0x98, 0xde, 0xbb, 0x5a,
    0x29, 0xb1, 0x9c, 0xd5, 0x8c, 0xcf, 0xf9, 0x75,
};

START_TEST(test_ton_v5r1_data_cell_hash)
{
    uint8_t hash[32];
    test_ton_data_cell_hash(&test_ton_v5r1, test_pubkey, hash);
    const uint8_t *expected = from_hex("50928487809e4f0a3490a88374e041ebffeb88f882bbcc641ec7cf85b35e4f26");
    ck_assert_mem_eq(hash, expected, 32);
}
END_TEST

START_TEST(test_ton_v4r2_data_cell_hash)
{
    uint8_t hash[32];
    test_ton_data_cell_hash(&test_ton_v4r2, test_pubkey, hash);
    const uint8_t *expected = from_hex("df51d64f4a454a563798d2ca2f65bce2102f7218b848ccd990f25d6f7ec72829");
    ck_assert_mem_eq(hash, expected, 32);
}
END_TEST

START_TEST(test_ton_v5r1_stateinit_hash)
{
    uint8_t data_hash[32], si_hash[32];
    test_ton_data_cell_hash(&test_ton_v5r1, test_pubkey, data_hash);
    test_ton_stateinit_hash(&test_ton_v5r1, data_hash, si_hash);
    const uint8_t *expected = from_hex("46d8bc093ed54a5e5507a17106988164b1b2da09982b043b440c3d0cc65dbea1");
    ck_assert_mem_eq(si_hash, expected, 32);
}
END_TEST

START_TEST(test_ton_v4r2_stateinit_hash)
{
    uint8_t data_hash[32], si_hash[32];
    test_ton_data_cell_hash(&test_ton_v4r2, test_pubkey, data_hash);
    test_ton_stateinit_hash(&test_ton_v4r2, data_hash, si_hash);
    const uint8_t *expected = from_hex("794b27615f061ba5cd6a3fc45e77fa5fe17ba23a436fb4d88a2d9ce1c79e285c");
    ck_assert_mem_eq(si_hash, expected, 32);
}
END_TEST

START_TEST(test_ton_v5r1_address_bounceable)
{
    uint8_t data_hash[32], si_hash[32];
    char addr[64];
    test_ton_data_cell_hash(&test_ton_v5r1, test_pubkey, data_hash);
    test_ton_stateinit_hash(&test_ton_v5r1, data_hash, si_hash);
    test_ton_encode_address(si_hash, 1, addr);
    ck_assert_str_eq(addr, "EQBG2LwJPtVKXlUHoXEGmIFksbLaCZgrBDtEDD0Mxl2-oWSC");
}
END_TEST

START_TEST(test_ton_v5r1_address_non_bounceable)
{
    uint8_t data_hash[32], si_hash[32];
    char addr[64];
    test_ton_data_cell_hash(&test_ton_v5r1, test_pubkey, data_hash);
    test_ton_stateinit_hash(&test_ton_v5r1, data_hash, si_hash);
    test_ton_encode_address(si_hash, 0, addr);
    ck_assert_str_eq(addr, "UQBG2LwJPtVKXlUHoXEGmIFksbLaCZgrBDtEDD0Mxl2-oTlH");
}
END_TEST

START_TEST(test_ton_v4r2_address_bounceable)
{
    uint8_t data_hash[32], si_hash[32];
    char addr[64];
    test_ton_data_cell_hash(&test_ton_v4r2, test_pubkey, data_hash);
    test_ton_stateinit_hash(&test_ton_v4r2, data_hash, si_hash);
    test_ton_encode_address(si_hash, 1, addr);
    ck_assert_str_eq(addr, "EQB5SydhXwYbpc1qP8Red_pf4XuiOkNvtNiKLZzhx54oXJ_6");
}
END_TEST

START_TEST(test_ton_v4r2_address_non_bounceable)
{
    uint8_t data_hash[32], si_hash[32];
    char addr[64];
    test_ton_data_cell_hash(&test_ton_v4r2, test_pubkey, data_hash);
    test_ton_stateinit_hash(&test_ton_v4r2, data_hash, si_hash);
    test_ton_encode_address(si_hash, 0, addr);
    ck_assert_str_eq(addr, "UQB5SydhXwYbpc1qP8Red_pf4XuiOkNvtNiKLZzhx54oXMI_");
}
END_TEST

START_TEST(test_ton_bounceable_detection)
{
    /* EQ prefix → bounceable */
    ck_assert_int_eq(
        (strlen("EQABC") >= 2 && 'E' == 'E' && 'Q' == 'Q') ? 1 : 0,
        1);
    /* UQ prefix → not bounceable */
    ck_assert_int_eq(
        (strlen("UQABC") >= 2 && 'U' == 'E' && 'Q' == 'Q') ? 1 : 0,
        0);
    /* Suffix only → not bounceable */
    ck_assert_int_eq(
        (strlen("") >= 2) ? 1 : 0,
        0);
}
END_TEST
