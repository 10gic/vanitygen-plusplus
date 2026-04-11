#include <memory.h>
#include "base32.h"
#include "stellar.h"
#include "crc16.h"

void strkey_encode(unsigned char versionByte, const unsigned char *in, size_t in_len, unsigned char *out) {
    unsigned char buf[35]; // 1 byte version, 32 bytes input, 2 bytes crc16 checksum
    buf[0] = versionByte;
    memcpy(buf + 1, in, in_len);
    unsigned short crc16result = crc16(buf, (int)(1 + in_len));
    buf[1 + in_len] = (unsigned char)(crc16result & 0x00FF);  // little-endian
    buf[2 + in_len] = (unsigned char)(crc16result >> 8);
    size_t encoded_len = ((1 + in_len + 2) + 4) / 5 * 8; // base32: ceil(n/5)*8
    base32_encode(buf, 1 + in_len + 2, out);
    out[encoded_len] = '\0';
}
