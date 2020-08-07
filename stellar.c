#include <memory.h>
#include "base32.h"
#include "stellar.h"
#include "crc16.h"

void strkey_encode(unsigned char versionByte, unsigned char *in, size_t in_len, unsigned char *out) {
    unsigned char buf[35]; // 1 byte version, 32 bytes input, 2 bytes crc16 checksum
    buf[0] = versionByte;
    memcpy(buf + 1, in, 32);
    unsigned short crc16result = crc16(buf, 33);
    buf[33] = (unsigned char)(crc16result & 0x00FF);  // assume little-endian
    buf[34] = (unsigned char)(crc16result >> 8);
    // dumphex(buf, 35);
    base32_encode(buf, 35, out);
}
