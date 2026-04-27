#include <byteorder.h>

void write_u32_be(uint32_t value, unsigned char out[4])
{
    out[0] = (value >> 24) & 0xff;
    out[1] = (value >> 16) & 0xff;
    out[2] = (value >> 8) & 0xff;
    out[3] = value & 0xff;
}

uint32_t read_u32_be(const unsigned char in[4])
{
    return ((uint32_t)in[0] << 24) |
           ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8)  |
           ((uint32_t)in[3]);
}