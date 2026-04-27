#ifndef BYTEORDER_H
#define BYTEORDER_H

#include <stdint.h>
#include <stddef.h>

void write_u32_be(uint32_t value, unsigned char out[4]);
uint32_t read_u32_be(const unsigned char in[4]);

#endif