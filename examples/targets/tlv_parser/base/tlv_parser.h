#ifndef TLV_PARSER_H
#define TLV_PARSER_H

#include <stddef.h>
#include <stdio.h>

/* The caller publishes staged output only after a successful parse. */
int parse_packet(const unsigned char *data, size_t size, FILE *output);

#endif
