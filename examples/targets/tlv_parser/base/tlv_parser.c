#include "tlv_parser.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TAG_LABEL 1
#define TAG_UINT32 2
#define TAG_NESTED 3
#define MAX_NESTING 16

static int parse_label_record(const unsigned char *payload, size_t rec_len, FILE *output) {
    for (size_t i = 0; i < rec_len; ++i) {
        if (payload[i] > 0x7f) return -1;
    }
    char *label = malloc(17);
    if (!label) return -1;
    /* Deliberately vulnerable training baseline: the field holds at most 16 bytes. */
    memcpy(label, payload, rec_len);
    label[rec_len] = '\0';
    int failed = fputs("LABEL:", output) == EOF;
    if (fwrite(label, 1, rec_len, output) != rec_len) failed = 1;
    if (fputc('\n', output) == EOF) failed = 1;
    free(label);
    return failed ? -1 : 0;
}

static int parse_record(unsigned char tag, const unsigned char *payload,
                        size_t rec_len, unsigned depth, FILE *output) {
    switch (tag) {
        case TAG_LABEL:
            return parse_label_record(payload, rec_len, output);
        case TAG_UINT32: {
            if (rec_len != 4) return -1;
            uint32_t value = ((uint32_t)payload[0] << 24) | ((uint32_t)payload[1] << 16)
                           | ((uint32_t)payload[2] << 8) | payload[3];
            return fprintf(output, "UINT32:%lu\n", (unsigned long)value) < 0 ? -1 : 0;
        }
        case TAG_NESTED:
            if (depth >= MAX_NESTING || rec_len < 2 || (size_t)payload[1] != rec_len - 2) return -1;
            if (fputs("NESTED->", output) == EOF) return -1;
            return parse_record(payload[0], payload + 2, payload[1], depth + 1, output);
        default:
            return -1;
    }
}

int parse_packet(const unsigned char *data, size_t size, FILE *output) {
    if (size < 4 || data[0] != 'T' || data[1] != 1 || data[3] != 0) return -1;
    size_t offset = 4;
    for (unsigned record = 0; record < data[2]; ++record) {
        if (size - offset < 2) return -1;
        unsigned char tag = data[offset];
        size_t rec_len = data[offset + 1];
        offset += 2;
        if (rec_len > size - offset) return -1;
        switch (tag) {
            case TAG_LABEL:
                if (parse_label_record(data + offset, rec_len, output) < 0) return -1;
                break;
            default:
                if (parse_record(tag, data + offset, rec_len, 0, output) < 0) return -1;
        }
        offset += rec_len;
    }
    return offset == size ? 0 : -1;
}
