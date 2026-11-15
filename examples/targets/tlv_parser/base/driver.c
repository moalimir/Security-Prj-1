#include "tlv_parser.h"

#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    FILE *input = fopen(argv[1], "rb");
    if (!input) return 1;
    if (fseek(input, 0, SEEK_END) != 0) { fclose(input); return 1; }
    long length = ftell(input);
    /* Header count and byte-sized lengths bound the largest legal packet. */
    if (length < 4 || length > 4 + 255 * 257 || fseek(input, 0, SEEK_SET) != 0) {
        fclose(input);
        return 1;
    }
    unsigned char *data = malloc((size_t)length);
    if (!data) { fclose(input); return 1; }
    int failed = fread(data, 1, (size_t)length, input) != (size_t)length || ferror(input);
    if (fclose(input) != 0) failed = 1;
    FILE *staged = tmpfile();
    if (!staged) { free(data); return 1; }
    if (!failed && parse_packet(data, (size_t)length, staged) < 0) failed = 1;
    free(data);
    if (failed || fflush(staged) != 0 || fseek(staged, 0, SEEK_SET) != 0) {
        fclose(staged);
        return 1;
    }
    char chunk[4096];
    size_t count;
    while ((count = fread(chunk, 1, sizeof(chunk), staged)) != 0) {
        if (fwrite(chunk, 1, count, stdout) != count) { failed = 1; break; }
    }
    if (ferror(staged)) failed = 1;
    if (fclose(staged) != 0) failed = 1;
    if (fflush(stdout) != 0) failed = 1;
    return failed ? 1 : 0;
}
