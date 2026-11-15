/* Local test fixture only: deliberately vulnerable baseline, not a final target. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *file = fopen(argv[1], "rb");
    if (!file) return 2;
    char input[256];
    size_t length = fread(input, 1, sizeof(input), file);
    int failed = ferror(file);
    fclose(file);
    if (failed) return 2;
    if (length == 0) return 1;
    /* PATCH */
    char *buffer = malloc(8);
    if (!buffer) return 2;
    memcpy(buffer, input, length);
    fwrite(buffer, 1, length, stdout);
    putchar('\n');
    free(buffer);
    return 0;
}
