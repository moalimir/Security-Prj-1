#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    FILE *input = fopen(argv[1], "rb");
    if (!input) return 1;
    if (fseek(input, 0, SEEK_END) != 0) { fclose(input); return 1; }
    long length = ftell(input);
    if (length <= 0 || length > 1024 * 1024 || fseek(input, 0, SEEK_SET) != 0) {
        fclose(input);
        return 1;
    }
    /* Keep the exact allocation: a sentinel would mask the upstream over-read. */
    char *data = malloc((size_t)length);
    if (!data) { fclose(input); return 1; }
    int failed = fread(data, 1, (size_t)length, input) != (size_t)length || ferror(input);
    if (fclose(input) != 0) failed = 1;
    if (failed) { free(data); return 1; }

    const char *end = NULL;
    cJSON *document = cJSON_ParseWithLengthOpts(data, (size_t)length, &end, 0);
    if (!document) { free(data); return 1; }
    while (end < data + length && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) ++end;
    if (end != data + length) { cJSON_Delete(document); free(data); return 1; }
    char *output = cJSON_PrintUnformatted(document);
    cJSON_Delete(document);
    free(data);
    if (!output) return 1;
    failed = fputs(output, stdout) == EOF;
    if (fputc('\n', stdout) == EOF || fflush(stdout) != 0) failed = 1;
    cJSON_free(output);
    return failed ? 1 : 0;
}
