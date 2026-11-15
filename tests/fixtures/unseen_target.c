/* Harmless fixture: diagnostics are printed, never caused by a memory error. */
#include <stdio.h>
#include <string.h>

static int emit_diagnostic(int caller_line)
{
    fputs("ERROR: AddressSanitizer: heap-buffer-overflow\n", stderr);
    fprintf(stderr, "    #0 0x123 in emit_diagnostic target.c:%d:1\n", __LINE__);
    fprintf(stderr, "    #1 0x456 in main target.c:%d:1\n", caller_line);
    return 1;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
#ifdef INPUT_ARGS
    const char *value = argv[1];
#else
    char input[1024] = {0};
    FILE *stream = fopen(argv[1], "rb");
    if (!stream) return 2;
    fread(input, 1, sizeof(input) - 1, stream);
    fclose(stream);
    const char *value = input;
#endif
    if (strcmp(value, "exploit") == 0 || strcmp(value, "remaining") == 0) {
#ifdef FIXTURE_SANITIZED
        return emit_diagnostic(__LINE__);
#endif
    }
    if (strncmp(value, "echo:", 5) == 0) {
        fputs(value + 5, stdout);
        return 0;
    }
    puts("ok");
    return 0;
}
