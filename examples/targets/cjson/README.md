# cJSON target study

This is the real cJSON **1.7.17** C library, not a replacement parser.
`base/cJSON.c`, `base/cJSON.h`, `base/LICENSE`, and `base/UPSTREAM_README.md`
are unmodified upstream files. Exact upstream revision, file checksums, and
patch provenance are in [provenance.json](provenance.json). The remaining
files implement the course harness and explicitly labeled patch variants.

The upstream [issue #800](https://github.com/DaveGamble/cJSON/issues/800)
documents an out-of-bounds read when a length-delimited, non-NUL-terminated
object ends in a comma. `parse_object` advances past the buffer and calls
`parse_string`, which reads outside the allocation. The complete patch is the
unaltered upstream [commit c390438](https://github.com/DaveGamble/cJSON/commit/c39043866aaef2e599045b2c04936b247f84d82d)
from [PR #852](https://github.com/DaveGamble/cJSON/pull/852), applied to 1.7.17.
This study fixes that issue only; it does not claim this old release has no
other bugs.

| Git tag | Library change | Expected evidence |
| --- | --- | --- |
| `base` | Upstream 1.7.17, unchanged | Both exploits produce ASan heap-buffer-overflow reads |
| `correct` | Upstream bounds check inside `parse_object` | Both exploits safely rejected; functional cases preserved |
| `incomplete` | Course mutation: bounds check only at depth 1 | Original exploit rejected; nested exploit still over-reads |
| `regression` | Course mutation: complete fix plus empty-object rejection | Both exploits rejected; valid `{}` rejected |

All three patches apply independently to `base`. Incomplete and regression
variants are local teaching mutations, **not** historical upstream releases.
`tools/prepare_targets.py` creates the four actual Git revisions offline and
leaves `correct` checked out. The target is a self-contained copy of the
library needed by the driver, not a clone of its entire upstream history.

## Driver contract

`target_bin INPUT_FILE` reads one document (maximum 1 MiB), calls
`cJSON_ParseWithLengthOpts` with the exact input length, and requires the rest
of the file to contain only JSON whitespace. On success it prints cJSON's
compact representation followed by LF and returns 0. Empty input, syntax
failure, trailing data, file/allocation failure, or an oversized file returns
1. Parse failures produce no stdout. No NUL sentinel is added: upstream
explicitly identified such padding as masking this bug.

The contract uses cJSON's supported JSON representation and number formatting;
it does not add a second RFC conformance parser. The reference corpus avoids
large/ambiguous numbers, duplicate keys and embedded NUL string values where
JSON libraries' data models or formatting can differ. Literal oracle outputs
are cross-checked with Python's independent standard-library JSON parser.

`tests/cjson/exploit/original_poc.json` is exactly the seven bytes
`{"1":1,`, without LF or NUL, from issue #800. `bypass_poc.json` is the
16-byte `{"outer":{"1":1,`, also without LF/NUL; it reaches the same
read through a nested object and bypasses the depth-1-only guard. Both are
invalid JSON and must return 1 without stdout on the correct revision.

## Build and validate

From the project root:

```sh
python tools/prepare_targets.py
make -C targets/cjson release
make -C targets/cjson sanitized OUT=target_sanitized
python -m src -c configs/cjson_correct.yaml -o reports/cjson_correct --skip-hardening
python -m unittest tests.test_prepared_targets -v
```

Preparation refuses to overwrite existing targets. Run it once, or pass a fresh
`--output-dir` for a separate copy. The correct native macOS comparison exits
40 because ELF hardening is skipped. Linux x86_64 validation with hardening
enabled should exit 0; incomplete and regression comparisons should exit 10
and 20 respectively. Instructor approval of target/oracle selection remains
a separate course requirement.
