CC = clang
OUT ?= target_bin
COMMON = -std=c11 -Wall -Wextra -Werror
RELEASE_FLAGS = -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2
ifeq ($(shell uname -s),Linux)
RELEASE_FLAGS += -fPIE -pie -Wl,-z,relro,-z,now
endif

.PHONY: release sanitized
release:
	$(CC) $(COMMON) $(RELEASE_FLAGS) driver.c tlv_parser.c -o "$(OUT)"

sanitized:
	$(CC) $(COMMON) -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer driver.c tlv_parser.c -o "$(OUT)"
