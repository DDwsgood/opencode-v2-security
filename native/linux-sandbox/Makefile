# Build the P4 sandbox helper as a static x86_64 ELF into ../../bin/.
# Run once per source change; the output binary is committed.
CC      ?= gcc
CFLAGS  ?= -O2 -static -s -Wall -Wextra
OUT     := ../../bin/opencode-sandbox
SRC     := opencode-sandbox.c

$(OUT): $(SRC)
	mkdir -p ../../bin
	$(CC) $(CFLAGS) -o $(OUT) $(SRC)

.PHONY: clean
clean:
	rm -f $(OUT)
