# Build the P4 sandbox helper and the boundary watcher as static x86_64
# ELFs into ../../bin/. Run once per source change; the output binaries are
# committed.
CC      ?= gcc
CFLAGS  ?= -O2 -static -s -Wall -Wextra
OUT     := ../../bin/opencode-sandbox
OUT_BW  := ../../bin/opencode-boundary-watch
SRC     := opencode-sandbox.c
SRC_BW  := opencode-boundary-watch.c

all: $(OUT) $(OUT_BW)

$(OUT): $(SRC)
	mkdir -p ../../bin
	$(CC) $(CFLAGS) -o $(OUT) $(SRC)

$(OUT_BW): $(SRC_BW)
	mkdir -p ../../bin
	$(CC) $(CFLAGS) -o $(OUT_BW) $(SRC_BW)

.PHONY: clean
clean:
	rm -f $(OUT) $(OUT_BW)
