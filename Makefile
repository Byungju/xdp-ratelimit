CLANG		?= clang
CC		?= gcc
BPFTOOL		?= bpftool

ARCH		?= $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/' -e 's/ppc64le/powerpc/' -e 's/riscv64/riscv/')
MULTIARCH	:= $(shell $(CC) -dumpmachine)

BUILD		:= build
BPF_OBJ		:= $(BUILD)/xdp_ratelimit.bpf.o
SKEL		:= $(BUILD)/xdp_ratelimit.skel.h
BIN		:= $(BUILD)/xdp-ratelimit

BPF_CFLAGS	:= -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		   -I/usr/include/$(MULTIARCH) -I/usr/include -Isrc
CFLAGS		:= -g -O2 -Wall -Wextra -Isrc -I$(BUILD)
LDLIBS		:= -lbpf -lelf -lz

BENCH_PKTGEN	:= $(BUILD)/pktgen
BENCH_SINK	:= $(BUILD)/udp_sink

.PHONY: all clean test bench

all: $(BIN)

bench: $(BENCH_PKTGEN) $(BENCH_SINK)

$(BUILD):
	mkdir -p $(BUILD)

$(BPF_OBJ): src/xdp_ratelimit.bpf.c src/xdp_ratelimit.h | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@.tmp
	mv $@.tmp $@

$(BIN): src/xdp_ratelimit.c src/xdp_ratelimit.h $(SKEL) | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

$(BENCH_PKTGEN): bench/pktgen.c | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@

$(BENCH_SINK): bench/udp_sink.c | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(BUILD)

test: all
	./tests/test_iptables_rules.sh
	./tests/test_xdp_ratelimit.sh

bench-all: bench
	./bench/run_bench.sh --quick
