.PHONY: all test clean

PYTHON ?= python3

TARGETS = examples/simple_crackme examples/hash_crackme \
	examples/simple_crackme_i386 examples/hash_crackme_i386 \
	examples/stream_crackme examples/stream_crackme_i386

all: $(TARGETS)

examples/simple_crackme: examples/simple_crackme.c
	$(CC) -O0 -g -fno-stack-protector -fno-pie -no-pie -o $@ $<

examples/hash_crackme: examples/hash_crackme.c
	$(CC) -O0 -g -fno-stack-protector -fno-pie -no-pie -o $@ $<

examples/simple_crackme_i386: examples/simple_crackme.c
	$(CC) -m32 -O0 -g -fno-stack-protector -fno-pie -no-pie -o $@ $<

examples/hash_crackme_i386: examples/hash_crackme.c
	$(CC) -m32 -O0 -g -fno-stack-protector -fno-pie -no-pie -o $@ $<

examples/stream_crackme: examples/stream_crackme.c
	$(CC) -O0 -g -fno-stack-protector -fno-pie -no-pie -o $@ $<

examples/stream_crackme_i386: examples/stream_crackme.c
	$(CC) -m32 -O0 -g -fno-stack-protector -fno-pie -no-pie -o $@ $<

test: all
	$(PYTHON) -m unittest discover -s tests -v

clean:
	rm -f $(TARGETS)
