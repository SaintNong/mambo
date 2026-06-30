.PHONY: all test clean

PYTHON ?= python3

all: examples/simple_crackme examples/hash_crackme

examples/simple_crackme: examples/simple_crackme.c
	$(CC) -O0 -g -fno-stack-protector -fno-pie -no-pie -o $@ $<

examples/hash_crackme: examples/hash_crackme.c
	$(CC) -O0 -g -fno-stack-protector -fno-pie -no-pie -o $@ $<

test: all
	$(PYTHON) -m unittest discover -s tests -v

clean:
	rm -f examples/simple_crackme examples/hash_crackme
