.PHONY: all all-i386 test test-i386 clean

PYTHON ?= python3

NATIVE_TARGETS = examples/simple_crackme examples/hash_crackme \
	examples/stream_crackme examples/if_crackme \
	examples/mambo_race_planner

I386_TARGETS = examples/simple_crackme_i386 examples/hash_crackme_i386 \
	examples/stream_crackme_i386 examples/if_crackme_i386 \
	examples/mambo_race_planner_i386

all: $(NATIVE_TARGETS)

all-i386: $(I386_TARGETS)

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

examples/if_crackme: examples/if_crackme.c
	$(CC) -O0 -g -fno-stack-protector -fno-pie -no-pie -o $@ $<

examples/if_crackme_i386: examples/if_crackme.c
	$(CC) -m32 -O0 -g -fno-stack-protector -fno-pie -no-pie -o $@ $<

examples/mambo_race_planner: examples/mambo_race_planner.c
	$(CC) -O0 -g -fno-stack-protector -fno-pie -no-pie -o $@ $<

examples/mambo_race_planner_i386: examples/mambo_race_planner.c
	$(CC) -m32 -O0 -g -fno-stack-protector -fno-pie -no-pie -o $@ $<

test: all
	$(PYTHON) -m unittest discover -s tests -v

test-i386: all all-i386
	MAMBO_TEST_I386=1 $(PYTHON) -m unittest discover -s tests -v

clean:
	rm -f $(NATIVE_TARGETS) $(I386_TARGETS)
