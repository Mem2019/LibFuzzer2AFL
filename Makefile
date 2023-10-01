REPO_DIR ?= $(shell pwd)
CFLAGS ?= -O2 -Wall -g

all: compiler

afl.o: afl.c
	$(CC) $(CFLAGS) -fPIC -c afl.c

common_interface_defs.o: common_interface_defs.c
	$(CC) $(CFLAGS) -fPIC -c common_interface_defs.c

compiler: compiler.c afl.o common_interface_defs.o libfuzzer-mutator.a
	$(CC) $(CFLAGS) -DLIBFUZZER2AFL_PATH="\"${REPO_DIR}\"" compiler.c -o compiler
	rm -f compiler++ && ln -s compiler compiler++

libfuzzer-mutator.a: LibFuzzerMakefile
	make -C AFLplusplus/custom_mutators/libfuzzer/ -f ../../../LibFuzzerMakefile clean all
	mv AFLplusplus/custom_mutators/libfuzzer/libfuzzer-mutator.a libfuzzer-mutator.a
	make -C AFLplusplus/custom_mutators/libfuzzer/ -f ../../../LibFuzzerMakefile clean

test: compiler test.c
	./compiler -g -O1 -fsanitize=fuzzer test.c -o test
	./compiler -g -O1 -fsanitize=fuzzer -DNO_CUSTOM_MUTATOR=1 test.c -o test_cross_over
	./compiler -g -O1 -fsanitize=fuzzer -DNO_CUSTOM_CROSS_OVER=1 test.c -o test_mutator
	cd AFLplusplus && make && make -C utils/aflpp_driver
	AFLplusplus/afl-cc -g -O1 -fsanitize=fuzzer test.c -o test_afl
	mkdir -p in && echo AAAA > in/seed
	@echo "Run the following commands to test:"
	@echo "export AFL_CUSTOM_MUTATOR_ONLY=1"
	@echo "export AFL_CUSTOM_MUTATOR_LIBRARY=./test # or test_cross_over, or test_mutator"
	@echo "export AFL_DISABLE_TRIM=1"
	@echo "export AFL_SKIP_CPUFREQ=1"
	@echo "AFLplusplus/afl-fuzz -i in/ -o out/ ./test_afl"

clean:
	rm -rf afl.o common_interface_defs.o compiler compiler++ test test_cross_over test_mutator test_afl in/ out/ libfuzzer-mutator.a