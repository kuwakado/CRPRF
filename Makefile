# Released under the MIT License
# https://opensource.org/license/mit
# Copyright 2025  Hidenori Kuwakado

CC=/usr/bin/gcc
#CC=/usr/bin/clang
CFLAGS=-std=c17 -pedantic -pedantic-errors \
-Wall -Wextra -Werror=pedantic \
-march=native -msha \
-O2 -DNDEBUG
#-O0
#-O2 -DNDEBUG
#-O2
#-O3 -DNDEBUG
#-Wno-unused-variable
#-Wno-unused-const-variable
#-Wno-unused-function
#-Wno-unused-parameter
#-Wno-pointer-to-int-cast


INCFLAGS=
LDFLAGS=
# Use OpenSSL library of the system.
LDLIBS=-lcrypto

sources=$(wildcard *.c)
objects=$(subst .c,.o,$(sources))
mocObjects=$(subst .c,_moc.o,$(sources))
headers=$(wildcard *.h)
deps=$(headers) Makefile
goal=crprf

benchmark_dir=Benchmark
check_dir=Checks
object_dir=Objs

benchmarkFileBaseName=$(benchmark_dir)/benchmark-$(hostName)-$@-$(now)
date=/usr/bin/date
echo=/usr/bin/echo
head=/usr/bin/head
hostName=$(shell /usr/bin/hostname -s)
makefile=Makefile
mkdir=/usr/bin/mkdir
now:=$(shell $(date) +%y%m%d-%H%M%S)
tail=/usr/bin/tail
tee=/usr/bin/tee
time=/usr/bin/time
timeOptions=--output=$(benchmarkFileBaseName).txt --verbose
tr=/usr/bin/tr

###
.PHONY: all
all: $(goal) $(goal)_moc $(goal)_moc_sha256cf

$(goal): $(addprefix $(object_dir)/,$(objects))
	@$(MAKE) --file=$(makefile) --no-print-directory mkdir
	$(CC) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(goal)_moc: $(addprefix $(object_dir)/,$(mocObjects))
	@$(MAKE) --file=$(makefile) --no-print-directory mkdir
	$(CC) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(goal)_moc_sha256cf: $(object_dir)/sha256cf_moc.o \
$(object_dir)/crprfBenchmark.o $(object_dir)/hmac.o $(object_dir)/khc1.o \
$(object_dir)/khc2.o $(object_dir)/main.o  $(object_dir)/sha256.o
	@$(MAKE) --file=$(makefile) --no-print-directory mkdir
	$(CC) $^ -o $@ $(LDFLAGS) $(LDLIBS)


$(object_dir)/%.o: %.c $(deps)
	@$(MAKE) --file=$(makefile) --no-print-directory mkdir
	$(CC) $< -o $@ -c $(CFLAGS) $(INCFLAGS)

$(object_dir)/%_moc.o: %.c $(deps)
	@$(MAKE) --file=$(makefile) --no-print-directory mkdir
	$(CC) $< -o $@ -c \
	-DSHA256CF_MOC -DSHA256_MOC -DHMAC_MOC -DKHC1_MOC -DKHC2_MOC \
	$(CFLAGS) $(INCFLAGS)


.PHONY: clean
clean:
	-$(RM) --recursive $(goal) $(goal)_moc $(goal)_moc_sha256cf \
	$(check_dir) $(object_dir) $(benchmark_dir)/bench_* .*.touch
	cd AuxiliaryPrograms && \
	$(MAKE) --file=Makefile --no-print-directory clean

###
.PHONY: mkdir
mkdir:
	@if [ ! -d ./$(benchmark_dir) ]; then $(mkdir) $(benchmark_dir); fi
	@if [ ! -d ./$(check_dir) ]; then $(mkdir) $(check_dir); fi
	@if [ ! -d ./$(object_dir) ]; then $(mkdir) $(object_dir); fi


###
.PHONY: benchmark full full_moc full_long full_moc_long full_moc_sha256cf
benchmark: full full_moc full_long full_moc_long full_moc_sha256cf

full: $(goal)
	@$(MAKE) --file=$(makefile) --no-print-directory mkdir
	@$(date) >> $(benchmarkFileBaseName)-time.txt
	./$< \
	--maxMessageByteLength=$(shell expr 32 \* 64) \
	--repeatCount=$(shell expr 32 \* 1024 \* 1024 + 1) \
	--stepByte=32 \
	> $(benchmarkFileBaseName).csv 2> $(benchmarkFileBaseName)-err.txt
	@$(date) >> $(benchmarkFileBaseName)-time.txt

full_long: $(goal)
	@$(MAKE) --file=$(makefile) --no-print-directory mkdir
	@$(date) >> $(benchmarkFileBaseName)-time.txt
# 384*64=24576=24*1024, (24*1024)/192=128
	./$< \
	--maxMessageByteLength=$(shell expr 384 \* 64) \
	--repeatCount=$(shell expr 32 \* 1024 \* 1024 + 1) \
	--stepByte=192 \
	> $(benchmarkFileBaseName).csv 2> $(benchmarkFileBaseName)-err.txt 
	@$(date) >> $(benchmarkFileBaseName)-time.txt

full_moc: $(goal)_moc
	@$(MAKE) --file=$(makefile) --no-print-directory mkdir
	@$(date) >> $(benchmarkFileBaseName)-time.txt
	./$< \
	--maxMessageByteLength=$(shell expr 32 \* 64) \
	--repeatCount=$(shell expr 32 \* 1024 \* 1024 + 1) \
	--stepByte=32 \
	> $(benchmarkFileBaseName).csv 2> $(benchmarkFileBaseName)-err.txt
	@$(date) >> $(benchmarkFileBaseName)-time.txt

full_moc_sha256cf: $(goal)_moc_sha256cf
	@$(MAKE) --file=$(makefile) --no-print-directory mkdir
	@$(date) >> $(benchmarkFileBaseName)-time.txt
	./$< \
	--maxMessageByteLength=$(shell expr 32 \* 64) \
	--repeatCount=$(shell expr 32 \* 1024 \* 1024 + 1) \
	--stepByte=32 \
	> $(benchmarkFileBaseName).csv 2> $(benchmarkFileBaseName)-err.txt
	@$(date) >> $(benchmarkFileBaseName)-time.txt

full_moc_long: $(goal)_moc
	@$(MAKE) --file=$(makefile) --no-print-directory mkdir
	@$(date) >> $(benchmarkFileBaseName)-time.txt
# 384*64=24576=24*1024, (24*1024)/192=128
	./$< \
	--maxMessageByteLength=$(shell expr 384 \* 64) \
	--repeatCount=$(shell expr 32 \* 1024 \* 1024 + 1) \
	--stepByte=192 \
	> $(benchmarkFileBaseName).csv 2> $(benchmarkFileBaseName)-err.txt
	@$(date) >> $(benchmarkFileBaseName)-time.txt


###
.PHONY: check check_sha256cf check_sha256 check_hmac check_khc1 check_khc2
check: check_sha256cf check_sha256 check_hmac check_khc1 check_khc2

check_sha256cf: sha256cf.c
	@$(MAKE) --file=$(makefile) --no-print-directory mkdir
	@$(CC) sha256cf.c -o $(check_dir)/$@ \
	-D$(shell $(echo) $@ | $(tr) [a-z] [A-Z]) \
	$(CFLAGS) $(INCFLAGS) $(LDFLAGS) $(LDLIBS)
	@./$(check_dir)/$@

check_sha256: sha256.c
	@$(MAKE) --file=$(makefile) --no-print-directory mkdir
	@$(CC) sha256cf.c -o $(object_dir)/sha256cf.o -c $(CFLAGS) $(INCFLAGS)
	@$(CC) $< $(object_dir)/sha256cf.o -o $(check_dir)/$@ \
	-D$(shell $(echo) $@ | $(tr) [a-z] [A-Z]) \
	$(CFLAGS) $(INCFLAGS) $(LDFLAGS) $(LDLIBS)
	@./$(check_dir)/$@

check_hmac: hmac.c
	@$(MAKE) --file=$(makefile) --no-print-directory mkdir
	@$(CC) sha256cf.c -o $(object_dir)/sha256cf.o -c $(CFLAGS) $(INCFLAGS)
	@$(CC) sha256.c -o $(object_dir)/sha256.o -c $(CFLAGS) $(INCFLAGS)
	@$(CC) $< $(object_dir)/sha256.o $(object_dir)/sha256cf.o -o $(check_dir)/$@ \
	-D$(shell $(echo) $@ | $(tr) [a-z] [A-Z]) \
	$(CFLAGS) $(INCFLAGS) $(LDFLAGS) $(LDLIBS)
	@./$(check_dir)/$@

check_khc1: khc1.c
	@$(MAKE) --file=$(makefile) --no-print-directory mkdir
	@$(CC) sha256cf.c -o $(object_dir)/sha256cf.o -c $(CFLAGS) $(INCFLAGS)
	@$(CC) $< $(object_dir)/sha256cf.o -o $(check_dir)/$@ \
	-D$(shell $(echo) $@ | $(tr) [a-z] [A-Z]) \
	$(CFLAGS) $(INCFLAGS) $(LDFLAGS) $(LDLIBS)
	@./$(check_dir)/$@

check_khc2: khc2.c
	@$(MAKE) --file=$(makefile) --no-print-directory mkdir
	@$(CC) sha256cf.c -o $(object_dir)/sha256cf.o -c $(CFLAGS) $(INCFLAGS)
	@$(CC) $< $(object_dir)/sha256cf.o -o $(check_dir)/$@ \
	-D$(shell $(echo) $@ | $(tr) [a-z] [A-Z]) \
	$(CFLAGS) $(INCFLAGS) $(LDFLAGS) $(LDLIBS)
	@./$(check_dir)/$@


###
.PHONY: bench bench_sha256cf bench_sha256 bench_hmac bench_khc1 bench_khc2
bench: bench_sha256cf bench_sha256 bench_hmac bench_khc1 bench_khc2

bench_sha256cf: sha256cf.c
	@$(MAKE) --file=$(makefile) --no-print-directory mkdir
	@$(CC) $< -o $(benchmark_dir)/$@ \
	-D$(shell $(echo) $@ | $(tr) [a-z] [A-Z]) \
	$(CFLAGS) $(INCFLAGS) $(LDFLAGS) $(LDLIBS)
	@$(date)
	$(time) $(timeOptions) ./$(benchmark_dir)/$@ 2>&1 | $(tee) $(benchmarkFileBaseName).csv
	@$(date)
	@$(head) --lines=4 $(benchmarkFileBaseName).txt

bench_sha256: sha256.c
	@$(MAKE) --file=$(makefile) --no-print-directory mkdir
	@$(CC) sha256cf.c -o $(object_dir)/sha256cf.o -c $(CFLAGS) $(INCFLAGS)
	@$(CC) $< $(object_dir)/sha256cf.o -o $(benchmark_dir)/$@ \
	-D$(shell $(echo) $@ | $(tr) [a-z] [A-Z]) \
	$(CFLAGS) $(INCFLAGS) $(LDFLAGS) $(LDLIBS)
	@$(date)
	$(time) $(timeOptions) ./$(benchmark_dir)/$@ > $(benchmarkFileBaseName).csv 2>&1
	@$(date)
	@$(head) --lines=5 $(benchmarkFileBaseName).csv
	@$(tail) --lines=5 $(benchmarkFileBaseName).csv
	@$(head) --lines=4 $(benchmarkFileBaseName).txt

bench_hmac: hmac.c
	@$(MAKE) --file=$(makefile) --no-print-directory mkdir
	@$(CC) sha256cf.c -o $(object_dir)/sha256cf.o -c $(CFLAGS) $(INCFLAGS)
	@$(CC) sha256.c -o $(object_dir)/sha256.o -c $(CFLAGS) $(INCFLAGS)
	@$(CC) $< $(object_dir)/sha256.o $(object_dir)/sha256cf.o -o $(benchmark_dir)/$@ \
	-D$(shell $(echo) $@ | $(tr) [a-z] [A-Z]) \
	$(CFLAGS) $(INCFLAGS) $(LDFLAGS) $(LDLIBS)
	@$(date)
	$(time) $(timeOptions) ./$(benchmark_dir)/$@ > $(benchmarkFileBaseName).csv 2>&1
	@$(date)
	@$(head) --lines=5 $(benchmarkFileBaseName).csv
	@$(tail) --lines=5 $(benchmarkFileBaseName).csv
	@$(head) --lines=4 $(benchmarkFileBaseName).txt

bench_khc1: khc1.c
	@$(MAKE) --file=$(makefile) --no-print-directory mkdir
	@$(CC) sha256cf.c -o $(object_dir)/sha256cf.o -c $(CFLAGS) $(INCFLAGS)
	@$(CC) $< $(object_dir)/sha256cf.o -o $(benchmark_dir)/$@ \
	-D$(shell $(echo) $@ | $(tr) [a-z] [A-Z]) \
	$(CFLAGS) $(INCFLAGS) $(LDFLAGS) $(LDLIBS)
	@$(date)
	$(time) $(timeOptions) ./$(benchmark_dir)/$@ > $(benchmarkFileBaseName).csv 2>&1
	@$(date)
	@$(head) --lines=5 $(benchmarkFileBaseName).csv
	@$(tail) --lines=5 $(benchmarkFileBaseName).csv
	@$(head) --lines=4 $(benchmarkFileBaseName).txt

bench_khc2: khc2.c
	@$(MAKE) --file=$(makefile) --no-print-directory mkdir
	@$(CC) sha256cf.c -o $(object_dir)/sha256cf.o -c $(CFLAGS) $(INCFLAGS)
	@$(CC) $< $(object_dir)/sha256cf.o -o $(benchmark_dir)/$@ \
	-D$(shell $(echo) $@ | $(tr) [a-z] [A-Z]) \
	$(CFLAGS) $(INCFLAGS) $(LDFLAGS) $(LDLIBS)
	@$(date)
	$(time) $(timeOptions) ./$(benchmark_dir)/$@ > $(benchmarkFileBaseName).csv 2>&1
	@$(date)
	@$(head) --lines=5 $(benchmarkFileBaseName).csv
	@$(tail) --lines=5 $(benchmarkFileBaseName).csv
	@$(head) --lines=4 $(benchmarkFileBaseName).txt


###
indent=/usr/bin/indent
indentOptions=--k-and-r-style \
--no-tabs \
-T __m128i \
-T __m256i \
-T bool \
-T Sha256Context \
-T uint16_t \
-T uint32_t \
-T uint64_t \
-T uint8_t
touch=/usr/bin/touch

.PHONY: indent
indent: .indent.touch
.indent.touch: $(sources) $(headers)
	$(CC) -fsyntax-only $(CFLAGS) $?
	$(indent) $(indentOptions) $?
	@$(indent) $(indentOptions) $?
	@$(indent) $(indentOptions) $?
	@$(RM) $(subst .c,.c~, $(sources)) $(subst .h,.h~, $(headers))
	@$(touch) $@


###
xargs=/usr/bin/xargs
xargsOptions=--delimiter=" " --replace=$(targetFile)
targetFile=foo
sed=/usr/bin/sed
sedOptions=--in-place

.PHONY: trim
trim: .trim.touch
.trim.touch: $(sources) $(headers) Makefile
	$(echo) -n $? \
	| $(xargs) $(xargsOptions) \
	$(sed) $(sedOptions) 's/\s*$$//' $(targetFile)
	@$(touch) $@


###
cproto=/usr/bin/cproto

.PHONY: proto
proto: $(sources)
	$(echo) -n $^ | $(xargs) $(xargsOptions) $(cproto) $(targetFile)


###
.PHONY: predefined gcc make
predefined: gcc make
gcc:
	$(CC) -dM -xc -E /dev/null
make:
	$(MAKE) --print-data-base --file=/dev/null

# end of file
