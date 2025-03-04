CC=/usr/bin/gcc
CFLAGS=-std=c17 -pedantic -pedantic-errors \
-Wall -Wextra -Werror=pedantic \
-march=native \
-O2

sources=sizeof.c mmXor.c estimateFreq.c
deps=Makefile
targets=$(subst .c,,$(sources))

all: $(targets)

.PHONY: clean
clean:
	-$(RM) $(targets) .*.touch


%: %.c $(deps)
	$(CC) $< -o $@ $(CFLAGS)


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
.indent.touch: $(sources)
	$(CC) -fsyntax-only $(CFLAGS) $?
	$(indent) $(indentOptions) $?
	@$(indent) $(indentOptions) $?
	@$(RM) $(subst .c,.c~, $(sources))
	@$(touch) $@

###
echo=/usr/bin/echo
xargs=/usr/bin/xargs
xargsOptions=--delimiter=" " --replace=$(targetFile)
targetFile=foo
sed=/usr/bin/sed
sedOptions=--in-place

.PHONY: trim
trim: .trim.touch
.trim.touch: $(sources) Makefile
	$(echo) -n $? \
	| $(xargs) $(xargsOptions) \
	$(sed) $(sedOptions) 's/\s*$$//' $(targetFile)
	@$(touch) $@

###
# gcc -E -v -
iwyu=/usr/bin/iwyu
.PHONY: include
include: .include.touch
.include.touch: $(sources)
	$(echo) -n $? \
	| $(xargs) $(xargsOptions) \
	$(iwyu) \
	-I/usr/lib/gcc/x86_64-linux-gnu/11/include \
	-I/usr/local/include \
	-I/usr/include/x86_64-linux-gnu \
	-I/usr/include \
	$(targetFile)




# end of file

