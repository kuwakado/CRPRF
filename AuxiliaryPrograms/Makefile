CC=/usr/bin/gcc
CFLAGS=-pedantic -pedantic-errors \
-Wall -Wextra -Werror=pedantic \
-march=native \
-O2
#-DNDEBUG

sources=sizeof.c mmXor.c coreTSC.c
deps=Makefile
targets=$(subst .c,,$(sources))

all: $(targets)

sizeof: sizeof.c $(deps)
	$(CC) $< -o $@ -std=c17 $(CFLAGS)
mmXor: mmXor.c $(deps)
	$(CC) $< -o $@ -std=c17 $(CFLAGS)
coreTSC: coreTSC.c $(deps)
	$(CC) $< -o $@ -std=c99 $(CFLAGS) -lpthread

.PHONY: clean
clean:
	-$(RM) $(targets) .*.touch


###
indent=/usr/bin/indent
indentOptions=--k-and-r-style \
--no-tabs \
-T __m128i \
-T __m256i \
-T bool \
-T Sha256Context \
-T thread_args_t \
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

# end of file

