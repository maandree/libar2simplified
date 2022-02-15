.POSIX:

CONFIGFILE = config.mk
include $(CONFIGFILE)

OS = linux
# Linux:   linux
# Mac OS:  macos
# Windows: windows
include mk/$(OS).mk


LIB_MAJOR = 1
LIB_MINOR = 0
LIB_VERSION = $(LIB_MAJOR).$(LIB_MINOR)
LIB_NAME = ar2simplified


OBJ =\
	libar2simplified_crypt.o\
	libar2simplified_decode.o\
	libar2simplified_encode.o\
	libar2simplified_encode_hash.o\
	libar2simplified_hash.o\
	libar2simplified_init_context.o\
	libar2simplified_recommendation.o

HDR =\
	libar2simplified.h\
	common.h

LOBJ = $(OBJ:.o=.lo)
MAN3 = $(OBJ:.o=.3)
MAN7 = libar2simplified.7


all: libar2simplified.a libar2simplified.$(LIBEXT) test
$(OBJ): $(HDR)
$(LOBJ): $(HDR)
test.o: test.c $(HDR)

.c.o:
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

.c.lo:
	$(CC) -fPIC -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

test: test.o libar2simplified.a
	$(CC) -o $@ test.o libar2simplified.a $(LDFLAGS)

libar2simplified.a: $(OBJ)
	@rm -f -- $@
	$(AR) rc $@ $(OBJ)

libar2simplified.$(LIBEXT): $(LOBJ)
	$(CC) $(LIBFLAGS) -o $@ $(LOBJ) $(LDFLAGS)

check: test
	./test

install: libar2simplified.a libar2simplified.$(LIBEXT)
	mkdir -p -- "$(DESTDIR)$(PREFIX)/lib"
	mkdir -p -- "$(DESTDIR)$(PREFIX)/include"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man3"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man7"
	cp -- libar2simplified.a "$(DESTDIR)$(PREFIX)/lib/"
	cp -- libar2simplified.$(LIBEXT) "$(DESTDIR)$(PREFIX)/lib/libar2simplified.$(LIBMINOREXT)"
	ln -sf -- libar2simplified.$(LIBMINOREXT) "$(DESTDIR)$(PREFIX)/lib/libar2simplified.$(LIBMAJOREXT)"
	ln -sf -- libar2simplified.$(LIBMAJOREXT) "$(DESTDIR)$(PREFIX)/lib/libar2simplified.$(LIBEXT)"
	cp -- libar2simplified.h "$(DESTDIR)$(PREFIX)/include/"
	cp -- $(MAN3) "$(DESTDIR)$(MANPREFIX)/man3/"
	cp -- $(MAN7) "$(DESTDIR)$(MANPREFIX)/man7/"

uninstall:
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libar2simplified.a"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libar2simplified.$(LIBMAJOREXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libar2simplified.$(LIBMINOREXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libar2simplified.$(LIBEXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/include/libar2simplified.h"
	-cd -- "$(DESTDIR)$(MANPREFIX)/man3/" && rm -f -- $(MAN3)
	-cd -- "$(DESTDIR)$(MANPREFIX)/man7/" && rm -f -- $(MAN7)

clean:
	-rm -f -- *.o *.a *.lo *.su *.so *.so.* *.dll *.dylib
	-rm -f -- *.gch *.gcov *.gcno *.gcda *.$(LIBEXT) test

.SUFFIXES:
.SUFFIXES: .lo .o .c

.PHONY: all check install uninstall clean
