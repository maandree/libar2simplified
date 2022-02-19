LIBEXT      = dylib
LIBFLAGS    = -dynamiclib
LIBMAJOREXT = $(LIB_MAJOR).$(LIBEXT)
LIBMINOREXT = $(LIB_VERSION).$(LIBEXT)

FIX_INSTALL_NAME = install_name_tool -id "$(PREFIX)/lib/libar2simplified.$(LIBMAJOREXT)"
