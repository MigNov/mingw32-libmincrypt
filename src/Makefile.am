LIBNAME=mincrypt
SOURCES=mincrypt.c base64.c crc32.c byteops.c asymmetric.c mincrypt.h

EXTRA_DIST = mincrypt-tui.c mincrypt.c base64.c crc32.c byteops.c asymmetric.c mincrypt.h

all: compile-windows del-temp

compile-windows:
	$(MINGW32) -Wall -o $(LIBNAME).dll -mdll $(SOURCES) -DBUILDING_DLL -Wl,--out-implib,lib$(LIBNAME).a -DWINDOWS -DHAVE_CONFIG_H
	$(MINGW32) -o $(LIBNAME).exe mincrypt-tui.c -l$(LIBNAME) -DWINDOWS -L.

install-exec-local:
	cp -f mincrypt.dll $(DESTDIR)$(libdir)
	cp -f libmincrypt.a $(DESTDIR)$(libdir)
	cp -f mincrypt.exe $(DESTDIR)$(bindir)
	cp -f mincrypt.h $(DESTDIR)$(includedir)

del-temp:
	rm -f *.o

clean-local: del-temp
	rm -f *.a  *.o
