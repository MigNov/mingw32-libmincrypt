AC_INIT([mingw32-libmincrypt], [0.0.5], [mignov@gmail.com])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Werror])
AM_INIT_AUTOMAKE([-Wno-portability])

AC_PROG_CC
AM_PROG_CC_C_O
AC_CHECK_LIB([m], [pow], [], AC_MSG_ERROR([You need libm to compile this utility]))
AC_CHECK_TOOL([MKDIR], [mkdir])
AC_CHECK_TOOL([ECHO], [echo])
AC_CHECK_TOOL([RM], [rm])
AC_CHECK_TOOL([CP], [cp])
AC_CHECK_TOOL([MINGW32], [i686-pc-mingw32-gcc])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile])
AC_OUTPUT
