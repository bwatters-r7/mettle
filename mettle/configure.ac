AC_INIT([mettle], m4_esyscmd([tr -d '\n' < VERSION]))

AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AC_PROG_CC_STDC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL
LT_INIT

CFLAGS="$CFLAGS -Wall -std=gnu99"

case $host_os in
	*linux*)
		CPPFLAGS="$CPPFLAGS -D_DEFAULT_SOURCE -D_GNU_SOURCE -D_XOPEN_SOURCE=700"
		;;
esac

AC_CHECK_FUNCS([reallocarray strlcat strlcpy strtonum])

AM_CONDITIONAL([HAVE_REALLOCARRAY], [test "x$ac_cv_func_reallocarray" = xyes])
AM_CONDITIONAL([HAVE_STRLCAT], [test "x$ac_cv_func_strlcat" = xyes])
AM_CONDITIONAL([HAVE_STRLCPY], [test "x$ac_cv_func_strlcpy" = xyes])
AM_CONDITIONAL([HAVE_STRTONUM], [test "x$ac_cv_func_strtonum" = xyes])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])

AC_OUTPUT
