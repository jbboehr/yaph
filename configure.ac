
m4_include(m4/ax_pthread.m4)

AC_PREREQ(2.61)
AC_INIT([yaph], [0.0.0], [jbboehr@gmail.com], [yaph] [])

AC_CONFIG_AUX_DIR([build])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([yaph])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign -Wall -Werror subdir-objects])

# AC_CANONICAL_SYSTEM
# AC_ARG_PROGRAM
AX_PTHREAD

AC_CONFIG_FILES([
  Makefile
  yaph/Makefile
])
AC_OUTPUT
