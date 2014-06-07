#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
# vim: set sw=4 ts=4 sts=4 et:

AC_INIT([fastalg-protocol], [0.1], [BUG-REPORT-ADDRESS])
AC_CONFIG_SRCDIR([falgproto/falgproto.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC
LT_INIT

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T

AC_CONFIG_FILES([Makefile falgproto/falgproto-0.1.pc])
AC_OUTPUT
