#	$OpenBSD: Makefile.inc,v 1.11 2009/04/21 09:34:50 martynas Exp $

SRCS+=	setjmp.S
SRCS+=	fabs.c
SRCS+=	infinity.c ldexp.c modf.c nan.c setjmp.S
SRCS+=	flt_rounds.c fpgetmask.c fpgetround.c fpgetsticky.c fpsetmask.c \
	fpsetround.c fpsetsticky.c

SRCS+=	alloca.c
