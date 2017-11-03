#	$OpenBSD: 

.PATH:		${.CURDIR}/../ifconfigd

PROG=		ifconfigctl
MAN=		ifconfigctl.8
SRCS=		ifconfigctl.c 

LDADD=		-levent -lutil
DPADD=		${LIBEVENT} ${LIBCRYPTO} ${LIBZ} ${LIBUTIL}
CFLAGS+=	-I${.CURDIR}/../ifconfigd
CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare -g

.include <bsd.prog.mk>
