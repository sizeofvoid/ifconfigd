
.PATH:		${.CURDIR}/../../sbin/ifconfig ${.CURDIR}/../../sbin/bioctl
	
PROG=		ifconfigd
SRCS=		 brconfig.c pbkdf2.c ifcutil.c parse.y log.c control.c ifconfigd.c ifconfigde.c

LDADD+=		-levent -lutil 

MAN=		ifconfigd.8 ifconfigd.conf.5	
 
CFLAGS+=  -I${.CURDIR}/../../sbin/bioctl -I${.CURDIR}/../../sbin/ifconfig 
#CFLAGS+= 	-DINET6 -I${.CURDIR}
#CFLAGS+= 	-Wstrict-prototypes -Wmissing-prototypes
#CFLAGS+= 	-Wmissing-declarations
#CFLAGS+= 	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= 	-g 
#-Wsign-compare

YFLAGS=		-t -v
CLEANFILES+=	y.tab.h *.o y.output ifconfigd.conf.cat5 ifconfigd.cat8

.include <bsd.prog.mk>
