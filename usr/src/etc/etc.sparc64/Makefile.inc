#	$OpenBSD: Makefile.inc,v 1.10 2011/04/15 03:11:38 deraadt Exp $

kernels: bsd bsd.mp bootblocks
	cp ${.CURDIR}/../sys/arch/sparc64/compile/GENERIC/bsd \
	    ${RELEASEDIR}/bsd
	cp ${.CURDIR}/../sys/arch/sparc64/compile/GENERIC.MP/bsd \
	    ${RELEASEDIR}/bsd.mp

bsd:
	cd ${.CURDIR}/../sys/arch/sparc64/conf && config GENERIC
	cd ${.CURDIR}/../sys/arch/sparc64/compile/GENERIC && \
	    ${MAKE} clean && exec ${MAKE}

bsd.mp:
	cd ${.CURDIR}/../sys/arch/sparc64/conf && config GENERIC.MP
	cd ${.CURDIR}/../sys/arch/sparc64/compile/GENERIC.MP && \
	    ${MAKE} clean && ${MAKE} depend && exec ${MAKE}

bootblocks:
	cp ${DESTDIR}/usr/mdec/*boot* ${RELEASEDIR}

MDEXT=	bsd bsd.mp bsd.rd cd${OSrev}.iso \
	miniroot${OSrev}.fs floppy${OSrev}.fs floppyB${OSrev}.fs \
	bootblk installboot ofwboot ofwboot.net

.PHONY: bsd bsd.mp bootblocks
