#	$OpenBSD: Makefile,v 1.28 2011/04/18 16:52:10 thib Exp $

TOP=		${.CURDIR}/..

.include "${TOP}/Makefile.inc"
BSD_RD=		bsd.rd
IMAGE=		mr.fs
CBIN?=		instbin
LISTS=		${.CURDIR}/list
UTILS?=		${.CURDIR}/../../miniroot

MOUNT_POINT=	/mnt
MTREE=		${UTILS}/mtree.conf

VND?=		vnd0
VND_DEV=	/dev/${VND}a
VND_RDEV=	/dev/r${VND}a
VND_CRDEV=	/dev/r${VND}c
PID!=		echo $$$$


DISKTYPE=       rdroot
NBLKS=          4096
# minfree, opt, b/i  trks, sects, cpg
NEWFSARGS= -t ffs -m 0 -o space

all:	${BSD_RD}

${BSD_RD}: ${CBIN} ${IMAGE} bsd rdsetroot
	cp bsd ${BSD_RD}
	${.OBJDIR}/rdsetroot ${BSD_RD} ${IMAGE}

${IMAGE}: rd_setup do_files rd_teardown

bsd:
.ifndef(NOBUILD)
	cd ${.CURDIR}/../../../sys/arch/mvme68k/conf && config RAMDISK
	cd ${.CURDIR}/../../../sys/arch/mvme68k/compile/RAMDISK && \
	    ${MAKE} clean && exec ${MAKE}
.endif
	cp ${.CURDIR}/../../../sys/arch/mvme68k/compile/RAMDISK/bsd bsd

rd_test: rd_setup rd_teardown

rd_setup:
	dd if=/dev/zero of=${IMAGE} bs=512 count=${NBLKS}
	vnconfig -v -c ${VND} ${IMAGE}
	disklabel -w ${VND} ${DISKTYPE}
	newfs ${NEWFSARGS} ${VND_RDEV}
	fsck ${VND_RDEV}
	mount ${VND_DEV} ${MOUNT_POINT}

rd_teardown:
	@df -i ${MOUNT_POINT}
	-umount ${MOUNT_POINT}
	-vnconfig -u ${VND}

rdsetroot:	${TOP}/../common/rdsetroot.c
	${HOSTCC} -o rdsetroot ${TOP}/../common/rdsetroot.c

unconfig:
	-umount -f ${MOUNT_POINT}
	-vnconfig -u ${VND}

.PRECIOUS:      ${IMAGE}

.ifdef RELEASEDIR
install:
	cp ${BSD_RD} ${RELEASEDIR}
.endif

${CBIN}.conf: ${LISTS}
	awk -f ${UTILS}/makeconf.awk CBIN=${CBIN} ${LISTS} > ${CBIN}.conf

${CBIN}.mk ${CBIN}.cache ${CBIN}.c: ${CBIN}.conf
	crunchgen -D ${.CURDIR}/../../.. -L ${DESTDIR}/usr/lib ${CBIN}.conf

${CBIN}: ${CBIN}.mk ${CBIN}.cache ${CBIN}.c
	${MAKE} -f ${CBIN}.mk all

do_files:
	mtree -def ${MTREE} -p ${MOUNT_POINT}/ -u
	TOPDIR=${TOP} CURDIR=${.CURDIR} OBJDIR=${.OBJDIR} \
	    REV=${REV} TARGDIR=${MOUNT_POINT} UTILS=${UTILS} \
	    RELEASEDIR=${RELEASEDIR} sh ${UTILS}/runlist.sh ${LISTS}
	rm ${MOUNT_POINT}/${CBIN}

clean cleandir:
	/bin/rm -f core ${IMAGE} ${CBIN} ${CBIN}.conf ${CBIN}.mk ${CBIN}.cache \
	    *.o *.lo *.c bsd ${BSD_RD} rdsetroot

.include <bsd.obj.mk>
.include <bsd.subdir.mk>
