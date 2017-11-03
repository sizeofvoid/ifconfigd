/*	$OpenBSD: ifconfig.c,v 1.246 2011/03/23 18:36:41 jsg Exp $	*/
/*	$NetBSD: ifconfig.c,v 1.40 1997/10/01 02:19:43 enami Exp $	*/

/*
 * Copyright (c) 1983, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*-
 * Copyright (c) 1997, 1998, 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>
#include <netinet/ip_ipsp.h>
#include <netinet/if_ether.h>
#include <net/if_enc.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <net/pfvar.h>
#include <net/if_pfsync.h>
#include <net/if_pflow.h>
#include <net/if_pppoe.h>
#include <net/if_trunk.h>
#include <net/if_sppp.h>
#include <net/ppp_defs.h>

#include <netatalk/at.h>

#include <netinet/ip_carp.h>

#include <netdb.h>

#include <net/if_vlan_var.h>

#include <netmpls/mpls.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>

#include "ifcutil.h"

int ifaliases;
int aflag;
int	newaddr;
int	explicit_prefix;
int	Lflag;
int	af;

/* Known address families */
afswtch afs[];

cmd cmds[] = {
	{ "up",		IFF_UP,		0,		setifflags } ,
	{ "down",	-IFF_UP,	0,		setifflags },
	{ "arp",	-IFF_NOARP,	0,		setifflags },
	{ "-arp",	IFF_NOARP,	0,		setifflags },
	{ "debug",	IFF_DEBUG,	0,		setifflags },
	{ "-debug",	-IFF_DEBUG,	0,		setifflags },
	{ "alias",	IFF_UP,		0,		notealias },
	{ "-alias",	-IFF_UP,	0,		notealias },
	{ "delete",	-IFF_UP,	0,		notealias },
#ifdef notdef
#define	EN_SWABIPS	0x1000
	{ "swabips",	EN_SWABIPS,	0,		setifflags },
	{ "-swabips",	-EN_SWABIPS,	0,		setifflags },
#endif /* notdef */
	{ "netmask",	NEXTARG,	0,		setifnetmask },
	{ "mtu",	NEXTARG,	0,		setifmtu },
	{ "nwid",	NEXTARG,	0,		setifnwid },
	{ "-nwid",	-1,		0,		setifnwid },
	{ "bssid",	NEXTARG,	0,		setifbssid },
	{ "-bssid",	-1,		0,		setifbssid },
	{ "nwkey",	NEXTARG,	0,		setifnwkey },
	{ "-nwkey",	-1,		0,		setifnwkey },
	{ "wpa",	1,		0,		setifwpa },
	{ "-wpa",	0,		0,		setifwpa },
	{ "wpaakms",	NEXTARG,	0,		setifwpaakms },
	{ "wpaciphers",	NEXTARG,	0,		setifwpaciphers },
	{ "wpagroupcipher", NEXTARG,	0,		setifwpagroupcipher },
	{ "wpaprotos",	NEXTARG,	0,		setifwpaprotos },
	{ "wpakey",	NEXTARG,	0,		setifwpakey },
	{ "-wpakey",	-1,		0,		setifwpakey },
/*XXX delete these two after the 4.9 release */
/*XXX*/	{ "wpapsk",     NEXTARG,        0,              setifwpakey },
/*XXX*/	{ "-wpapsk",    -1,             0,              setifwpakey },
	{ "chan",	NEXTARG0,	0,		setifchan },
	{ "-chan",	-1,		0,		setifchan },
	{ "scan",	NEXTARG0,	0,		setifscan },
	{ "broadcast",	NEXTARG,	0,		setifbroadaddr },
	{ "prefixlen",  NEXTARG,	0,		setifprefixlen},
	{ "vlan",	NEXTARG,	0,		setvlantag },
	{ "vlandev",	NEXTARG,	0,		setvlandev },
	{ "-vlandev",	1,		0,		unsetvlandev },
#ifdef INET6
	{ "anycast",	IN6_IFF_ANYCAST,	0,	setia6flags },
	{ "-anycast",	-IN6_IFF_ANYCAST,	0,	setia6flags },
	{ "tentative",	IN6_IFF_TENTATIVE,	0,	setia6flags },
	{ "-tentative",	-IN6_IFF_TENTATIVE,	0,	setia6flags },
	{ "pltime",	NEXTARG,	0,		setia6pltime },
	{ "vltime",	NEXTARG,	0,		setia6vltime },
	{ "eui64",	0,		0,		setia6eui64 },
	{ "autoconfprivacy",	IFXF_INET6_PRIVACY,	0,	setifxflags },
	{ "-autoconfprivacy",	-IFXF_INET6_PRIVACY,	0,	setifxflags },
	{ "keepalive",	NEXTARG2,	0,		NULL, setkeepalive },
	{ "-keepalive",	1,		0,		unsetkeepalive },
#endif /*INET6*/
#ifndef SMALL
	{ "group",	NEXTARG,	0,		setifgroup },
	{ "-group",	NEXTARG,	0,		unsetifgroup },
	{ "trailers",	-1,		0,		notrailers },
	{ "-trailers",	1,		0,		notrailers },
	{ "metric",	NEXTARG,	0,		setifmetric },
	{ "powersave",	NEXTARG0,	0,		setifpowersave },
	{ "-powersave",	-1,		0,		setifpowersave },
	{ "priority",	NEXTARG,	0,		setifpriority },
	{ "rtlabel",	NEXTARG,	0,		setifrtlabel },
	{ "-rtlabel",	-1,		0,		setifrtlabel },
	{ "rdomain",	NEXTARG,	0,		setinstance },
	{ "range",	NEXTARG,	0,		setatrange },
	{ "phase",	NEXTARG,	0,		setatphase },
	{ "mpls",	IFXF_MPLS,	0,		setifxflags },
	{ "-mpls",	-IFXF_MPLS,	0,		setifxflags },
	{ "mplslabel",	NEXTARG,	0,		setmpelabel },
	{ "advbase",	NEXTARG,	0,		setcarp_advbase },
	{ "advskew",	NEXTARG,	0,		setcarp_advskew },
	{ "carppeer",	NEXTARG,	0,		setcarppeer },
	{ "-carppeer",	1,		0,		unsetcarppeer },
	{ "pass",	NEXTARG,	0,		setcarp_passwd },
	{ "vhid",	NEXTARG,	0,		setcarp_vhid },
	{ "vlanprio",	NEXTARG,	0,		setvlanprio },
	{ "state",	NEXTARG,	0,		setcarp_state },
	{ "carpdev",	NEXTARG,	0,		setcarpdev },
	{ "carpnodes",	NEXTARG,	0,		setcarp_nodes },
	{ "balancing",	NEXTARG,	0,		setcarp_balancing },
	{ "-carpdev",	1,		0,		unsetcarpdev },
	{ "syncdev",	NEXTARG,	0,		setpfsync_syncdev },
	{ "-syncdev",	1,		0,		unsetpfsync_syncdev },
	{ "syncif",	NEXTARG,	0,		setpfsync_syncdev },
	{ "-syncif",	1,		0,		unsetpfsync_syncdev },
	{ "syncpeer",	NEXTARG,	0,		setpfsync_syncpeer },
	{ "-syncpeer",	1,		0,		unsetpfsync_syncpeer },
	{ "maxupd",	NEXTARG,	0,		setpfsync_maxupd },
	{ "defer",	1,		0,		setpfsync_defer },
	{ "-defer",	0,		0,		setpfsync_defer },
	/* giftunnel is for backward compat */
	{ "giftunnel",  NEXTARG2,	0,		NULL, settunnel } ,
	{ "tunnel",	NEXTARG2,	0,		NULL, settunnel } ,
	{ "deletetunnel",  0,		0,		deletetunnel } ,
	{ "tunneldomain", NEXTARG,	0,		settunnelinst } ,
	{ "pppoedev",	NEXTARG,	0,		setpppoe_dev },
	{ "pppoesvc",	NEXTARG,	0,		setpppoe_svc },
	{ "-pppoesvc",	1,		0,		setpppoe_svc },
	{ "pppoeac",	NEXTARG,	0,		setpppoe_ac },
	{ "-pppoeac",	1,		0,		setpppoe_ac },
	{ "timeslot",	NEXTARG,	0,		settimeslot },
	{ "txpower",	NEXTARG,	0,		setiftxpower },
	{ "-txpower",	1,		0,		setiftxpower },
	{ "trunkport",	NEXTARG,	0,		settrunkport },
	{ "-trunkport",	NEXTARG,	0,		unsettrunkport },
	{ "trunkproto",	NEXTARG,	0,		settrunkproto },
	{ "authproto",	NEXTARG,	0,		setspppproto },
	{ "authname",	NEXTARG,	0,		setspppname },
	{ "authkey",	NEXTARG,	0,		setspppkey },
	{ "peerproto",	NEXTARG,	0,		setsppppeerproto },
	{ "peername",	NEXTARG,	0,		setsppppeername },
	{ "peerkey",	NEXTARG,	0,		setsppppeerkey },
	{ "peerflag",	NEXTARG,	0,		setsppppeerflag },
	{ "-peerflag",	NEXTARG,	0,		unsetsppppeerflag },
	{ "nwflag",	NEXTARG,	0,		setifnwflag },
	{ "-nwflag",	NEXTARG,	0,		unsetifnwflag },
	{ "flowsrc",	NEXTARG,	0,		setpflow_sender },
	{ "-flowsrc",	1,		0,		unsetpflow_sender },
	{ "flowdst", 	NEXTARG,	0,		setpflow_receiver },
	{ "-flowdst", 1,		0,		unsetpflow_receiver },
	{ "-inet6",	IFXF_NOINET6,	0,		setifxflags } ,
	{ "add",	NEXTARG,	0,		bridge_add },
	{ "del",	NEXTARG,	0,		bridge_delete },
	{ "addspan",	NEXTARG,	0,		bridge_addspan },
	{ "delspan",	NEXTARG, 	0,		bridge_delspan },
	{ "discover",	NEXTARG,	0,		setdiscover },
	{ "-discover",	NEXTARG,	0,		unsetdiscover },
	{ "blocknonip", NEXTARG,	0,		setblocknonip },
	{ "-blocknonip",NEXTARG,	0,		unsetblocknonip },
	{ "learn",	NEXTARG,	0,		setlearn },
	{ "-learn",	NEXTARG,	0,		unsetlearn },
	{ "stp",	NEXTARG,	0,		setstp },
	{ "-stp",	NEXTARG,	0,		unsetstp },
	{ "edge",	NEXTARG,	0,		setedge },
	{ "-edge",	NEXTARG,	0,		unsetedge },
	{ "autoedge",	NEXTARG,	0,		setautoedge },
	{ "-autoedge",	NEXTARG,	0,		unsetautoedge },
	{ "ptp",	NEXTARG,	0,		setptp },
	{ "-ptp",	NEXTARG,	0,		unsetptp },
	{ "autoptp",	NEXTARG,	0,		setautoptp },
	{ "-autoptp",	NEXTARG,	0,		unsetautoptp },
	{ "flush",	0,		0,		bridge_flush },
	{ "flushall",	0,		0,		bridge_flushall },
	{ "static",	NEXTARG2,	0,		NULL, bridge_addaddr },
	{ "deladdr",	NEXTARG,	0,		bridge_deladdr },
	{ "maxaddr",	NEXTARG,	0,		bridge_maxaddr },
	{ "addr",	0,		0,		bridge_addrs },
	{ "hellotime",	NEXTARG,	0,		bridge_hellotime },
	{ "fwddelay",	NEXTARG,	0,		bridge_fwddelay },
	{ "maxage",	NEXTARG,	0,		bridge_maxage },
	{ "proto",	NEXTARG,	0,		bridge_proto },
	{ "ifpriority",	NEXTARG2,	0,		NULL, bridge_ifprio },
	{ "ifcost",	NEXTARG2,	0,		NULL, bridge_ifcost },
	{ "-ifcost",	NEXTARG,	0,		bridge_noifcost },
	{ "timeout",	NEXTARG,	0,		bridge_timeout },
	{ "holdcnt",	NEXTARG,	0,		bridge_holdcnt },
	{ "spanpriority", NEXTARG,	0,		bridge_priority },
	{ "ipdst",	NEXTARG,	0,		setifipdst },
#if 0
	/* XXX `rule` special-cased below */
	{ "rule",	0,		0,		bridge_rule },
#endif
	{ "rules",	NEXTARG,	0,		bridge_rules },
	{ "rulefile",	NEXTARG,	0,		bridge_rulefile },
	{ "flushrule",	NEXTARG,	0,		bridge_flushrule },
	{ "description", NEXTARG,	0,		setifdesc },
	{ "descr",	NEXTARG,	0,		setifdesc },
	{ "-description", 1,		0,		unsetifdesc },
	{ "-descr",	1,		0,		unsetifdesc },
	{ "wol",	IFXF_WOL,	0,		setifxflags },
	{ "-wol",	-IFXF_WOL,	0,		setifxflags },
#else /* SMALL */
	{ "group",	NEXTARG,	0,		setignore },
	{ "powersave",	NEXTARG0,	0,		setignore },
	{ "priority",	NEXTARG,	0,		setignore },
	{ "rtlabel",	NEXTARG,	0,		setignore },
	{ "mpls",	IFXF_MPLS,	0,		setignore },
	{ "vlanprio",	NEXTARG,	0,		setignore },
	{ "txpower",	NEXTARG,	0,		setignore },
	{ "nwflag",	NEXTARG,	0,		setignore },
	{ "rdomain",	NEXTARG,	0,		setignore },
	{ "-inet6",	IFXF_NOINET6,	0,		setignore } ,
	{ "description", NEXTARG,	0,		setignore },
	{ "descr",	NEXTARG,	0,		setignore },
	{ "wol",	IFXF_WOL,	0,		setignore },
	{ "-wol",	-IFXF_WOL,	0,		setignore },
#endif /* SMALL */
#if 0
	/* XXX `create' special-cased below */
	{ "create",	0,		0,		clone_create } ,
#endif
	{ "destroy",	0,		0,		clone_destroy } ,
	{ "link0",	IFF_LINK0,	0,		setifflags } ,
	{ "-link0",	-IFF_LINK0,	0,		setifflags } ,
	{ "link1",	IFF_LINK1,	0,		setifflags } ,
	{ "-link1",	-IFF_LINK1,	0,		setifflags } ,
	{ "link2",	IFF_LINK2,	0,		setifflags } ,
	{ "-link2",	-IFF_LINK2,	0,		setifflags } ,
	{ "media",	NEXTARG0,	A_MEDIA,	setmedia },
	{ "mediaopt",	NEXTARG,	A_MEDIAOPTSET,	setmediaopt },
	{ "-mediaopt",	NEXTARG,	A_MEDIAOPTCLR,	unsetmediaopt },
	{ "mode",	NEXTARG,	A_MEDIAMODE,	setmediamode },
	{ "instance",	NEXTARG,	A_MEDIAINST,	setmediainst },
	{ "inst",	NEXTARG,	A_MEDIAINST,	setmediainst },
	{ "lladdr",	NEXTARG,	0,		setiflladdr },
	{ NULL, /*src*/	0,		0,		setifaddr },
	{ NULL, /*dst*/	0,		0,		setifdstaddr },
	{ NULL, /*illegal*/0,		0,		NULL },
};

/* Print usage, exit(value) if value is non-zero. */
void
usage(int value)
{
	fprintf(stderr,
	    "usage: ifconfig [-AaC] [interface] [address_family] "
	    "[address [dest_address]]\n"
	    "\t\t[parameters]\n");
	exit(value);
}

int
main(int argc, char *argv[])
{
	const struct afswtch *rafp = NULL;
	int create = 0;
#ifndef SMALL
	int Cflag = 0;
	int gflag = 0;
#endif
	int i;
	int noprint = 0;

	/* If no args at all, print all interfaces.  */
	if (argc < 2) {
		aflag = 1;
		printif(NULL, 0);
		exit(0);
	}
	argc--, argv++;
	if (*argv[0] == '-') {
		int nomore = 0;

		for (i = 1; argv[0][i]; i++) {
			switch (argv[0][i]) {
			case 'a':
				aflag = 1;
				nomore = 1;
				break;
			case 'A':
				aflag = 1;
				ifaliases = 1;
				nomore = 1;
				break;
#ifndef SMALL
			case 'g':
				gflag = 1;
				break;
			case 'C':
				Cflag = 1;
				nomore = 1;
				break;
#endif
			default:
				usage(1);
				break;
			}
		}
		if (nomore == 0) {
			argc--, argv++;
			if (argc < 1)
				usage(1);
			if (strlcpy(name, *argv, sizeof(name)) >= IFNAMSIZ)
				errx(1, "interface name '%s' too long", *argv);
		}
	} else if (strlcpy(name, *argv, sizeof(name)) >= IFNAMSIZ)
		errx(1, "interface name '%s' too long", *argv);
	argc--, argv++;
	if (argc > 0) {
		for (afp = rafp = afs; rafp->af_name; rafp++)
			if (strcmp(rafp->af_name, *argv) == 0) {
				afp = rafp;
				argc--;
				argv++;
				break;
			}
		rafp = afp;
		af = ifr.ifr_addr.sa_family = rafp->af_af;
	}
#ifndef SMALL
	if (Cflag) {
		if (argc > 0 || aflag)
			usage(1);
		list_cloners();
		exit(0);
	}
	if (gflag) {
		if (argc == 0)
			printgroupattribs(name);
		else
			setgroupattribs(name, argc, argv);
		exit(0);
	}
#endif
	(void) strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

#ifdef INET6
	/* initialization */
	in6_addreq.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
	in6_addreq.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
#endif /* INET6 */
	/*
	 * NOTE:  We must special-case the `create' command right
	 * here as we would otherwise fail in getinfo().
	 */
	if (argc > 0 && strcmp(argv[0], "create") == 0) {
		clone_create(argv[0], 0);
		argc--, argv++;
		if (argc == 0)
			exit(0);
	}
	if (aflag == 0) {
		create = (argc > 0) && strcmp(argv[0], "destroy") != 0;
		(void)getinfo(&ifr, create);
	}
#ifdef INET6
	if (argc != 0 && af == AF_INET6)
		setifxflags("inet6", -IFXF_NOINET6);
#endif
	while (argc > 0) {
		const struct cmd *p;

		for (p = cmds; p->c_name; p++)
			if (strcmp(*argv, p->c_name) == 0)
				break;
#ifndef SMALL
		if (strcmp(*argv, "rule") == 0) {
			argc--, argv++;
			return bridge_rule(argc, argv, -1);
		}
#endif
		if (p->c_name == 0 && setaddr)
			for (i = setaddr; i > 0; i--) {
				p++;
				if (p->c_func == NULL)
					errx(1, "%s: bad value", *argv);
			}
		if (p->c_func || p->c_func2) {
			if (p->c_parameter == NEXTARG0) {
				const struct cmd *p0;
				int noarg = 1;

				if (argv[1]) {
					for (p0 = cmds; p0->c_name; p0++)
						if (strcmp(argv[1], p0->c_name) == 0) {
							noarg = 0;
							break;
						}
				} else
					noarg = 0;

				if (noarg == 0)
					(*p->c_func)(NULL, 0);
				else
					goto nextarg;
			} else if (p->c_parameter == NEXTARG) {
nextarg:
				if (argv[1] == NULL)
					errx(1, "'%s' requires argument",
					    p->c_name);
				(*p->c_func)(argv[1], 0);
				argc--, argv++;
				actions = actions | A_SILENT | p->c_action;
			} else if (p->c_parameter == NEXTARG2) {
				if ((argv[1] == NULL) ||
				    (argv[2] == NULL))
					errx(1, "'%s' requires 2 arguments",
					    p->c_name);
				(*p->c_func2)(argv[1], argv[2]);
				argc -= 2;
				argv += 2;
				actions = actions | A_SILENT | p->c_action;
			} else {
				(*p->c_func)(*argv, p->c_parameter);
				actions = actions | A_SILENT | p->c_action;
			}
		}
		argc--, argv++;
	}

	if (argc == 0 && actions == 0 && !noprint) {
		printif(ifr.ifr_name, aflag ? ifaliases : 1);
		exit(0);
	}

	/* Process any media commands that may have been issued. */
	process_media_commands();

	if (af == AF_INET6 && explicit_prefix == 0) {
		/*
		 * Aggregatable address architecture defines all prefixes
		 * are 64. So, it is convenient to set prefixlen to 64 if
		 * it is not specified.
		 */
		setifprefixlen("64", 0);
		/* in6_getprefix("64", MASK) if MASK is available here... */
	}

#ifndef SMALL
	if (af == AF_APPLETALK)
		checkatrange((struct sockaddr_at *) &addreq.ifra_addr);
#endif /* SMALL */

	if (clearaddr) {
		(void) strlcpy(rafp->af_ridreq, name, sizeof(ifr.ifr_name));
		if (ioctl(s, rafp->af_difaddr, rafp->af_ridreq) < 0) {
			if (errno == EADDRNOTAVAIL && (doalias >= 0)) {
				/* means no previous address for interface */
			} else
				err(1, "SIOCDIFADDR");
		}
	}
	if (newaddr) {
		(void) strlcpy(rafp->af_addreq, name, sizeof(ifr.ifr_name));
		if (ioctl(s, rafp->af_aifaddr, rafp->af_addreq) < 0)
			err(1, "SIOCAIFADDR");
	}
	exit(0);
}
