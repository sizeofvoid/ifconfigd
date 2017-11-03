/*	$OpenBSD:  */

/*
 * Copyright (c) 2011 Rafael Sadowski <rafael@sizeofvoid.org>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/tree.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <pwd.h>

#include "ifconfigd.h"
#include "ifcutil.h"
#include "control.h"

__dead void	 usage(void);

int		check_child(pid_t, const char *);
void	ifconfigd_sig_handler(int, short, void *);
void	ifconfigd_shutdown(void);
void	ifconfigd_dispatch_ifconfige(int, short, void *);
void	main_dispatch_ifconfigde(int, short, void *);

int		ieee80211_scan(const char *, int, char *[], struct ieee80211_nodereq *[]);


struct imsgev			*iev_ifconfigde;
struct ifconfigd_conf	*ifconfigd_conf = NULL;

pid_t	ifconfigde_pid = 0;

int	ifaliases;
int	aflag;
int	newaddr;
int	explicit_prefix;
int	Lflag;
int	af;

cmd cmds[] = {
	{ "up",		IFF_UP,		0,		setifflags },
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

/* __dead is for lint */
__dead void
usage(void)
{
	extern char	*__progname;
	
	fprintf(stderr, "usage: %s [-d] [-f file]\n",
	    __progname);
	exit(1);
}

void
ifconfigd_sig_handler(int sig, short event, void *arg)
{
	struct ifconfigd_conf	*env = arg;

	switch (sig) {
	case SIGTERM:
		log_info("SIGTERM");
		if (check_child(ifconfigde_pid, "socket ifconfigd engine")) {
			ifconfigde_pid = 0;
			ifconfigd_shutdown();
		}
	case SIGINT:
		log_info("SIGINT");
		if (check_child(ifconfigde_pid, "socket ifconfigd engine")) {
			ifconfigde_pid = 0;
			ifconfigd_shutdown();
		}
	case SIGCHLD:
		if (check_child(ifconfigde_pid, "socket ifconfigd engine")) {
			ifconfigde_pid = 0;
			ifconfigd_shutdown();
		}
		break;
	case SIGHUP:
		/* reconfigure */
		/* TODO */
		log_info("reconfigure");
		break;
	default:
		log_warnx("unexpected signal");
	}
}

int
main(int argc, char *argv[])
{
	int		 c;
	int		 debug, verbose;
	int		 pipe_parent2ifconfigd[2];
	char	 *csockpath = IFCONFIGD_SOCKET;
	char	 *conffile = CONF_FILE;

	struct event		 ev_sigint;
	struct event		 ev_sigterm;
	struct event		 ev_sigchld;
	struct event		 ev_sighup;

	debug = 0;
	verbose = 0;

	while ((c = getopt(argc, argv, "vds:f:")) != -1) {
		switch (c) {
		case 'd':
			debug = 1;
			break;
		case 's':
			csockpath = optarg;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
		}
	}

	/* log to stderr until daemonized */
	log_init(debug ? debug : 1);

	argv += optind;
	argc -= optind;

	/* parse config file */
	if ((ifconfigd_conf = parse_config(conffile)) == NULL) {
		exit(1);
	}

	ifconfigd_conf->csock = csockpath;

	/* check for root privileges */
	if (geteuid())
		errx(1, "need root privileges");

	/* check if user exists  */
	if (getpwnam(IFCONFIGD_USER) == NULL)
		errx(1, "unknown user %s", IFCONFIGD_USER);

	if (!debug) {
		/* run ifconfigd background */
		if (daemon(1, 0) == -1)
			err(1, "failed to daemonize");
	}
	
	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC,
				pipe_parent2ifconfigd) != 0)
		fatal("socketpair");

	session_socket_blockmode(pipe_parent2ifconfigd[0], BM_NONBLOCK);
	session_socket_blockmode(pipe_parent2ifconfigd[1], BM_NONBLOCK);

	/* start children */
	ifconfigde_pid = ifconfigde(ifconfigd_conf, pipe_parent2ifconfigd);

	/* show who we are */
	setproctitle("parent");

	event_init();

	/* setup signal handler */
	signal_set(&ev_sigint, SIGINT, ifconfigd_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, ifconfigd_sig_handler, NULL);
	signal_set(&ev_sigchld, SIGCHLD, ifconfigd_sig_handler, NULL);
	signal_set(&ev_sighup, SIGHUP, ifconfigd_sig_handler, NULL);

	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sigchld, NULL);
	signal_add(&ev_sighup, NULL);

	/* setup pipes to children */
	close(pipe_parent2ifconfigd[1]);

	if ((iev_ifconfigde = malloc(sizeof(struct imsgev))) == NULL)
		fatal(NULL);

	imsg_init(&iev_ifconfigde->ibuf, pipe_parent2ifconfigd[0]);
	iev_ifconfigde->handler = main_dispatch_ifconfigde;

	/* setup event handler */
	iev_ifconfigde->events = EV_READ;
	event_set(&iev_ifconfigde->ev, iev_ifconfigde->ibuf.fd,
			iev_ifconfigde->events, iev_ifconfigde->handler, iev_ifconfigde);
	event_add(&iev_ifconfigde->ev, NULL);

	log_info("startup");

	event_dispatch();

	ifconfigd_shutdown();

	/* NOTREACHED */
	return (0);
}

/* imsg handling */
/* ARGSUSED */
void
main_dispatch_ifconfigde(int fd, short event, void *bula)
{
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	struct imsguse use;
	ssize_t			 n;
	int			 shut = 0;

	char	*ifname;
	char	name[MAX_NETWORK_NAME_SIZE];

	ibuf = &iev->ibuf;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1)
			fatal("imsg_read error");
		if (n == 0)	/* connection closed */
			shut = 1;
	}
	if (event & EV_WRITE) {
		if (msgbuf_write(&ibuf->w) == -1)
			fatal("msgbuf_write");
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("imsg_get");

		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_USE_ETHERNET:
			memcpy(&name, imsg.data, sizeof(name));
			log_debug("name %s", name);
			if(use_ethernet(name) == -1)
				log_warnx("could not use %s",name);
		case IMSG_IFCONFIGD_MONITOR:
			monitor();
			break;
		/* Example	
		case IMSG_CTL_IFINFO:
			if (imsg.hdr.len == IMSG_HEADER_SIZE)
				kr_ifinfo(NULL, imsg.hdr.pid);
			else if (imsg.hdr.len == IMSG_HEADER_SIZE + IFNAMSIZ)
				kr_ifinfo(imsg.data, imsg.hdr.pid);
			else
				log_warnx("IFINFO request with wrong len");
			break;
		*/
		default:
			log_debug("main_dispatch_ifconfigde: error handling imsg %d",
			    imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	if (!shut)
		imsg_event_add(iev);
	else {
		/* this pipe is dead, so remove the event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

int
check_child(pid_t pid, const char *pname)
{
	int	status;

	if (waitpid(pid, &status, WNOHANG) > 0) {
		if (WIFEXITED(status)) {
			log_warnx("check_child: lost child: %s exited", pname);
			return (1);
		}
		if (WIFSIGNALED(status)) {
			log_warnx("check_child: lost child: %s terminated; "
			    "signal %d", pname, WTERMSIG(status));
			return (1);
		}
	}
	return (0);
}

void
ifconfigd_shutdown(void)
{
	pid_t	pid;

	if (ifconfigde_pid)
		kill(ifconfigde_pid, SIGTERM);

	do {
		if ((pid = wait(NULL)) == -1 &&
		    errno != EINTR && errno != ECHILD)
			fatal("wait");
	} while (pid != -1 || (pid == -1 && errno == EINTR));

	log_info("terminating");
	exit(0);
}

void
imsg_event_add(struct imsgev *iev)
{
	iev->events = EV_READ;
	if (iev->ibuf.w.queued)
		iev->events |= EV_WRITE;

	event_del(&iev->ev);
	event_set(&iev->ev, iev->ibuf.fd, iev->events, iev->handler, iev);
	event_add(&iev->ev, NULL);
}


void
ifconfigd_dispatch_ifconfige(int fd, short event, void * ptr)
{
	struct imsgev		*iev;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	ssize_t			 n;

	iev = ptr;
	ibuf = &iev->ibuf;
	switch (event) {
	case EV_READ:
		if ((n = imsg_read(ibuf)) == -1)
			fatal("ifconfigd_dispatch_ifconfige: imsg_read error");
		if (n == 0) {
			/* this pipe is dead, so remove the event handler */
			event_del(&iev->ev);
			event_loopexit(NULL);
			return;
		}
		break;
	case EV_WRITE:
		if (msgbuf_write(&ibuf->w) == -1)
			fatal("ifconfigd_dispatch_ifconfige: msgbuf_write");
		imsg_event_add(iev);
		return;
	default:
		fatalx("ifconfigd_dispatch_ifconfige: unknown event");
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("ifconfigd_dispatch_ifconfige: imsg_read error");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		default:
			log_debug("ifconfigd_dispatch_ifconfige: unexpected imsg %d",
			    imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

int
imsg_compose_event(struct imsgev *iev, u_int16_t type, u_int32_t peerid,
    pid_t pid, int fd, void *data, u_int16_t datalen)
{
	int	ret;

	if ((ret = imsg_compose(&iev->ibuf, type, peerid,
		pid, fd, data, datalen)) != -1)
		imsg_event_add(iev);
	return (ret);
}

void
ifconfig_gate(int argc, char *argv[], const char *iface)
{
	const struct afswtch *rafp = NULL;

	/* set interface */
	if (strlcpy(name, iface, sizeof(iface)) >= IFNAMSIZ)
		errx(1, "interface name '%s' too long", iface);

	if (argc > 0) {
		for (afp = rafp = afs; rafp->af_name; rafp++)
			if (strcmp(rafp->af_name, *argv) == 0) {
				argc--;
				argv++;
				afp = rafp;
				break;
			}
		rafp = afp;
		af = ifr.ifr_addr.sa_family = rafp->af_af;
	}

	(void) strlcpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));

	/* set flags and socket */
	(void)getinfo(&ifr, 0);

	while (argc > 0) {
		cmd *p;

		for (p = cmds; p->c_name; p++)
			if (strcmp(*argv, p->c_name) == 0)
				break;
		
		if (p->c_parameter == NEXTARG) {
			if (argv[1] == NULL)
				errx(1, "'%s' requires argument", p->c_name);

			(*p->c_func)(argv[1], 0);
			argc--, argv++;
			actions = actions | A_SILENT | p->c_action;
		}
		else if (p->c_parameter == NEXTARG2) {
			if ((argv[1] == NULL) ||
				(argv[2] == NULL))
				errx(1, "'%s' requires 2 arguments", p->c_name);

			(*p->c_func2)(argv[1], argv[2]);
			argc -= 2;
			argv += 2;
		}
		else {
			(*p->c_func)(*argv, p->c_parameter);
			actions = actions | A_SILENT | p->c_action;
		}
		argc--, argv++;
	}

	/* Process any media commands that may have been issued. */
	process_media_commands();

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
}

const char *
active_check(const char *ifname)
{
	struct ifmediareq ifmr;
	struct ifaddrs *ifap, *ifa;
	struct if_data *ifdata;
	char *oname = NULL;
	struct ifreq *ifrp;
	size_t nlen = 0;

	if (ifname) {
		if ((oname = strdup(ifname)) == NULL)
			err(1, "strdup");
		nlen = strlen(oname);
	}

	if (getifaddrs(&ifap) != 0)
		err(1, "getifaddrs");

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (oname) {
			if (nlen && isdigit(oname[nlen - 1])) {
				/* must have exact match */
				if (strcmp(oname, ifa->ifa_name) != 0)
					continue;
			} else {
				/* partial match OK if it ends w/ digit */
				if (strncmp(oname, ifa->ifa_name, nlen) != 0 ||
				    !isdigit(ifa->ifa_name[nlen]))
					continue;
			}
		}
#ifdef INET6
		/* quickhack: sizeof(ifr) < sizeof(ifr6) */
		if (ifa->ifa_addr->sa_family == AF_INET6) {
			memset(&ifr6, 0, sizeof(ifr6));
			memcpy(&ifr6.ifr_addr, ifa->ifa_addr,
			    MIN(sizeof(ifr6.ifr_addr), ifa->ifa_addr->sa_len));
			ifrp = (struct ifreq *)&ifr6;
		} else
#endif
		{
		memset(&ifr, 0, sizeof(ifr));
		memcpy(&ifr.ifr_addr, ifa->ifa_addr,
			MIN(sizeof(ifr.ifr_addr), ifa->ifa_addr->sa_len));

		ifrp = &ifr;
		}

		strlcpy(name, ifa->ifa_name, sizeof(name));
		strlcpy(ifrp->ifr_name, ifa->ifa_name, sizeof(ifrp->ifr_name));


		(void) memset(&ifmr, 0, sizeof(ifmr));
		(void) strlcpy(ifmr.ifm_name, name, sizeof(ifmr.ifm_name));

		if (ifa->ifa_addr->sa_family == AF_LINK) {
			getinfo(ifrp, 0);

			ifdata = ifa->ifa_data;
			struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;

			// XXX with ioctl it don't work
			//if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
				/*
				* Interface doesn't support SIOC{G,S}IFMEDIA.
				*/
				return (get_linkstate(sdl->sdl_type, ifdata->ifi_link_state));
			//}
		}
	}
}

int
ieee80211_scan(const char *ifname, int argc, char *nwid[],
		struct ieee80211_nodereq *resault[])
{
	const struct afswtch *rafp = NULL;
	struct ieee80211_nodereq_all na;
	struct ieee80211_nodereq nr[512];
	struct ifreq ifr;
	int i, x, count = 0;

	/* set interface */
	if (strlcpy(name, ifname, sizeof(ifname)) >= IFNAMSIZ)
		errx(1, "interface name '%s' too long", ifname);

	for (afp = rafp = afs; rafp->af_name; rafp++)
		if (strcmp(rafp->af_name, ifname) == 0) {
			afp = rafp;
			break;
		}

	rafp = afp;
	af = ifr.ifr_addr.sa_family = rafp->af_af;

	(void) strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	/* set flags and socket */
	(void)getinfo(&ifr, 0);


	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

	if (ioctl(s, SIOCS80211SCAN, (caddr_t)&ifr) != 0) {
		if (errno == EPERM)
			log_warn("no permission to scan on %s", name);
	}

	bzero(&na, sizeof(na));
	bzero(&nr, sizeof(nr));
	na.na_node = nr;
	na.na_size = sizeof(nr);
	strlcpy(na.na_ifname, name, sizeof(na.na_ifname));

	if (ioctl(s, SIOCG80211ALLNODES, &na) != 0) {
		log_warn("SIOCG80211ALLNODES");
	}

	if (!na.na_nodes)
		return count;

	for (i = 0; i < na.na_nodes; i++) {
		struct ieee80211_nodereq *tnr = &nr[i];
		int len;

		if (tnr->nr_flags & IEEE80211_NODEREQ_AP) {
			len = tnr->nr_nwid_len;
			if (len > IEEE80211_NWID_LEN)
				len = IEEE80211_NWID_LEN;

			for (x=0; x < argc; x++) {
				if(strcmp(tnr->nr_nwid, nwid[x]) == 0){
					resault[count] = &nr[i];
					++count;
					continue;
				}
			}
		}
	}
	sleep(2);
	return count;
}

int
use_ethernet(const char *name)
{
	struct network *network;
	struct ethernet *eth;

	LIST_FOREACH(network, &ifconfigd_conf->network_list, entry) {
		LIST_FOREACH(eth, &network->ethernet_list, entry) {
			if (strncmp(eth->name, name, sizeof(eth->name)) == 0) {
					return (connect_ethernet(eth));
			}
		}
	}
}

int
monitor_ethernet(void)
{
	const char *ifstat_n;
	const char *ifstat_o;
	
	char *todo[11];
	int i;

	struct network *network;
	struct ethernet *eth;

	LIST_FOREACH(network, &ifconfigd_conf->network_list, entry) {
		LIST_FOREACH(eth, &network->ethernet_list, entry) {
			ifstat_o = ifstat_n;
			ifstat_n = active_check(eth->interface[0]);

			if (ifstat_o != NULL) {
				if (strncmp(ifstat_n, ifstat_o, sizeof(ifstat_o)) != 0){
					/* change interface status */
					if (strncmp(ifstat_n, "active", 6) == 0) {
						log_info("ethernet interface %s is active!", eth->interface);
						return (connect_ethernet(eth));
					}
				}
			}
		}
	}
	return 1;
}

int
connect_ethernet(struct ethernet *eth)
{
	char *todo[11];
	int i;

	/* Connecting*/
	if (eth->isdhcp == 1) {
		/* TODO: dhcp via dhcleint socket and fork(2) */
		log_info("init dhcp request on %s", eth->interface);
		if (execle(_PATH_DHCLEINT, "dhclient", "-d",
					"-q", eth->interface))
			return 0;
	}
	else if (eth->staticopts != NULL) {
		/* XXX:
		* - route {delete and set default gateway}
		* - set resolv.conf
		* - check DNS
		*/
		/* initial static network */
		i=0;
		bzero(todo, sizeof(char)*11);

		todo[i] = "inet";
		todo[++i] = &eth->staticopts->inet[0];

		bzero(todo, sizeof(char)*11);
		if (eth->staticopts->netmask != NULL) {
			todo[++i] = "netmask";
			todo[++i] = &eth->staticopts->netmask[0];
		}
		log_info("init static route on", eth->interface);
		ifconfig_gate(++i, todo, eth->interface[0]);
		return 0;
	}
	return -1;
}

int
connect_wireless(struct wireless *wlan)
{
	char *todo[11];
	char *t[1] ={"-bssid"};
	int i;

	/* Change the link layer address (MAC address) */
	if (wlan->lladdr != NULL) {
		bzero(todo, sizeof(char)*10);
		todo[0] = "lladdr";
		todo[1] = &wlan->lladdr[0];

		ifconfig_gate(2, todo, wlan->interface);
	}
	/* Enable Wi-Fi Protected Access. */
	if (wlan->wpa != NULL) {
		/* cleanup interface */
		bzero(todo, sizeof(char)*11);
		todo[0] = "-bssid";
		todo[1] = "-chan";
		todo[2] = "-nwid";
		todo[3] = "-wpa";
		todo[4] = "-wpapsk";

		log_info("cleanup interface %s", wlan->interface);
		ifconfig_gate(1, t, &wlan->interface[0]);

		i=0;
		bzero(todo, sizeof(char)*11);
		todo[i] = "nwid";
		todo[++i] = &wlan->nwid[0];
		todo[++i] = "wpa";

		if (wlan->wpa->wpaakms != NULL) {
			todo[++i] = "wpaakms";
			todo[++i] = &wlan->wpa->wpaakms[0];
		}
		if (wlan->wpa->wpaciphers != NULL) {
			todo[++i] = "wpaciphers";
			todo[++i] = &wlan->wpa->wpaciphers[0];
		}
		if (wlan->wpa->wpagroupcipher != NULL) {
			todo[++i] = "wpagroupcipher";
			todo[++i] = &wlan->wpa->wpagroupcipher[0];
		}

		todo[++i] = "wpakey";
		todo[++i] = &wlan->wpa->wpakey[0];

		log_info("init WPA access on ", wlan->interface);
		ifconfig_gate(++i, todo, &wlan->interface[0]);
	}

	if (wlan->isdhcp == 1) {
		/* TODO: dhcp via dhcleint socket and fork(2) */
		log_info("init dhcp request on %s", wlan->interface);
		if(execl(_PATH_DHCLEINT, "dhclient", "-d", "-q", wlan->interface) != -1)
			return 0;
	}
	else if (wlan->staticopts != NULL) {
		/*
		 * TODO:
		 * - route {delete and set default gateway}
		 * - set resolv.conf
		 * - check DNS
		 */

		/* initial static network */
		i=0;
		bzero(todo, sizeof(char)*11);

		todo[i] = "inet";
		todo[++i] = &wlan->staticopts->inet[0];

		bzero(todo, sizeof(char)*11);
		if (wlan->staticopts->netmask != NULL) {
			todo[++i] = "netmask";
			todo[++i] = &wlan->staticopts->netmask[0];
		}
		log_info("init static route on", wlan->interface);
		ifconfig_gate(++i, todo, &wlan->interface[0]);
		return 0;
	}
	return 0;
}

int
monitor_wireless(void)
{
	int rssi;
	char *ifstat_n;
	char *ifstat_o;
	struct ieee80211_nodereq *myre[512];
	char *todo[1]; 

	struct network *network;
	struct wireless *wlan;

	LIST_FOREACH(network, &ifconfigd_conf->network_list, entry) {
		LIST_FOREACH(wlan, &network->wireless_list, entry) {
			todo[0] = "up";
			ifconfig_gate(1, todo, &wlan->interface[0]);

			/* scan wireless interface and check ranges  */
			if (ieee80211_scan(&wlan->interface[0], 1, &wlan->nwid, myre)) {
				rssi = (myre[0]->nr_rssi*100)/255;

				if (myre[0]->nr_channel != wlan->channel) {
					log_info("%s on chan %d, mismatch with channel from config file",
							wlan->nwid, myre[0]->nr_channel);
					break;
				}
				else if (rssi < wlan->minsignal) {
					log_info(" %s is in range but signal strength %d is too weak",
							wlan->nwid, rssi);
					break;
				}
				else if (wlan->bssid != NULL) {
						if (wlan->bssid != ether_ntoa((struct ether_addr*)myre[0]->nr_bssid)) {
							log_info("%s on chan %d, mismatch with BSSID from config file",
							wlan->nwid, myre[0]->nr_channel);
							break;
						}
				}
				else {
				log_info(" SSID: \"%s\" on chan \"%d\"  signal  %d % (\"%ddb\")",
						myre[0]->nr_nwid,
						myre[0]->nr_channel,
						rssi,
						myre[0]->nr_rssi);
				return (connect_wireless(wlan));
				}
			}
			bzero(todo, sizeof(char));
			todo[0] = "down";
			ifconfig_gate(1, todo, &wlan->interface[0]);
		}
	}
	return -1;
}

int
monitor(void)
{
	do {
		/* first, check ethernet */
		if (monitor_ethernet() != 0)
			log_info("ethernet connection successful");
			return 0;

		/* secound, check ethernet */
		if (monitor_wireless() == 0) {
			log_info("wireless connection successful");
			return 0;
		}

		/* suspend until next update interval */
		sleep(ifconfigd_conf->upinterval);
	}
	while(1);
}

void
__monitor (void) {
	char *ifstat_n;
	char *ifstat_o;

	do {
		char *ifname = "iwn0";
		char *eifname = "em0";
		char *mystuff2[1] = {"up"};
		ifconfig_gate(1, mystuff2, ifname);

		/* check interface activity (changes) */
		/*ifstat_o = ifstat_n;
		ifstat_n = active_check(eifname);

		if (strncmp(ifstat_n, ifstat_o),sizeof(ifstat_o)){
			log_info("ethernet interface %s is offline!", eifname);

		}*/
		/* interface down */
		/*/if (strncmp(retmp, "no carrier", 10) == 0
				|| strncmp(retmp, "down", 4) == 0
				|| strncmp(retmp, "keepalive down", 14) == 0){
			log_info("ethernet interface %s is offline!", eifname);

		}
		else if (strncmp(retmp, "active", 6) == 0) {
			log_info("ethernet interface %s is online!", eifname);
		}
		*/
		/* scan wireless interface and check ranges  */
		char *mystuff[3] = {"OpenHTC","wir3","OpenHome"};
		struct ieee80211_nodereq *myre[512];
		int my  =0, i;

		my = ieee80211_scan(ifname, 3, mystuff, myre);

		for (i=0; i < my; i++) {
			log_info("catch wireless SSID: \"%s\" on channel \"%d\" with received signal strength %d % (\"%ddb\")",
					myre[i]->nr_nwid, myre[i]->nr_channel,(int) ((myre[i]->nr_rssi / 255)*100), myre[i]->nr_rssi);
		}

		sleep(2);

		char *mystuff22[1] = {"down"};
		ifconfig_gate(1, mystuff22, "iwn0");

		/* after scan wireless interface without results, shut it down to
		* save power
		*/
		//ifconfig_gate(1, "down", "iwn0");
		
		/* suspend until next update interval */
		sleep(ifconfigd_conf->upinterval);
	}
	while(1);
}
