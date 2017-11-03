/*
 * Copyright (c) 2011 Rafael Sadowski <rafael@sizeofvoid.org>
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
#ifndef _IFCUTIL_H_
#define _IFCUTIL_H_

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

#include "brconfig.h"
#include "pbkdf2.h"

struct	ifreq		ifr, ridreq;
struct	in_aliasreq	in_addreq;
#ifdef INET6
struct	in6_ifreq	ifr6;
struct	in6_ifreq	in6_ridreq;
struct	in6_aliasreq	in6_addreq;
#endif /* INET6 */
struct	sockaddr_in	netmask;

#ifndef SMALL
struct	ifaliasreq	addreq;
struct  netrange	at_nr;		/* AppleTalk net range */
#endif /* SMALL */

char	name[IFNAMSIZ];
int	flags, xflags, setaddr, setipdst, doalias;
u_long	metric, mtu;
int	rdomainid;
int	clearaddr, s;
extern int	newaddr;
extern int	explicit_prefix;
extern int	af;
#ifdef INET6
int	Lflag;
#endif /* INET6 */

int	showmediaflag;
int	shownet80211chans;
int	shownet80211nodes;

extern int ifaliases;
extern int aflag;

void	notealias(const char *, int);
void	setifaddr(const char *, int);
void	setifrtlabel(const char *, int);
void	setiflladdr(const char *, int);
void	setifdstaddr(const char *, int);
void	setifflags(const char *, int);
void	setifxflags(const char *, int);
void	setifbroadaddr(const char *, int);
void	setifmtu(const char *, int);
void	setifnwid(const char *, int);
void	setifbssid(const char *, int);
void	setifnwkey(const char *, int);
void	setifwpa(const char *, int);
void	setifwpaprotos(const char *, int);
void	setifwpaakms(const char *, int);
void	setifwpaciphers(const char *, int);
void	setifwpagroupcipher(const char *, int);
void	setifwpakey(const char *, int);
void	setifchan(const char *, int);
void	setifscan(const char *, int);
void	setiftxpower(const char *, int);
void	setifnwflag(const char *, int);
void	unsetifnwflag(const char *, int);
void	setifnetmask(const char *, int);
void	setifprefixlen(const char *, int);
void	setatrange(const char *, int);
void	setatphase(const char *, int);
void	settunnel(const char *, const char *);
void	deletetunnel(const char *, int);
void	settunnelinst(const char *, int);
#ifdef INET6
void	setia6flags(const char *, int);
void	setia6pltime(const char *, int);
void	setia6vltime(const char *, int);
void	setia6lifetime(const char *, const char *);
void	setia6eui64(const char *, int);
void	setkeepalive(const char *, const char *);
void	unsetkeepalive(const char *, int);
#endif /* INET6 */
void	checkatrange(struct sockaddr_at *);
void	setmedia(const char *, int);
void	setmediaopt(const char *, int);
void	setmediamode(const char *, int);
void	clone_create(const char *, int);
void	clone_destroy(const char *, int);
void	unsetmediaopt(const char *, int);
void	setmediainst(const char *, int);
void	settimeslot(const char *, int);
void	timeslot_status(void);
void	setmpelabel(const char *, int);
void	setvlantag(const char *, int);
void	setvlanprio(const char *, int);
void	setvlandev(const char *, int);
void	unsetvlandev(const char *, int);
void	mpe_status(void);
void	vlan_status(void);
void	setinstance(const char *, int);
int	main(int, char *[]);
int	prefix(void *val, int);

#ifndef SMALL
void	getifgroups(void);
void	carp_status(void);
void	setcarp_advbase(const char *,int);
void	setcarp_advskew(const char *, int);
void	setcarppeer(const char *, int);
void	unsetcarppeer(const char *, int);
void	setcarp_passwd(const char *, int);
void	setcarp_vhid(const char *, int);
void	setcarp_state(const char *, int);
void	setcarpdev(const char *, int);
void	unsetcarpdev(const char *, int);
void	setcarp_nodes(const char *, int);
void	setcarp_balancing(const char *, int);
void	setpfsync_syncdev(const char *, int);
void	setpfsync_maxupd(const char *, int);
void	unsetpfsync_syncdev(const char *, int);
void	setpfsync_syncpeer(const char *, int);
void	unsetpfsync_syncpeer(const char *, int);
void	setpfsync_defer(const char *, int);
void	pfsync_status(void);
void	setpppoe_dev(const char *,int);
void	setpppoe_svc(const char *,int);
void	setpppoe_ac(const char *,int);
void	pppoe_status(void);
void	setspppproto(const char *, int);
void	setspppname(const char *, int);
void	setspppkey(const char *, int);
void	setsppppeerproto(const char *, int);
void	setsppppeername(const char *, int);
void	setsppppeerkey(const char *, int);
void	setsppppeerflag(const char *, int);
void	unsetsppppeerflag(const char *, int);
void	spppinfo(struct spppreq *);
void	sppp_status(void);
void	sppp_printproto(const char *, struct sauthreq *);
void	settrunkport(const char *, int);
void	unsettrunkport(const char *, int);
void	settrunkproto(const char *, int);
void	trunk_status(void);
void	setifgroup(const char *, int);
void	unsetifgroup(const char *, int);
void	setifpriority(const char *, int);
void	setifpowersave(const char *, int);
void	setifmetric(const char *, int);
void	notrailers(const char *, int);
void	setgroupattribs(char *, int, char *[]);
void	pflow_status(void);
void	setpflow_sender(const char *, int);
void	unsetpflow_sender(const char *, int);
void	setpflow_receiver(const char *, int);
void	unsetpflow_receiver(const char *, int);
void	list_cloners(void);
void	setifipdst(const char *, int);
void	setifdesc(const char *, int);
void	unsetifdesc(const char *, int);
int	printgroup(char *, int);
#else
void	setignore(const char *, int);
#endif

/*
 * Media stuff.  Whenever a media command is first performed, the
 * currently select media is grabbed for this interface.  If `media'
 * is given, the current media word is modified.  `mediaopt' commands
 * only modify the set and clear words.  They then operate on the
 * current media word later.
 */
int	media_current;
int	mediaopt_set;
int	mediaopt_clear;

int	actions;			/* Actions performed */

#define	A_MEDIA		0x0001		/* media command */
#define	A_MEDIAOPTSET	0x0002		/* mediaopt command */
#define	A_MEDIAOPTCLR	0x0004		/* -mediaopt command */
#define	A_MEDIAOPT	(A_MEDIAOPTSET|A_MEDIAOPTCLR)
#define	A_MEDIAINST	0x0008		/* instance or inst command */
#define	A_MEDIAMODE	0x0010		/* mode command */
#define A_SILENT	0x8000000	/* doing operation, do not print */

#define	NEXTARG0	0xffffff
#define NEXTARG		0xfffffe
#define	NEXTARG2	0xfffffd

typedef const struct	cmd {
	char	*c_name;
	int	c_parameter;		/* NEXTARG means next argv */
	int	c_action;		/* defered action */
	void	(*c_func)(const char *, int);
	void	(*c_func2)(const char *, const char *);
} cmd;

extern cmd cmds[];

int	getinfo(struct ifreq *, int);
void	getsock(int);
void	printgroupattribs(char *);
void	printif(char *, int);
void	printb_status(unsigned short, char *);
const char *get_linkstate(int, int);
void	status(int, struct sockaddr_dl *, int);
const char *get_string(const char *, const char *, u_int8_t *, int *);
void	print_string(const u_int8_t *, int);
char	*sec2str(time_t);

const char *get_media_type_string(int);
const char *get_media_subtype_string(int);
int	get_media_mode(int, const char *);
int	get_media_subtype(int, const char *);
int	get_media_options(int, const char *);
int	lookup_media_word(const struct ifmedia_description *, int,
	    const char *);
void	print_media_word(int, int, int);
void	process_media_commands(void);
void	init_current_media(void);

unsigned long get_ts_map(int, int, int);

void	in_status(int);
void	in_getaddr(const char *, int);
void	in_getprefix(const char *, int);
#ifdef INET6
void	in6_fillscopeid(struct sockaddr_in6 *sin6);
void	in6_alias(struct in6_ifreq *);
void	in6_status(int);
void	in6_getaddr(const char *, int);
void	in6_getprefix(const char *, int);
#endif /* INET6 */
void    at_status(int);
void    at_getaddr(const char *, int);
void	ieee80211_status(void);
void	ieee80211_listchans(void);
void	ieee80211_listnodes(void);
void	ieee80211_printnode(struct ieee80211_nodereq *);

/* Known address families */
typedef const struct afswtch {
	char *af_name;
	short af_af;
	void (*af_status)(int);
	void (*af_getaddr)(const char *, int);
	void (*af_getprefix)(const char *, int);
	u_long af_difaddr;
	u_long af_aifaddr;
	caddr_t af_ridreq;
	caddr_t af_addreq;
} afswtch;

extern  afswtch afs[];

const struct afswtch *afp;	/*the address family being set or asked about*/
#endif	/* _IFCUTIL_H_ */
