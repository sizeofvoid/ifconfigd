/*	$OpenBSD:  */

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

#ifndef _IFCONFIGD_H_
#define _IFCONFIGD_H_

#include <net/if.h>

#include <event.h>
#include <imsg.h>

#include <limits.h>

#define CONF_FILE				"/etc/ifconfigd.conf"
#define IFCONFIGD_SOCKET		"/var/run/ifconfigd.sock"
#define IFCONFIGD_USER			"_ifconfigd"
#define IFCONFIGD_ANCHOR		"_ifconfigd"
#define IFCONFIGD_SERVERNAME	"OpenBSD ifconfigd"

#define _PATH_DHCLEINT			"/sbin/dhclient"

#define	MAX_NETWORK_NAME_SIZE	64
#define	MIN_UPDATE_INTERVAL		5


/* XXX delete */
void			__monitor(void);

struct static_cfg {
	char			*inet;
	char			*netmask;
	char			*domainname;
	char			*domainserver;
};
struct ethernet {
	LIST_ENTRY(ethernet) entry;
	char				*name[MAX_NETWORK_NAME_SIZE];
	const char			*interface[IF_NAMESIZE];
	int					priority;
	int					isdhcp;
	struct static_cfg	*staticopts;

	char				*lladdr;
	char				*run_up;
	char				*run_down;

};


struct wpa_cfg {
		char		*wpakey;
		char		*wpagroupcipher;
		char		*wpaciphers;
		char		*wpaakms;
};

struct wireless {
	LIST_ENTRY(wireless) entry;
	const char			*name[MAX_NETWORK_NAME_SIZE];
	const char			*interface[IF_NAMESIZE];
	int					priority;

	char				*nwid;
	char				*bssid;
	
	int					minsignal;
	int					channel;

	int					isdhcp;
	struct static_cfg	*staticopts;

	struct wpa_cfg		*wpa;
	const char			*wep_nwkex;

	char				*lladdr;
	char				*run_up;
	char				*run_down;
};

struct network {
	LIST_ENTRY(network) entry;
	char				*name[MAX_NETWORK_NAME_SIZE];  // like ID
	int					priority;
	LIST_HEAD(,ethernet)	ethernet_list;
	LIST_HEAD(,wireless)	wireless_list;
};

struct ifconfigd_conf {
	LIST_HEAD(, network)	network_list;
	char				*csock;
	int					upinterval;
};


struct ifconfigd {
	u_int8_t			SC_Flags;

	const char			*sc_confpath;
	int					sc_sock;
	struct event		sc_ev;
	struct timeval		sc_starttime;
};

TAILQ_HEAD(ctl_conns, ctl_conn)	ctl_conns;

struct imsgev {
	struct imsgbuf		ibuf;
	void				(*handler)(int, short, void *);
	struct event		ev;
	void				*data;
	short				events;
};

struct imsguse {
	char				name[MAX_NETWORK_NAME_SIZE];
	int					number;
};

enum imsg_type {
	IMSG_NONE,
	/* USE calls */
	IMSG_USE_ETHERNET,
	IMSG_USE_NETWORKS,
	IMSG_USE_WIRELESS,
	/* SHOW calls */
	IMSG_SHOW_ETHERNET,
	IMSG_SHOW_NETWORKS,
	IMSG_SHOW_WIRELESS,
	/* call ifconfigd parent (root privileges) functions */
	IMSG_IFCONFIGD_MONITOR
};


/* ifconfigd.c */
void		 imsg_event_add(struct imsgev *);
int			 imsg_compose_event(struct imsgev *, u_int16_t, u_int32_t,
			 pid_t, int, void *, u_int16_t);

void			ifconfig_gate(int , char *[], const char*);
const char*		active_check(const char *);
int				monitor_wireless(void);
int				monitor_ethernet(void);
int				monitor(void);
int				use_ethernet(const char* );
int				connect_ethernet(struct ethernet*);

/* ifconfigde.c */
pid_t	 ifconfigde(struct ifconfigd_conf *, int pipe_parent2ifconfigd[2]);
int		 ifconfigde_imsg_compose_parent(int, pid_t, void *, u_int16_t);


/* parse.y */
struct	 ifconfigd_conf *parse_config(const char *);
int		 cmdline_symset(char *);

/* log.c */
void		 log_init(int);
void		 log_warn(const char *, ...);
void		 log_warnx(const char *, ...);
void		 log_info(const char *, ...);
void		 log_debug(const char *, ...);
__dead void	 fatal(const char *);
__dead void	 fatalx(const char *);

#endif	/* _IFCONFIGD_H_ */
