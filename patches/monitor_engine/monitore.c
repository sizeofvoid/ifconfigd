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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/tree.h>

#include <net/if.h>

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
// DEBUG
#include <stdio.h>

#include "ifconfigd.h"
#include "ifcutil.h"

void monitore_dispatch_imsg(int, short, void *);
struct imsgev		*iev_parent;
struct ifconfigd_conf	*env = NULL;

pid_t
monitore(struct ifconfigd_conf *xconf, int pipe_parent2ifconfigd[2])
{
	pid_t			 pid;

	env = xconf;

	switch (pid = fork()) {
	case -1:
		fatal("cannot fork");
	case 0:
		break;
	default:
		return (pid);
	}

	setproctitle("ifconfigd monitor engine");

	event_init();

	/* config sockets */
	close(pipe_parent2ifconfigd[0]);

	if ((iev_parent = calloc(1, sizeof(struct imsgev))) == NULL)
		fatal("monitore");

	imsg_init(&iev_parent->ibuf, pipe_parent2ifconfigd[1]);
	iev_parent->handler = monitore_dispatch_imsg;
	
	iev_parent->events = EV_READ;
	event_set(&iev_parent->ev, iev_parent->ibuf.fd, iev_parent->events,
	    iev_parent->handler, iev_parent);
	event_add(&iev_parent->ev, NULL);
	
	event_dispatch();

	exit(0);
}

void
monitore_dispatch_imsg(int fd, short event, void * ptr)
{
	struct imsgev		*iev;
	struct imsgbuf		*ibuf;
	struct imsg			imsg;
	ssize_t				n;

	iev = ptr;
	ibuf = &iev->ibuf;
	switch (event) {
	case EV_READ:
		if ((n = imsg_read(ibuf)) == -1)
			fatal("monitore_dispatch_imsg: imsg_read error");
		if (n == 0) {
			/* this pipe is dead, so remove the event handler */
			event_del(&iev->ev);
			event_loopexit(NULL);
			return;
		}
		break;
	case EV_WRITE:
		if (msgbuf_write(&ibuf->w) == -1)
			fatal("monitore_dispatch_imsg: msgbuf_write");
		imsg_event_add(iev);
		return;
	default:
		fatalx("monitore_dispatch_imsg: unknown event");
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("monitore_dispatch_imsg: imsg_read error");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
			case IMSG_IFCONFIGD_MONITOR:
				monitor();
				break;
		default:
			log_debug("monitore_dispatch_imsg: unexpected imsg %d",
			    imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/* imesg */
int
monitore_imsg_compose_parent(int type, pid_t pid, void *data,
		u_int16_t datalen)
{
	return (imsg_compose_event(iev_parent, type, 0, pid, -1, data, datalen));
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

	LIST_FOREACH(network, &env->network_list, entry) {
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
monitor_wireless(void)
{
	int rssi;
	char *ifstat_n;
	char *ifstat_o;
	struct ieee80211_nodereq *myre[512];
	char *todo[1]; 

	struct network *network;
	struct wireless *wlan;

	LIST_FOREACH(network, &env->network_list, entry) {
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
		if (monitor_ethernet() == 0) {
			log_info("ethernet connection successful");
			return 0;
		}

		/* secound, check ethernet */
		if (monitor_wireless() == 0) {
			log_info("wireless connection successful");
			return 0;
		}

		/* suspend until next update interval */
		sleep(env->upinterval);
	}
	while(1);
}
