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
#include "control.h"

void ifconfigd_dispatch_parent(int, short, void *);
struct imsgev		*iev_parent;

pid_t
ifconfigde(struct ifconfigd_conf *xconf, int pipe_parent2ifconfigd[2])
{
	pid_t			 pid;
	struct passwd	*pw;

	switch (pid = fork()) {
	case -1:
		fatal("cannot fork");
	case 0:
		break;
	default:
		return (pid);
	}

		/* create ifconfigd control socket outside chroot */
	if (control_init(xconf->csock) == -1)
		fatalx("control socket setup failed");

	if ((pw = getpwnam(IFCONFIGD_USER)) == NULL)
		fatal("getpwnam");

	if (chroot(pw->pw_dir) == -1)
		fatal("chroot");
	if (chdir("/") == -1)
		fatal("chdir(\"/\")");

	setproctitle("ifconfigd engine");

	if (setgroups(1, &pw->pw_gid) ||
			setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
			setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges");

	event_init();

	/* listen on ifconfigd control socket */
	TAILQ_INIT(&ctl_conns);
	control_listen();

	/* config sockets */
	close(pipe_parent2ifconfigd[0]);

	if ((iev_parent = calloc(1, sizeof(struct imsgev))) == NULL)
		fatal("ifconfigde");

	imsg_init(&iev_parent->ibuf, pipe_parent2ifconfigd[1]);
	iev_parent->handler = ifconfigd_dispatch_parent;
	
	iev_parent->events = EV_READ;
	event_set(&iev_parent->ev, iev_parent->ibuf.fd, iev_parent->events,
	    iev_parent->handler, iev_parent);
	event_add(&iev_parent->ev, NULL);
	
	event_dispatch();

	exit(0);
}

void
ifconfigd_dispatch_parent(int fd, short event, void * ptr)
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
			fatal("ifconfigd_dispatch_parent: imsg_read error");
		if (n == 0) {
			/* this pipe is dead, so remove the event handler */
			event_del(&iev->ev);
			event_loopexit(NULL);
			return;
		}
		break;
	case EV_WRITE:
		if (msgbuf_write(&ibuf->w) == -1)
			fatal("ifconfigd_dispatch_parent: msgbuf_write");
		imsg_event_add(iev);
		return;
	default:
		fatalx("ifconfigd_dispatch_parent: unknown event");
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("ifconfigd_dispatch_parent: imsg_read error");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		default:
			log_debug("ifconfigd_dispatch_parent: unexpected imsg %d",
			    imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/* imesg */
int
ifconfigde_imsg_compose_parent(int type, pid_t pid, void *data,
		u_int16_t datalen)
{
	return (imsg_compose_event(iev_parent, type, 0, pid, -1, data, datalen));
}
