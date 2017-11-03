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
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/un.h>
#include <sys/tree.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <event.h>

#include "ifconfigd.h"
#include "ifconfigctl.h"

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr,
			"usage: %s [-v] [-s socket] command [argument ...]\n",
			__progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct sockaddr_un	 sun;
	//struct keylist		 *keys;
	//struct imsg			 imsg;
	struct imsgbuf		 ibuf;

	int			 ctl_sock;
	int			 done = 0;
	int			 verbose = 0;
	int			 imsgflag;
	int			 ch;
	//ssize_t		 n;
	
	//char		 *imsg_arg;
	char		 name[MAX_NETWORK_NAME_SIZE];
	char		 *csockpath = IFCONFIGD_SOCKET;


	while ((ch = getopt(argc, argv, "s:v")) != -1) {
		switch (ch) {
		case 's':
			csockpath = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage();

	switch (keyword(*argv)) {
			case K_MONITOR:
				imsgflag = IMSG_IFCONFIGD_MONITOR;
				break;
			case K_SHOW:
				imsgflag = IMSG_SHOW_NETWORKS;
				break;
			case K_USE_ETH:
				imsgflag = IMSG_USE_ETHERNET;
				argv++;
				strncpy(name, *argv, sizeof(name));
				break;
			case K_USE_NET:
				imsgflag = IMSG_USE_NETWORKS;
				break;
			case K_USE_WLAN:
				imsgflag = IMSG_USE_WIRELESS;
				break;
			default:
				usage();
	}

	/* connect to ifconfig control socket */
	if ((ctl_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		err(1, "socket");

	bzero(&sun, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, csockpath, sizeof(sun.sun_path));
	if (connect(ctl_sock, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		err(1, "connect: %s", csockpath);

	imsg_init(&ibuf, ctl_sock);
	done = 0;

	switch (imsgflag) {
			case IMSG_USE_ETHERNET:
				imsg_compose(&ibuf, IMSG_USE_ETHERNET, 0, 0, -1,
						&name, sizeof(name));
				break;
			case IMSG_IFCONFIGD_MONITOR:
				imsg_compose(&ibuf, IMSG_IFCONFIGD_MONITOR, 0, 0, -1, NULL, 0);
				break;
	}
	
	while (ibuf.w.queued)
		if (msgbuf_write(&ibuf.w) < 0)
			err(1, "write error");

	/*  while (!done) {
		if ((n = imsg_read(&ibuf)) == -1)
			errx(1, "imsg_read error");
		if (n == 0)
			errx(1, "pipe closed");

		while (!done) {
			if ((n = imsg_get(ibuf, &imsg)) == -1)
				errx(1, "imsg_get error");
			if (n == 0)
				break;
			switch (res->action) {
			case IMSG_NONE:
				done = show_db_msg_detail(&imsg);
			}

		imsg_free(&imsg);
	}
	*/
	close(ctl_sock);

	return (0);
}

int
keycmp(const void *key, const void *kt)
{
	return (strcmp(key, ((struct keytab *)kt)->kt_cp));
}

int
keyword(char *cp)
{
	struct keytab *kt;

	kt = bsearch(cp, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), keycmp);
	if (!kt)
		return (0);

	return (kt->kt_i);
}
