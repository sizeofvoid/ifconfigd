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

struct keytab {
	char	*kt_cp;
	int		kt_i;
};

enum {
	K_NULL,
	K_MONITOR,
	K_SHOW,
	K_USE_ETH,
	K_USE_NET,
	K_USE_WLAN,
};

struct keytab keywords[] = {
	{ "monitor",	K_MONITOR },
	{ "show",		K_SHOW },
	{ "uselan",		K_USE_ETH },
	{ "usenet",		K_USE_NET },
	{ "usewlan",	K_USE_WLAN },
};


__dead void		usage(void);
int				keyword(char *);
int				keycmp(const void *, const void *);
