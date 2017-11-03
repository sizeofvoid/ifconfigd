/*
 * Copyright (c) 2011 Rafael Sadowski <rafael@sizeofvoid.org>
 * Copyright (c) 2010 Reyk Floeter <reyk@vantronix.net>
 * Copyright (c) 2004, 2005 Hans-Joerg Hoexer <hshoexer@openbsd.org>
 * Copyright (c) 2002, 2003, 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Daniel Hartmeier.  All rights reserved.
 * Copyright (c) 2001 Theo de Raadt.  All rights reserved.
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

%{
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include <ctype.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "ifconfigd.h"

/* XXX DEBUG */
/*#define YYDEBUG 1
extern int yydebug = 1;
*/
TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	int			 lineno;
	int			 errors;
} *file;
struct file	*pushfile(const char *, int);
int		 popfile(void);
int		 check_file_secrecy(int, const char *);
int		 yyparse(void);
int		 yylex(void);
int		 yyerror(const char *, ...);
int		 yywarn(const char *, ...);
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 lgetc(int);
int		 lungetc(int);
int		 findeol(void);

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};
int		 symset(const char *, const char *, int);
char	 *symget(const char *);


static struct ifconfigd_conf	*conf;
struct network			*network;
struct ethernet			*ether;
struct wireless			*wlan;
struct wpa_cfg			*wpa;
struct static_cfg		*staticonfig;
static int				errors = 0;

typedef struct {
	union {
		int64_t			 number;
		char			*string;
	} v;
	int lineno;
} YYSTYPE;
%}

/*
 * BEGIN yacc Deklarationen
 */
/*
%token BSSID CHANNEL DHCP DOMAINNAME DOMAINNAMESERVERS ERROR ETHERNETNAME
%token INCLUDE INET INTERFACE YES
%token LLADDR MINSIGNAL NETMASK NETWORK NWID NO PRIORITY RUNDOWN RUNUP
%token UPDATEINTERVAL WIRELESSNAME WEP WEPKEY 
%token WPA WPAAKMS WPACIPHERS WPAGROUPCIPHER WPAKEY
*/
%token NETWORK ETHERNETNAME WIRELESSNAME 
%token BSSID CHANNEL  DOMAINNAME DOMAINNAMESERVERS ERROR
%token INCLUDE INET INTERFACE YES
%token LLADDR MINSIGNAL NETMASK NWID NO PRIORITY RUNDOWN RUNUP 
%token UPDATEINTERVAL DHCP WEP WEPKEY
%token WPA WPAAKMS WPACIPHERS WPAGROUPCIPHER WPAKEY WPAAKMS WPACIPHERS 
%token	<v.string>		STRING
%token	<v.number>		NUMBER
%type	<v.string>		string
%type	<v.number>		yesno

/*
 * BEGIN yacc rules/grammer
 */
%%
grammar		: /* empty */
		| grammar include '\n'
		| grammar '\n'
		| grammar global '\n'
		| grammar varset '\n'
		| grammar network '\n'
		| grammar error '\n'		{ file->errors++; }
		;

optnl		: '\n' optnl
		|
		;

nl		: '\n' optnl		/* one newline or more */
		;

comma		: ','
		| /*empty*/
		;

yesno	: YES	{ $$ = 1; }
		| NO	{ $$ = 0; }
		;

include		: INCLUDE STRING		{
			struct file	*nfile;

			if ((nfile = pushfile($2, 1)) == NULL) {
				yyerror("failed to include file %s", $2);
				free($2);
				YYERROR;
			}
			free($2);

			file = nfile;
			lungetc('\n');
		}
		;

string		: string STRING	{
			if (asprintf(&$$, "%s %s", $1, $2) == -1) {
				free($1);
				free($2);
				yyerror("string: asprintf");
				YYERROR;
			}
			free($1);
			free($2);
		}
		| STRING
		;

varset		: STRING string
		{
			if (symset($1, $2, 0) == -1)
				err(1, "cannot store variable");
			free($1);
			free($2);
		}
		;

/* global stuff */

global		: UPDATEINTERVAL NUMBER {
			if ($2 < MIN_UPDATE_INTERVAL) {
				yyerror("update interval is to short");
				YYERROR;
			}
			conf->upinterval = $2;
		}
		;

/* NETWORK Section */
network		: NETWORK STRING {
			if (strlen($2) > MAX_NETWORK_NAME_SIZE) {
				yyerror("network name too long (max length %d)",
				    MAX_NETWORK_NAME_SIZE);
					free($2);
					YYERROR;
			}

			if ((network = calloc(1, sizeof(*network))) == NULL)
				errx(1, "new_network: calloc");

			LIST_INSERT_HEAD(&conf->network_list, network, entry);
			strncpy(network->name, $2, sizeof(network->name));
			free($2);

		}
		'{' optnl networkopts_l '}' {
			network = NULL;
		}
		;

networkopts_l	: networkopts_l networkoptsl nl
		| networkoptsl optnl
		;

networkoptsl	: 
			 | ethernet
			 | wireless

		;

/* ETHERNET Section */
ethernet		: ETHERNETNAME STRING {
				if ((ether = calloc(1, sizeof(*ether))) == NULL)
					errx(1, "new_ethernet: calloc");
				
				LIST_INSERT_HEAD(&network->ethernet_list, ether, entry);

				strncpy(ether->name, $2, sizeof(ether->name));
				free($2);

				/* TODO If we don't use static, we will always calloc space, it
				 * suxx ass*/
				if ((staticonfig = calloc(1, sizeof(*staticonfig))) == NULL)
					errx(1, "new_static_cfg: calloc");

				ether->staticopts = staticonfig;
				ether->lladdr = NULL;

			
		} 
		ethernet_block {
			ether = NULL;
			staticonfig = NULL;
		}
		;

ethernet_block	: '{' optnl ethernetopts_l '}'
		| '{' optnl '}'
		|
		;

ethernetopts_l	: ethernetopts_l ethernetoptsl nl
		| ethernetoptsl 
		;

ethernetoptsl	: 
		|	PRIORITY NUMBER  {
			ether->priority = $2;
		}
		| INTERFACE STRING {
			strncpy(ether->interface, $2, sizeof(ether->interface));
			free($2);
		}
		| DHCP yesno {
			if ($2 == 0) {
				ether->isdhcp = 0; // NO
				if (staticonfig == NULL) {
					if ((staticonfig = calloc(1, sizeof(*staticonfig))) == NULL)
						errx(1, "new_static_cfg: calloc");
					}
				ether->staticopts = staticonfig;
			}
			else {
				ether->isdhcp = 1; // YES
				ether->staticopts = NULL; 
			}
		}
		| staticopts
		| LLADDR STRING {
			ether->lladdr = $2;
		}
		| RUNUP STRING {
			ether->run_up = $2;
		}
		| RUNDOWN STRING {
			ether->run_down = $2;
		}
		;

/* WIRELESS Section */
wireless		: WIRELESSNAME STRING {
				if ((wlan = calloc(1, sizeof(*wlan))) == NULL)
					errx(1, "new_wlan: calloc");
				
				LIST_INSERT_HEAD(&network->wireless_list, wlan, entry);

				strncpy(wlan->name, $2, sizeof(wlan->name));
				free($2);

				/* TODO If we don't use static, we will always calloc space, it
				 * suxx ass*/
				if ((staticonfig = calloc(1, sizeof(*staticonfig))) == NULL)
					errx(1, "new_static_cfg: calloc");

				wlan->staticopts = staticonfig;

				if ((wpa = calloc(1, sizeof(*wpa))) == NULL)
					errx(1, "new_static_cfg: calloc");

				wlan->wpa = wpa;
		} 
		wireless_block {
			wlan = NULL;
			ether = NULL;
		}
		;

wireless_block	: '{' optnl wirelessopts_l '}'
		| '{' optnl '}'
		|
		;

wirelessopts_l	: wirelessopts_l wirelessoptsl nl
		| wirelessoptsl 
		;

wirelessoptsl	: 
			|	PRIORITY NUMBER  {
				wlan->priority = $2;
			}
			| INTERFACE STRING {
				strncpy(wlan->interface, $2, sizeof(wlan->interface));
				free($2);
			}
			| NWID STRING {
				wlan->nwid = $2;
			}
			| CHANNEL NUMBER {
				wlan->channel = $2;
			}
			| BSSID STRING {
				wlan->bssid = $2;
			}
			| MINSIGNAL NUMBER {
				wlan->minsignal = $2;
			}
			| DHCP yesno {
				if ($2 == 0) {
					wlan->isdhcp = 0; // NO
					if ((staticonfig = calloc(1, sizeof(*staticonfig))) == NULL)
						errx(1, "new_static_cfg: calloc");

					wlan->staticopts = staticonfig;
				}
				else
					wlan->isdhcp = 1; // YES
			}
			| staticopts {
			}
			| wpa
			| wep
			| RUNUP STRING {
				wlan->run_up = $2;
			}
			| RUNDOWN STRING {
				wlan->run_down = $2;
			}
			| LLADDR STRING {
				wlan->lladdr = $2;
			}
		;

/* WPA Section */
wpa		: WPA  {
		} 
		wpa_block {
		}
		;

wpa_block	: '{' optnl wpaopts_l '}'
		| '{' optnl '}'
		|
		;

wpaopts_l	: wpaopts_l wpaoptsl nl
		| wpaoptsl 
		;

wpaoptsl	: 
			 | WPAKEY STRING  {
				wpa->wpakey = $2;
			 }
			 | WPAGROUPCIPHER STRING {
				wpa->wpagroupcipher = $2;
			 }
			 | WPAAKMS STRING {
				wpa->wpaakms = $2;
			 }
			 | WPACIPHERS STRING {
				wpa->wpaciphers = $2;
			 }
		;
/* WEP Section */
wep		: WEP  {
		} 
		wep_block {
		}
		;

wep_block	: '{' optnl wepopts_l '}'
		| '{' optnl '}'
		|
		;

wepopts_l	: wepopts_l wepoptsl nl
		| wepoptsl 
		;

wepoptsl	: 
			 | WEPKEY STRING  {
			 wlan->wep_nwkex = $2;
			 }
		;

/* static network options */
staticopts		: {
			}
			| DOMAINNAME STRING {
				staticonfig->domainname = $2;
			}
			| DOMAINNAMESERVERS STRING {
				staticonfig->domainserver = $2;
			}
			/* XXX TODO: check inet */
			| INET STRING {
				staticonfig->inet = $2;
			/*struct in_addr	id;
			if (inet_aton($2, &id) == 0) {
				yyerror("error parsing area");
				free($2);
				YYERROR;
			}*/
			}
			| NETMASK STRING {
				staticonfig->netmask = $2;
			}
			;
%%
struct keywords {
	const char	*k_name;
	int		 k_val;
};

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;

	file->errors++;
	va_start(ap, fmt);
	fprintf(stderr, "%s: %d: ", file->name, yylval.lineno);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	return (0);
}

int
yywarn(const char *fmt, ...)
{
	va_list		 ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: %d: ", file->name, yylval.lineno);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	return (0);
}

int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->k_name));
}

int
lookup(char *s)
{
	/* this has to be sorted always */
	static const struct keywords keywords[] = {
		{ "bssid",					BSSID },
		{ "chan",					CHANNEL },
		{ "dhcp",					DHCP },
		{ "domain-name",			DOMAINNAME },
		{ "domain-name-servers",	DOMAINNAMESERVERS },
		{ "error",					ERROR },
		{ "ethernet",				ETHERNETNAME },
		{ "include",				INCLUDE },
		{ "inet",					INET },
		{ "interface",				INTERFACE },
		{ "lladdr",					LLADDR },
		{ "minsignal",				MINSIGNAL },
		{ "netmask",				NETMASK },
		{ "network",				NETWORK },
		{ "no",						NO },
		{ "nwid",					NWID },
		{ "priority",				PRIORITY },
		{ "run-down",				RUNDOWN },
		{ "run-up",					RUNUP },
		{ "update_interval",		UPDATEINTERVAL },
		{ "wep",					WEP},
		{ "wepkey",					WEPKEY},
		{ "wireless",				WIRELESSNAME },
		{ "wpa",					WPA},
		{ "wpaakms",				WPAAKMS },
		{ "wpaciphers",				WPACIPHERS },
		{ "wpagroupcipher",			WPAGROUPCIPHER },
		{ "wpakey",					WPAKEY },
		{ "yes",					YES }
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p)
		return (p->k_val);
	else
		return (STRING);
}

#define MAXPUSHBACK	128

char	*parsebuf;
int	 parseindex;
char	 pushback_buffer[MAXPUSHBACK];
int	 pushback_index = 0;

int
lgetc(int quotec)
{
	int		c, next;

	if (parsebuf) {
		/* Read character from the parsebuffer instead of input. */
		if (parseindex >= 0) {
			c = parsebuf[parseindex++];
			if (c != '\0')
				return (c);
			parsebuf = NULL;
		} else
			parseindex++;
	}

	if (pushback_index)
		return (pushback_buffer[--pushback_index]);

	if (quotec) {
		if ((c = getc(file->stream)) == EOF) {
			yyerror("reached end of file while parsing quoted string");
			if (popfile() == EOF)
				return (EOF);
			return (quotec);
		}
		return (c);
	}

	while ((c = getc(file->stream)) == '\\') {
		next = getc(file->stream);
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	while (c == EOF) {
		if (popfile() == EOF)
			return (EOF);
		c = getc(file->stream);
	}
	return (c);
}

int
lungetc(int c)
{
	if (c == EOF)
		return (EOF);
	if (parsebuf) {
		parseindex--;
		if (parseindex >= 0)
			return (c);
	}
	if (pushback_index < MAXPUSHBACK-1)
		return (pushback_buffer[pushback_index++] = c);
	else
		return (EOF);
}

int
findeol(void)
{
	int	c;

	parsebuf = NULL;

	/* skip to either EOF or the first real EOL */
	while (1) {
		if (pushback_index)
			c = pushback_buffer[--pushback_index];
		else
			c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return (ERROR);
}


int
yylex(void)
{
	char	 buf[8096];
	char	*p, *val;
	int	 quotec, next, c;
	int	 token;

top:
	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */
	if (c == '$' && parsebuf == NULL) {
		while (1) {
			if ((c = lgetc(0)) == EOF)
				return (0);

			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			if (isalnum(c) || c == '_') {
				*p++ = (char)c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		val = symget(buf);
		if (val == NULL) {
			yyerror("macro '%s' not defined", buf);
			return (findeol());
		}
		parsebuf = val;
		parseindex = 0;
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return (0);
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return (0);
				if (next == quotec || c == ' ' || c == '\t')
					c = next;
				else if (next == '\n') {
					file->lineno++;
					continue;
				} else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = (char)c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			err(1, "yylex: strdup");
		return (STRING);
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x ==',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && isdigit(c));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {
			const char *errstr = NULL;

			*p = '\0';
			yylval.v.number = strtonum(buf, LLONG_MIN,
			    LLONG_MAX, &errstr);
			if (errstr) {
				yyerror("\"%s\" invalid number: %s",
				    buf, errstr);
				return (findeol());
			}
			return (NUMBER);
		} else {
nodigits:
			while (p > buf + 1)
				lungetc(*--p);
			c = *--p;
			if (c == '-')
				return (c);
		}
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && \
	x != '!' && x != '=' && x != '#' && \
	x != ','))

	if (isalnum(c) || c == ':' || c == '_') {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == STRING)
			if ((yylval.v.string = strdup(buf)) == NULL)
				err(1, "yylex: strdup");
		return (token);
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return (0);
	return (c);
}

int
check_file_secrecy(int fd, const char *fname)
{
	struct stat	st;

	if (fstat(fd, &st)) {
		warn("cannot stat %s", fname);
		return (-1);
	}
	if (st.st_uid != 0 && st.st_uid != getuid()) {
		warnx("%s: owner not root or current user", fname);
		return (-1);
	}
	if (st.st_mode & (S_IRWXG | S_IRWXO)) {
		warnx("%s: group/world readable/writeable", fname);
		return (-1);
	}
	return (0);
}

struct file *
pushfile(const char *name, int secret)
{
	struct file	*nfile;

	if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
		warn("malloc");
		return (NULL);
	}
	if ((nfile->name = strdup(name)) == NULL) {
		warn("malloc");
		free(nfile);
		return (NULL);
	}
	if (TAILQ_FIRST(&files) == NULL && strcmp(nfile->name, "-") == 0) {
		nfile->stream = stdin;
		free(nfile->name);
		if ((nfile->name = strdup("stdin")) == NULL) {
			warn("strdup");
			free(nfile);
			return (NULL);
		}
	} else if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		warn("%s", nfile->name);
		free(nfile->name);
		free(nfile);
		return (NULL);
	} else if (secret &&
	    check_file_secrecy(fileno(nfile->stream), nfile->name)) {
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	nfile->lineno = 1;
	TAILQ_INSERT_TAIL(&files, nfile, entry);
	return (nfile);
}

int
popfile(void)
{
	struct file	*prev;

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL) {
		prev->errors += file->errors;
		TAILQ_REMOVE(&files, file, entry);
		fclose(file->stream);
		free(file->name);
		free(file);
		file = prev;
		return (0);
	}
	return (EOF);
}

struct ifconfigd_conf *
parse_config(const char *filename)
{
	/*struct sym	*sym, *next;*/

	if ((conf = calloc(1, sizeof(struct ifconfigd_conf))) == NULL)
		return (NULL);
	
	if ((file = pushfile(filename, 0)) == NULL) {
		free(conf);
		return (NULL);
	}


	yyparse();
	errors = file->errors;
	popfile();


	if (errors) 
		return (NULL);

	return (conf);
}

int
symset(const char *nam, const char *val, int persist)
{
	struct sym	*sym;

	for (sym = TAILQ_FIRST(&symhead); sym && strcmp(nam, sym->nam);
	    sym = TAILQ_NEXT(sym, entry))
		;	/* nothing */

	if (sym != NULL) {
		if (sym->persist == 1)
			return (0);
		else {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}
	if ((sym = calloc(1, sizeof(*sym))) == NULL)
		return (-1);

	sym->nam = strdup(nam);
	if (sym->nam == NULL) {
		free(sym);
		return (-1);
	}
	sym->val = strdup(val);
	if (sym->val == NULL) {
		free(sym->nam);
		free(sym);
		return (-1);
	}
	sym->used = 0;
	sym->persist = persist;
	TAILQ_INSERT_TAIL(&symhead, sym, entry);
	return (0);
}

int
cmdline_symset(char *s)
{
	char	*sym, *val;
	int	ret;
	size_t	len;

	if ((val = strrchr(s, '=')) == NULL)
		return (-1);

	len = strlen(s) - strlen(val) + 1;
	if ((sym = malloc(len)) == NULL)
		errx(1, "cmdline_symset: malloc");

	(void)strlcpy(sym, s, len);

	ret = symset(sym, val + 1, 1);
	free(sym);

	return (ret);
}

char *
symget(const char *nam)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry)
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return (sym->val);
		}
	return (NULL);
}
