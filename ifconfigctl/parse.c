#include <stdlib.h>
#include <string.h>
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYLEX yylex()
#define YYEMPTY -1
#define yyclearin (yychar=(YYEMPTY))
#define yyerrok (yyerrflag=0)
#define YYRECOVERING() (yyerrflag!=0)
#define YYPREFIX "yy"
#line 25 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "ldapd.h"

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	int			 lineno;
	int			 errors;
} *file, *topfile;
struct file	*pushfile(const char *, int);
int		 popfile(void);
int		 check_file_secrecy(int, const char *);
int		 yyparse(void);
int		 yylex(void);
int		 yyerror(const char *, ...);
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 lgetc(int);
int		 lungetc(int);
int		 findeol(void);

struct listener *host_unix(const char *path);
struct listener	*host_v4(const char *, in_port_t);
struct listener	*host_v6(const char *, in_port_t);
int		 host_dns(const char *, const char *,
		    struct listenerlist *, int, in_port_t, u_int8_t);
int		 host(const char *, const char *,
		    struct listenerlist *, int, in_port_t, u_int8_t);
int		 interface(const char *, const char *,
		    struct listenerlist *, int, in_port_t, u_int8_t);

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};
int		 symset(const char *, const char *, int);
char		*symget(const char *);

struct ldapd_config	*conf;

static struct aci	*mk_aci(int type, int rights, enum scope scope,
				char *target, char *subject);

typedef struct {
	union {
		int64_t		 number;
		char		*string;
		struct aci	*aci;
	} v;
	int lineno;
} YYSTYPE;

static struct namespace *current_ns = NULL;

#line 95 "y.tab.c"
#define ERROR 257
#define LISTEN 258
#define ON 259
#define TLS 260
#define LDAPS 261
#define PORT 262
#define NAMESPACE 263
#define ROOTDN 264
#define ROOTPW 265
#define INDEX 266
#define SECURE 267
#define RELAX 268
#define STRICT 269
#define SCHEMA 270
#define USE 271
#define COMPRESSION 272
#define LEVEL 273
#define INCLUDE 274
#define CERTIFICATE 275
#define FSYNC 276
#define CACHE_SIZE 277
#define INDEX_CACHE_SIZE 278
#define DENY 279
#define ALLOW 280
#define READ 281
#define WRITE 282
#define BIND 283
#define ACCESS 284
#define TO 285
#define ROOT 286
#define REFERRAL 287
#define ANY 288
#define CHILDREN 289
#define OF 290
#define ATTRIBUTE 291
#define IN 292
#define SUBTREE 293
#define BY 294
#define SELF 295
#define STRING 296
#define NUMBER 297
#define YYERRCODE 256
#if defined(__cplusplus) || defined(__STDC__)
const short yylhs[] =
#else
short yylhs[] =
#endif
	{                                        -1,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    2,
    2,    2,    2,   12,   12,    1,    1,    1,   16,   16,
   16,   16,   20,   17,    3,    3,   19,   19,   19,   21,
   21,   21,   21,   21,   21,   21,   21,   21,   21,   21,
    4,    4,   13,   13,    5,    5,    6,    6,    6,    7,
    7,    8,    8,    8,    9,    9,    9,   10,   10,   10,
   11,   11,   11,   11,   14,   15,   18,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yylen[] =
#else
short yylen[] =
#endif
	{                                         2,
    0,    2,    3,    3,    3,    3,    3,    3,    3,    0,
    1,    1,    1,    0,    2,    2,    2,    0,    6,    2,
    2,    2,    0,    7,    1,    1,    0,    2,    3,    2,
    2,    2,    2,    2,    2,    1,    2,    2,    3,    2,
    0,    2,    6,    2,    1,    1,    0,    1,    2,    1,
    3,    1,    1,    1,    0,    1,    2,    1,    1,    1,
    0,    2,    2,    2,    2,    3,    2,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yydefred[] =
#else
short yydefred[] =
#endif
	{                                      1,
    0,    0,    0,    0,    0,    0,    0,    0,   45,   46,
    0,    0,    2,    0,    0,    0,    0,    0,    0,    0,
    6,    0,    0,   21,   22,   67,   65,   20,    0,   52,
   53,   54,   48,    0,    0,   50,    8,    3,    4,    5,
    7,    9,    0,    0,   66,    0,   49,    0,    0,    0,
   23,    0,   56,    0,   51,   16,   17,   11,   12,   13,
    0,   27,   57,   59,   58,   60,    0,    0,   19,    0,
    0,   43,   15,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   28,   24,   36,    0,   62,   64,   63,
   30,   31,   32,   37,   38,    0,   26,   25,   35,   33,
   34,   40,   29,    0,   39,   42,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yydgoto[] =
#else
short yydgoto[] =
#endif
	{                                       1,
   50,   61,   99,  105,   14,   34,   35,   36,   54,   67,
   72,   69,   15,   16,   17,   18,   19,   20,   70,   62,
   87,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yysindex[] =
#else
short yysindex[] =
#endif
	{                                      0,
  -10,    1, -245, -276, -270, -262, -261, -260,    0,    0,
 -259,  -23,    0, -254,   29,   30,   32,   33,   34,   35,
    0, -249,  -77,    0,    0,    0,    0,    0, -247,    0,
    0,    0,    0, -237,  -41,    0,    0,    0,    0,    0,
    0,    0, -212,   41,    0, -268,    0, -250, -274, -248,
    0, -238,    0, -281,    0,    0,    0,    0,    0,    0,
 -222,    0,    0,    0,    0,    0, -240, -241,    0,   14,
 -279,    0,    0, -239, -236, -235, -214, -211, -210, -255,
 -234, -233, -231,    0,    0,    0,   48,    0,    0,    0,
    0,    0,    0,    0,    0, -207,    0,    0,    0,    0,
    0,    0,    0, -230,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short yyrindex[] =
#else
short yyrindex[] =
#endif
	{                                      0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   -9,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   58,    0,    0,    0,    0,    0,    0,
    0,    0,   -4,    0,    0, -278,    0,    0,    0,   -8,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   59,    0,    0,    0,    0,    0,   60,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   34,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short yygindex[] =
#else
short yygindex[] =
#endif
	{                                      0,
    0,    0,    0,    0,    0,    0,    0,   23,    0,    0,
    0,    0,    2,    0,    0,    0,    0,    0,    0,    0,
    0,
};
#define YYTABLESIZE 301
#if defined(__cplusplus) || defined(__STDC__)
const short yytable[] =
#else
short yytable[] =
#endif
	{                                      13,
   47,   10,   48,   97,   64,   18,   65,   55,   88,   55,
   21,   58,   59,   22,   66,   89,   90,   55,   60,   23,
   52,   56,   57,   84,   53,   24,   30,   31,   32,   33,
   30,   31,   32,   25,   26,   27,   28,   29,   37,   38,
   98,   39,   40,   41,   42,   44,   43,   46,   45,   49,
   51,   63,   68,   71,   73,   94,   91,  103,   95,   92,
   93,   96,  100,  101,  102,  104,  106,   44,   14,   61,
   55,   86,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   85,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   47,    0,    0,    2,    0,    3,    0,    0,
    0,    0,    4,    5,    6,   18,   18,    0,    0,    7,
    0,    0,   18,    8,    0,    0,   10,    0,    9,   10,
   18,    0,    0,    0,    0,   47,   11,   74,   75,   76,
    0,   77,   78,    0,   79,   12,    0,    0,    0,   80,
   81,   82,    9,   10,    0,    0,    0,    0,    0,    0,
   83,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yycheck[] =
#else
short yycheck[] =
#endif
	{                                      10,
   10,   10,   44,  259,  286,   10,  288,  286,  288,  288,
   10,  260,  261,  259,  296,  295,  296,  296,  267,  296,
  289,  296,  297,   10,  293,  296,  281,  282,  283,  284,
  281,  282,  283,  296,  296,  296,  296,   61,   10,   10,
  296,   10,   10,   10,   10,  123,  296,  285,  296,  262,
   10,  290,  275,  294,  296,  270,  296,   10,  270,  296,
  296,  272,  297,  297,  296,  273,  297,   10,   10,   10,
   48,   70,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  125,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  284,   -1,   -1,  256,   -1,  258,   -1,   -1,
   -1,   -1,  263,  264,  265,  260,  261,   -1,   -1,  270,
   -1,   -1,  267,  274,   -1,   -1,  275,   -1,  279,  280,
  275,   -1,   -1,   -1,   -1,  285,  287,  264,  265,  266,
   -1,  268,  269,   -1,  271,  296,   -1,   -1,   -1,  276,
  277,  278,  279,  280,   -1,   -1,   -1,   -1,   -1,   -1,
  287,
};
#define YYFINAL 1
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 297
#if YYDEBUG
#if defined(__cplusplus) || defined(__STDC__)
const char * const yyname[] =
#else
char *yyname[] =
#endif
	{
"end-of-file",0,0,0,0,0,0,0,0,0,"'\\n'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,"','",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'='",0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"ERROR",
"LISTEN","ON","TLS","LDAPS","PORT","NAMESPACE","ROOTDN","ROOTPW","INDEX",
"SECURE","RELAX","STRICT","SCHEMA","USE","COMPRESSION","LEVEL","INCLUDE",
"CERTIFICATE","FSYNC","CACHE_SIZE","INDEX_CACHE_SIZE","DENY","ALLOW","READ",
"WRITE","BIND","ACCESS","TO","ROOT","REFERRAL","ANY","CHILDREN","OF",
"ATTRIBUTE","IN","SUBTREE","BY","SELF","STRING","NUMBER",
};
#if defined(__cplusplus) || defined(__STDC__)
const char * const yyrule[] =
#else
char *yyrule[] =
#endif
	{"$accept : grammar",
"grammar :",
"grammar : grammar '\\n'",
"grammar : grammar include '\\n'",
"grammar : grammar varset '\\n'",
"grammar : grammar conf_main '\\n'",
"grammar : grammar error '\\n'",
"grammar : grammar namespace '\\n'",
"grammar : grammar aci '\\n'",
"grammar : grammar schema '\\n'",
"ssl :",
"ssl : TLS",
"ssl : LDAPS",
"ssl : SECURE",
"certname :",
"certname : CERTIFICATE STRING",
"port : PORT STRING",
"port : PORT NUMBER",
"port :",
"conf_main : LISTEN ON STRING port ssl certname",
"conf_main : REFERRAL STRING",
"conf_main : ROOTDN STRING",
"conf_main : ROOTPW STRING",
"$$1 :",
"namespace : NAMESPACE STRING '{' '\\n' $$1 ns_opts '}'",
"boolean : STRING",
"boolean : ON",
"ns_opts :",
"ns_opts : ns_opts '\\n'",
"ns_opts : ns_opts ns_opt '\\n'",
"ns_opt : ROOTDN STRING",
"ns_opt : ROOTPW STRING",
"ns_opt : INDEX STRING",
"ns_opt : CACHE_SIZE NUMBER",
"ns_opt : INDEX_CACHE_SIZE NUMBER",
"ns_opt : FSYNC boolean",
"ns_opt : aci",
"ns_opt : RELAX SCHEMA",
"ns_opt : STRICT SCHEMA",
"ns_opt : USE COMPRESSION comp_level",
"ns_opt : REFERRAL STRING",
"comp_level :",
"comp_level : LEVEL NUMBER",
"aci : aci_type aci_access TO aci_scope aci_target aci_subject",
"aci : aci_type aci_access",
"aci_type : DENY",
"aci_type : ALLOW",
"aci_access :",
"aci_access : ACCESS",
"aci_access : aci_rights ACCESS",
"aci_rights : aci_right",
"aci_rights : aci_rights ',' aci_right",
"aci_right : READ",
"aci_right : WRITE",
"aci_right : BIND",
"aci_scope :",
"aci_scope : SUBTREE",
"aci_scope : CHILDREN OF",
"aci_target : ANY",
"aci_target : ROOT",
"aci_target : STRING",
"aci_subject :",
"aci_subject : BY ANY",
"aci_subject : BY STRING",
"aci_subject : BY SELF",
"include : INCLUDE STRING",
"varset : STRING '=' STRING",
"schema : SCHEMA STRING",
};
#endif
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH 10000
#endif
#endif
#define YYINITSTACKSIZE 200
/* LINTUSED */
int yydebug;
int yynerrs;
int yyerrflag;
int yychar;
short *yyssp;
YYSTYPE *yyvsp;
YYSTYPE yyval;
YYSTYPE yylval;
short *yyss;
short *yysslim;
YYSTYPE *yyvs;
int yystacksize;
#line 376 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"

struct keywords {
	const char	*k_name;
	int		 k_val;
};

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;
	char		*nfmt;

	file->errors++;
	va_start(ap, fmt);
	if (asprintf(&nfmt, "%s:%d: %s", file->name, yylval.lineno, fmt) == -1)
		fatalx("yyerror asprintf");
	vlog(LOG_CRIT, nfmt, ap);
	va_end(ap);
	free(nfmt);
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
		{ "access",		ACCESS },
		{ "allow",		ALLOW },
		{ "any",		ANY },
		{ "bind",		BIND },
		{ "by",			BY },
		{ "cache-size",		CACHE_SIZE },
		{ "certificate",	CERTIFICATE },
		{ "children",		CHILDREN },
		{ "compression",	COMPRESSION },
		{ "deny",		DENY },
		{ "fsync",		FSYNC },
		{ "in",			IN },
		{ "include",		INCLUDE },
		{ "index",		INDEX },
		{ "index-cache-size",	INDEX_CACHE_SIZE },
		{ "ldaps",		LDAPS },
		{ "level",		LEVEL },
		{ "listen",		LISTEN },
		{ "namespace",		NAMESPACE },
		{ "of",			OF },
		{ "on",			ON },
		{ "port",		PORT },
		{ "read",		READ },
		{ "referral",		REFERRAL },
		{ "relax",		RELAX },
		{ "root",		ROOT },
		{ "rootdn",		ROOTDN },
		{ "rootpw",		ROOTPW },
		{ "schema",		SCHEMA },
		{ "secure",		SECURE },
		{ "self",		SELF },
		{ "strict",		STRICT },
		{ "subtree",		SUBTREE },
		{ "tls",		TLS },
		{ "to",			TO },
		{ "use",		USE },
		{ "write",		WRITE },

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
			yyerror("reached end of file while parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
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
		if (file == topfile || popfile() == EOF)
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
	char	 buf[4096];
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
				log_warnx("string too long");
				return (findeol());
			}
			*p++ = (char)c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			fatal("yylex: strdup");
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
	x != '{' && x != '}' && x != '<' && x != '>' && \
	x != '!' && x != '=' && x != '/' && x != '#' && \
	x != ','))

	if (isalnum(c) || c == ':' || c == '_' || c == '*') {
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
				fatal("yylex: strdup");
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
		log_warn("cannot stat %s", fname);
		return (-1);
	}
	if (st.st_uid != 0 && st.st_uid != getuid()) {
		log_warnx("%s: owner not root or current user", fname);
		return (-1);
	}
	if (st.st_mode & (S_IRWXG | S_IRWXO)) {
		log_warnx("%s: group/world readable/writeable", fname);
		return (-1);
	}
	return (0);
}

struct file *
pushfile(const char *name, int secret)
{
	struct file	*nfile;

	log_debug("parsing config %s", name);

	if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
		log_warn("malloc");
		return (NULL);
	}
	if ((nfile->name = strdup(name)) == NULL) {
		log_warn("malloc");
		free(nfile);
		return (NULL);
	}
	if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		log_warn("%s", nfile->name);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	if (secret &&
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

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
		prev->errors += file->errors;

	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file);
	file = prev;
	return (file ? 0 : EOF);
}

int
parse_config(char *filename)
{
	struct sym		*sym, *next;
	int			 errors = 0;

	if ((conf = calloc(1, sizeof(struct ldapd_config))) == NULL)
		fatal(NULL);

	conf->schema = schema_new();
	if (conf->schema == NULL)
		fatal("schema_new");

	TAILQ_INIT(&conf->namespaces);
	TAILQ_INIT(&conf->listeners);
	if ((conf->sc_ssl = calloc(1, sizeof(*conf->sc_ssl))) == NULL)
		fatal(NULL);
	SPLAY_INIT(conf->sc_ssl);
	SIMPLEQ_INIT(&conf->acl);
	SLIST_INIT(&conf->referrals);

	if ((file = pushfile(filename, 1)) == NULL) {
		free(conf);
		return (-1);
	}
	topfile = file;

	yyparse();
	errors = file->errors;
	popfile();

	/* Free macros and check which have not been used. */
	for (sym = TAILQ_FIRST(&symhead); sym != NULL; sym = next) {
		next = TAILQ_NEXT(sym, entry);
		log_debug("warning: macro \"%s\" not used", sym->nam);
		if (!sym->persist) {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}

	return (errors ? -1 : 0);
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
		fatal("cmdline_symset: malloc");

	strlcpy(sym, s, len);

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

struct listener *
host_unix(const char *path)
{
	struct sockaddr_un	*saun;
	struct listener		*h;

	if (*path != '/')
		return (NULL);

	if ((h = calloc(1, sizeof(*h))) == NULL)
		fatal(NULL);
	saun = (struct sockaddr_un *)&h->ss;
	saun->sun_len = sizeof(struct sockaddr_un);
	saun->sun_family = AF_UNIX;
	if (strlcpy(saun->sun_path, path, sizeof(saun->sun_path)) >=
	    sizeof(saun->sun_path))
		fatal("socket path too long");
	h->flags = F_SECURE;

	return (h);
}

struct listener *
host_v4(const char *s, in_port_t port)
{
	struct in_addr		 ina;
	struct sockaddr_in	*sain;
	struct listener		*h;

	bzero(&ina, sizeof(ina));
	if (inet_pton(AF_INET, s, &ina) != 1)
		return (NULL);

	if ((h = calloc(1, sizeof(*h))) == NULL)
		fatal(NULL);
	sain = (struct sockaddr_in *)&h->ss;
	sain->sin_len = sizeof(struct sockaddr_in);
	sain->sin_family = AF_INET;
	sain->sin_addr.s_addr = ina.s_addr;
	sain->sin_port = port;

	return (h);
}

struct listener *
host_v6(const char *s, in_port_t port)
{
	struct in6_addr		 ina6;
	struct sockaddr_in6	*sin6;
	struct listener		*h;

	bzero(&ina6, sizeof(ina6));
	if (inet_pton(AF_INET6, s, &ina6) != 1)
		return (NULL);

	if ((h = calloc(1, sizeof(*h))) == NULL)
		fatal(NULL);
	sin6 = (struct sockaddr_in6 *)&h->ss;
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = port;
	memcpy(&sin6->sin6_addr, &ina6, sizeof(ina6));

	return (h);
}

int
host_dns(const char *s, const char *cert,
    struct listenerlist *al, int max, in_port_t port, u_int8_t flags)
{
	struct addrinfo		 hints, *res0, *res;
	int			 error, cnt = 0;
	struct sockaddr_in	*sain;
	struct sockaddr_in6	*sin6;
	struct listener		*h;

	bzero(&hints, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM; /* DUMMY */
	error = getaddrinfo(s, NULL, &hints, &res0);
	if (error == EAI_AGAIN || error == EAI_NODATA || error == EAI_NONAME)
		return (0);
	if (error) {
		log_warnx("host_dns: could not parse \"%s\": %s", s,
		    gai_strerror(error));
		return (-1);
	}

	for (res = res0; res && cnt < max; res = res->ai_next) {
		if (res->ai_family != AF_INET &&
		    res->ai_family != AF_INET6)
			continue;
		if ((h = calloc(1, sizeof(*h))) == NULL)
			fatal(NULL);

		h->port = port;
		h->flags = flags;
		h->ss.ss_family = res->ai_family;
		h->ssl = NULL;
		h->ssl_cert_name[0] = '\0';
		if (cert != NULL)
			(void)strlcpy(h->ssl_cert_name, cert, sizeof(h->ssl_cert_name));

		if (res->ai_family == AF_INET) {
			sain = (struct sockaddr_in *)&h->ss;
			sain->sin_len = sizeof(struct sockaddr_in);
			sain->sin_addr.s_addr = ((struct sockaddr_in *)
			    res->ai_addr)->sin_addr.s_addr;
			sain->sin_port = port;
		} else {
			sin6 = (struct sockaddr_in6 *)&h->ss;
			sin6->sin6_len = sizeof(struct sockaddr_in6);
			memcpy(&sin6->sin6_addr, &((struct sockaddr_in6 *)
			    res->ai_addr)->sin6_addr, sizeof(struct in6_addr));
			sin6->sin6_port = port;
		}

		TAILQ_INSERT_HEAD(al, h, entry);
		cnt++;
	}
	if (cnt == max && res) {
		log_warnx("host_dns: %s resolves to more than %d hosts",
		    s, max);
	}
	freeaddrinfo(res0);
	return (cnt);
}

int
host(const char *s, const char *cert, struct listenerlist *al,
    int max, in_port_t port, u_int8_t flags)
{
	struct listener *h;

	/* Unix socket path? */
	h = host_unix(s);

	/* IPv4 address? */
	if (h == NULL)
		h = host_v4(s, port);

	/* IPv6 address? */
	if (h == NULL)
		h = host_v6(s, port);

	if (h != NULL) {
		h->port = port;
		h->flags |= flags;
		h->ssl = NULL;
		h->ssl_cert_name[0] = '\0';
		if (cert != NULL)
			strlcpy(h->ssl_cert_name, cert, sizeof(h->ssl_cert_name));

		TAILQ_INSERT_HEAD(al, h, entry);
		return (1);
	}

	return (host_dns(s, cert, al, max, port, flags));
}

int
interface(const char *s, const char *cert,
    struct listenerlist *al, int max, in_port_t port, u_int8_t flags)
{
	int			 ret = 0;
	struct ifaddrs		*ifap, *p;
	struct sockaddr_in	*sain;
	struct sockaddr_in6	*sin6;
	struct listener		*h;

	if (getifaddrs(&ifap) == -1)
		fatal("getifaddrs");

	for (p = ifap; p != NULL; p = p->ifa_next) {
		if (strcmp(s, p->ifa_name) != 0)
			continue;

		switch (p->ifa_addr->sa_family) {
		case AF_INET:
			if ((h = calloc(1, sizeof(*h))) == NULL)
				fatal(NULL);
			sain = (struct sockaddr_in *)&h->ss;
			*sain = *(struct sockaddr_in *)p->ifa_addr;
			sain->sin_len = sizeof(struct sockaddr_in);
			sain->sin_port = port;

			h->fd = -1;
			h->port = port;
			h->flags = flags;
			h->ssl = NULL;
			h->ssl_cert_name[0] = '\0';
			if (cert != NULL)
				(void)strlcpy(h->ssl_cert_name, cert, sizeof(h->ssl_cert_name));

			ret = 1;
			TAILQ_INSERT_HEAD(al, h, entry);

			break;

		case AF_INET6:
			if ((h = calloc(1, sizeof(*h))) == NULL)
				fatal(NULL);
			sin6 = (struct sockaddr_in6 *)&h->ss;
			*sin6 = *(struct sockaddr_in6 *)p->ifa_addr;
			sin6->sin6_len = sizeof(struct sockaddr_in6);
			sin6->sin6_port = port;

			h->fd = -1;
			h->port = port;
			h->flags = flags;
			h->ssl = NULL;
			h->ssl_cert_name[0] = '\0';
			if (cert != NULL)
				(void)strlcpy(h->ssl_cert_name, cert, sizeof(h->ssl_cert_name));

			ret = 1;
			TAILQ_INSERT_HEAD(al, h, entry);

			break;
		}
	}

	freeifaddrs(ifap);

	return ret;
}

static struct aci *
mk_aci(int type, int rights, enum scope scope, char *target, char *subject)
{
	struct aci	*aci;

	if ((aci = calloc(1, sizeof(*aci))) == NULL) {
		yyerror("calloc");
		return NULL;
	}
	aci->type = type;
	aci->rights = rights;
	aci->scope = scope;
	aci->target = target;
	aci->subject = subject;

	log_debug("%s %02X access to %s scope %d by %s",
	    aci->type == ACI_DENY ? "deny" : "allow",
	    aci->rights,
	    aci->target ?: "any",
	    aci->scope,
	    aci->subject ?: "any");

	return aci;
}

struct namespace *
namespace_new(const char *suffix)
{
	struct namespace		*ns;

	if ((ns = calloc(1, sizeof(*ns))) == NULL)
		return NULL;
	ns->suffix = strdup(suffix);
	ns->sync = 1;
	ns->cache_size = 1024;
	ns->index_cache_size = 512;
	if (ns->suffix == NULL) {
		free(ns->suffix);
		free(ns);
		return NULL;
	}
	TAILQ_INIT(&ns->indices);
	TAILQ_INIT(&ns->request_queue);
	SIMPLEQ_INIT(&ns->acl);
	SLIST_INIT(&ns->referrals);

	return ns;
}

#line 1178 "y.tab.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
#if defined(__cplusplus) || defined(__STDC__)
static int yygrowstack(void)
#else
static int yygrowstack()
#endif
{
    int newsize, i;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;
    i = yyssp - yyss;
#ifdef SIZE_MAX
#define YY_SIZE_MAX SIZE_MAX
#else
#define YY_SIZE_MAX 0xffffffffU
#endif
    if (newsize && YY_SIZE_MAX / newsize < sizeof *newss)
        goto bail;
    newss = yyss ? (short *)realloc(yyss, newsize * sizeof *newss) :
      (short *)malloc(newsize * sizeof *newss); /* overflow check above */
    if (newss == NULL)
        goto bail;
    yyss = newss;
    yyssp = newss + i;
    if (newsize && YY_SIZE_MAX / newsize < sizeof *newvs)
        goto bail;
    newvs = yyvs ? (YYSTYPE *)realloc(yyvs, newsize * sizeof *newvs) :
      (YYSTYPE *)malloc(newsize * sizeof *newvs); /* overflow check above */
    if (newvs == NULL)
        goto bail;
    yyvs = newvs;
    yyvsp = newvs + i;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
bail:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return -1;
}

#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab
int
#if defined(__cplusplus) || defined(__STDC__)
yyparse(void)
#else
yyparse()
#endif
{
    int yym, yyn, yystate;
#if YYDEBUG
#if defined(__cplusplus) || defined(__STDC__)
    const char *yys;
#else /* !(defined(__cplusplus) || defined(__STDC__)) */
    char *yys;
#endif /* !(defined(__cplusplus) || defined(__STDC__)) */

    if ((yys = getenv("YYDEBUG")))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif /* YYDEBUG */

    yynerrs = 0;
    yyerrflag = 0;
    yychar = (-1);

    if (yyss == NULL && yygrowstack()) goto yyoverflow;
    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yyssp >= yysslim && yygrowstack())
        {
            goto yyoverflow;
        }
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
        yychar = (-1);
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;
#if defined(lint) || defined(__GNUC__)
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#if defined(lint) || defined(__GNUC__)
    goto yyerrlab;
#endif
yyerrlab:
    ++yynerrs;
yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yysslim && yygrowstack())
                {
                    goto yyoverflow;
                }
                *++yyssp = yystate = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = (-1);
        goto yyloop;
    }
yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    if (yym)
        yyval = yyvsp[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);
    switch (yyn)
    {
case 6:
#line 127 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ file->errors++; }
break;
case 8:
#line 129 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{
			SIMPLEQ_INSERT_TAIL(&conf->acl, yyvsp[-1].v.aci, entry);
		}
break;
case 10:
#line 135 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.number = 0; }
break;
case 11:
#line 136 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.number = F_STARTTLS; }
break;
case 12:
#line 137 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.number = F_LDAPS; }
break;
case 13:
#line 138 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.number = F_SECURE; }
break;
case 14:
#line 141 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.string = NULL; }
break;
case 15:
#line 142 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.string = yyvsp[0].v.string; }
break;
case 16:
#line 145 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{
			struct servent	*servent;

			servent = getservbyname(yyvsp[0].v.string, "tcp");
			if (servent == NULL) {
				yyerror("port %s is invalid", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			yyval.v.number = servent->s_port;
			free(yyvsp[0].v.string);
		}
break;
case 17:
#line 157 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{
			if (yyvsp[0].v.number <= 0 || yyvsp[0].v.number >= (int)USHRT_MAX) {
				yyerror("invalid port: %lld", yyvsp[0].v.number);
				YYERROR;
			}
			yyval.v.number = htons(yyvsp[0].v.number);
		}
break;
case 18:
#line 164 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{
			yyval.v.number = 0;
		}
break;
case 19:
#line 169 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{
			char			*cert;

			if (yyvsp[-2].v.number == 0) {
				if (yyvsp[-1].v.number == F_LDAPS)
					yyvsp[-2].v.number = htons(LDAPS_PORT);
				else
					yyvsp[-2].v.number = htons(LDAP_PORT);
			}

			cert = (yyvsp[0].v.string != NULL) ? yyvsp[0].v.string : yyvsp[-3].v.string;

			if ((yyvsp[-1].v.number == F_STARTTLS || yyvsp[-1].v.number == F_LDAPS) &&
			    ssl_load_certfile(conf, cert, F_SCERT) < 0) {
				yyerror("cannot load certificate: %s", cert);
				free(yyvsp[0].v.string);
				free(yyvsp[-3].v.string);
				YYERROR;
			}

			if (! interface(yyvsp[-3].v.string, cert, &conf->listeners,
				MAX_LISTEN, yyvsp[-2].v.number, yyvsp[-1].v.number)) {
				if (host(yyvsp[-3].v.string, cert, &conf->listeners,
					MAX_LISTEN, yyvsp[-2].v.number, yyvsp[-1].v.number) <= 0) {
					yyerror("invalid virtual ip or interface: %s", yyvsp[-3].v.string);
					free(yyvsp[0].v.string);
					free(yyvsp[-3].v.string);
					YYERROR;
				}
			}
			free(yyvsp[0].v.string);
			free(yyvsp[-3].v.string);
		}
break;
case 20:
#line 202 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{
			struct referral	*ref;
			if ((ref = calloc(1, sizeof(*ref))) == NULL) {
				yyerror("calloc");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			ref->url = yyvsp[0].v.string;
			SLIST_INSERT_HEAD(&conf->referrals, ref, next);
		}
break;
case 21:
#line 212 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{
			conf->rootdn = yyvsp[0].v.string;
			normalize_dn(conf->rootdn);
		}
break;
case 22:
#line 216 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ conf->rootpw = yyvsp[0].v.string; }
break;
case 23:
#line 219 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{
			log_debug("parsing namespace %s", yyvsp[-2].v.string);
			current_ns = namespace_new(yyvsp[-2].v.string);
			free(yyvsp[-2].v.string);
			TAILQ_INSERT_TAIL(&conf->namespaces, current_ns, next);
		}
break;
case 24:
#line 224 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ current_ns = NULL; }
break;
case 25:
#line 227 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{
			if (strcasecmp(yyvsp[0].v.string, "true") == 0 ||
			    strcasecmp(yyvsp[0].v.string, "yes") == 0)
				yyval.v.number = 1;
			else if (strcasecmp(yyvsp[0].v.string, "false") == 0 ||
			    strcasecmp(yyvsp[0].v.string, "off") == 0 ||
			    strcasecmp(yyvsp[0].v.string, "no") == 0)
				yyval.v.number = 0;
			else {
				yyerror("invalid boolean value '%s'", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 26:
#line 242 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.number = 1; }
break;
case 30:
#line 250 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{
			current_ns->rootdn = yyvsp[0].v.string;
			normalize_dn(current_ns->rootdn);
		}
break;
case 31:
#line 254 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ current_ns->rootpw = yyvsp[0].v.string; }
break;
case 32:
#line 255 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{
			struct attr_index	*ai;
			if ((ai = calloc(1, sizeof(*ai))) == NULL) {
				yyerror("calloc");
                                free(yyvsp[0].v.string);
				YYERROR;
			}
			ai->attr = yyvsp[0].v.string;
			ai->type = INDEX_EQUAL;
			TAILQ_INSERT_TAIL(&current_ns->indices, ai, next);
		}
break;
case 33:
#line 266 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ current_ns->cache_size = yyvsp[0].v.number; }
break;
case 34:
#line 267 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ current_ns->index_cache_size = yyvsp[0].v.number; }
break;
case 35:
#line 268 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ current_ns->sync = yyvsp[0].v.number; }
break;
case 36:
#line 269 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{
			SIMPLEQ_INSERT_TAIL(&current_ns->acl, yyvsp[0].v.aci, entry);
		}
break;
case 37:
#line 272 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ current_ns->relax = 1; }
break;
case 38:
#line 273 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ current_ns->relax = 0; }
break;
case 39:
#line 274 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ current_ns->compression_level = yyvsp[0].v.number; }
break;
case 40:
#line 275 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{
			struct referral	*ref;
			if ((ref = calloc(1, sizeof(*ref))) == NULL) {
				yyerror("calloc");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			ref->url = yyvsp[0].v.string;
			SLIST_INSERT_HEAD(&current_ns->referrals, ref, next);
		}
break;
case 41:
#line 287 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.number = 6; }
break;
case 42:
#line 288 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.number = yyvsp[0].v.number; }
break;
case 43:
#line 291 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{
			if ((yyval.v.aci = mk_aci(yyvsp[-5].v.number, yyvsp[-4].v.number, yyvsp[-2].v.number, yyvsp[-1].v.string, yyvsp[0].v.string)) == NULL) {
				free(yyvsp[-1].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
		}
break;
case 44:
#line 298 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{
			if ((yyval.v.aci = mk_aci(yyvsp[-1].v.number, yyvsp[0].v.number, LDAP_SCOPE_SUBTREE, NULL,
			    NULL)) == NULL) {
				YYERROR;
			}
		}
break;
case 45:
#line 306 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.number = ACI_DENY; }
break;
case 46:
#line 307 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.number = ACI_ALLOW; }
break;
case 47:
#line 310 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.number = ACI_ALL; }
break;
case 48:
#line 311 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.number = ACI_ALL; }
break;
case 49:
#line 312 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.number = yyvsp[-1].v.number; }
break;
case 50:
#line 315 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.number = yyvsp[0].v.number; }
break;
case 51:
#line 316 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.number = yyvsp[-2].v.number | yyvsp[0].v.number; }
break;
case 52:
#line 319 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.number = ACI_READ; }
break;
case 53:
#line 320 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.number = ACI_WRITE; }
break;
case 54:
#line 321 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.number = ACI_BIND; }
break;
case 55:
#line 325 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.number = LDAP_SCOPE_BASE; }
break;
case 56:
#line 326 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.number = LDAP_SCOPE_SUBTREE; }
break;
case 57:
#line 327 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.number = LDAP_SCOPE_ONELEVEL; }
break;
case 58:
#line 330 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.string = NULL; }
break;
case 59:
#line 331 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.string = strdup(""); }
break;
case 60:
#line 332 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.string = yyvsp[0].v.string; normalize_dn(yyval.v.string); }
break;
case 61:
#line 335 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.string = NULL; }
break;
case 62:
#line 336 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.string = NULL; }
break;
case 63:
#line 337 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.string = yyvsp[0].v.string; normalize_dn(yyval.v.string); }
break;
case 64:
#line 338 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{ yyval.v.string = strdup("@"); }
break;
case 65:
#line 341 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{
			struct file	*nfile;

			if ((nfile = pushfile(yyvsp[0].v.string, 1)) == NULL) {
				yyerror("failed to include file %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);

			file = nfile;
			lungetc('\n');
		}
break;
case 66:
#line 356 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{
			if (symset(yyvsp[-2].v.string, yyvsp[0].v.string, 0) == -1)
				fatal("cannot store variable");
			free(yyvsp[-2].v.string);
			free(yyvsp[0].v.string);
		}
break;
case 67:
#line 364 "/home/zyon/devel/openbsd/src/usr.sbin/ifconfigdctl/../ldapd/parse.y"
{
			int	 ret;

			ret = schema_parse(conf->schema, yyvsp[0].v.string);
			free(yyvsp[0].v.string);
			if (ret != 0) {
				YYERROR;
			}
		}
break;
#line 1755 "y.tab.c"
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yyssp, yystate);
#endif
    if (yyssp >= yysslim && yygrowstack())
    {
        goto yyoverflow;
    }
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;
yyoverflow:
    yyerror("yacc stack overflow");
yyabort:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return (1);
yyaccept:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return (0);
}
