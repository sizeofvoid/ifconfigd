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
#line 30 "parse.y"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <net/pfvar.h>
#include <arpa/inet.h>
#include <altq/altq.h>
#include <altq/altq_cbq.h>
#include <altq/altq_priq.h>
#include <altq/altq_hfsc.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <err.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <md5.h>

#include "pfctl_parser.h"
#include "pfctl.h"

static struct pfctl	*pf = NULL;
static int		 debug = 0;
static int		 rulestate = 0;
static u_int16_t	 returnicmpdefault =
			    (ICMP_UNREACH << 8) | ICMP_UNREACH_PORT;
static u_int16_t	 returnicmp6default =
			    (ICMP6_DST_UNREACH << 8) | ICMP6_DST_UNREACH_NOPORT;
static int		 blockpolicy = PFRULE_DROP;
static int		 require_order = 0;
static int		 default_statelock;

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
char		*symget(const char *);

int		 atoul(char *, u_long *);

enum {
	PFCTL_STATE_NONE,
	PFCTL_STATE_OPTION,
	PFCTL_STATE_QUEUE,
	PFCTL_STATE_NAT,
	PFCTL_STATE_FILTER
};

struct node_proto {
	u_int8_t		 proto;
	struct node_proto	*next;
	struct node_proto	*tail;
};

struct node_port {
	u_int16_t		 port[2];
	u_int8_t		 op;
	struct node_port	*next;
	struct node_port	*tail;
};

struct node_uid {
	uid_t			 uid[2];
	u_int8_t		 op;
	struct node_uid		*next;
	struct node_uid		*tail;
};

struct node_gid {
	gid_t			 gid[2];
	u_int8_t		 op;
	struct node_gid		*next;
	struct node_gid		*tail;
};

struct node_icmp {
	u_int8_t		 code;
	u_int8_t		 type;
	u_int8_t		 proto;
	struct node_icmp	*next;
	struct node_icmp	*tail;
};

enum	{ PF_STATE_OPT_MAX, PF_STATE_OPT_NOSYNC, PF_STATE_OPT_SRCTRACK,
	    PF_STATE_OPT_MAX_SRC_STATES, PF_STATE_OPT_MAX_SRC_CONN,
	    PF_STATE_OPT_MAX_SRC_CONN_RATE, PF_STATE_OPT_MAX_SRC_NODES,
	    PF_STATE_OPT_OVERLOAD, PF_STATE_OPT_STATELOCK,
	    PF_STATE_OPT_TIMEOUT, PF_STATE_OPT_SLOPPY,
	    PF_STATE_OPT_PFLOW };

enum	{ PF_SRCTRACK_NONE, PF_SRCTRACK, PF_SRCTRACK_GLOBAL, PF_SRCTRACK_RULE };

struct node_state_opt {
	int			 type;
	union {
		u_int32_t	 max_states;
		u_int32_t	 max_src_states;
		u_int32_t	 max_src_conn;
		struct {
			u_int32_t	limit;
			u_int32_t	seconds;
		}		 max_src_conn_rate;
		struct {
			u_int8_t	flush;
			char		tblname[PF_TABLE_NAME_SIZE];
		}		 overload;
		u_int32_t	 max_src_nodes;
		u_int8_t	 src_track;
		u_int32_t	 statelock;
		struct {
			int		number;
			u_int32_t	seconds;
		}		 timeout;
	}			 data;
	struct node_state_opt	*next;
	struct node_state_opt	*tail;
};

struct peer {
	struct node_host	*host;
	struct node_port	*port;
};

struct node_queue {
	char			 queue[PF_QNAME_SIZE];
	char			 parent[PF_QNAME_SIZE];
	char			 ifname[IFNAMSIZ];
	int			 scheduler;
	struct node_queue	*next;
	struct node_queue	*tail;
}	*queues = NULL;

struct node_qassign {
	char		*qname;
	char		*pqname;
};

struct range {
	int		 a;
	int		 b;
	int		 t;
};
struct redirection {
	struct node_host	*host;
	struct range		 rport;
};

struct pool_opts {
	int			 marker;
#define POM_TYPE		0x01
#define POM_STICKYADDRESS	0x02
	u_int8_t		 opts;
	int			 type;
	int			 staticport;
	struct pf_poolhashkey	*key;

} pool_opts;

struct redirspec {
	struct redirection      *rdr;
	struct pool_opts         pool_opts;
	int			 binat;
};

struct filter_opts {
	int			 marker;
#define FOM_FLAGS	0x0001
#define FOM_ICMP	0x0002
#define FOM_TOS		0x0004
#define FOM_KEEP	0x0008
#define FOM_SRCTRACK	0x0010
#define FOM_MINTTL	0x0020
#define FOM_MAXMSS	0x0040
#define FOM_SETTOS	0x0100
#define FOM_SCRUB_TCP	0x0200
	struct node_uid		*uid;
	struct node_gid		*gid;
	struct node_if		*rcv;
	struct {
		u_int8_t	 b1;
		u_int8_t	 b2;
		u_int16_t	 w;
		u_int16_t	 w2;
	} flags;
	struct node_icmp	*icmpspec;
	u_int32_t		 tos;
	u_int32_t		 prob;
	struct {
		int			 action;
		struct node_state_opt	*options;
	} keep;
	int			 fragment;
	int			 allowopts;
	char			*label;
	struct node_qassign	 queues;
	char			*tag;
	char			*match_tag;
	u_int8_t		 match_tag_not;
	u_int			 rtableid;
	struct {
		struct node_host	*addr;
		u_int16_t		port;
	}			 divert, divert_packet;
	struct redirspec	 nat;
	struct redirspec	 rdr;
	struct redirspec	 rroute;

	/* scrub opts */
	int			 nodf;
	int			 minttl;
	int			 settos;
	int			 randomid;
	int			 max_mss;

	/* route opts */
	struct {
		struct node_host	*host;
		u_int8_t		 rt;
		u_int8_t		 pool_opts;
		sa_family_t		 af;
		struct pf_poolhashkey	*key;
	}			 route;
} filter_opts;

struct antispoof_opts {
	char			*label;
	u_int			 rtableid;
} antispoof_opts;

struct scrub_opts {
	int			marker;
	int			nodf;
	int			minttl;
	int			maxmss;
	int			settos;
	int			randomid;
	int			reassemble_tcp;
} scrub_opts;

struct queue_opts {
	int			marker;
#define QOM_BWSPEC	0x01
#define QOM_SCHEDULER	0x02
#define QOM_PRIORITY	0x04
#define QOM_TBRSIZE	0x08
#define QOM_QLIMIT	0x10
	struct node_queue_bw	queue_bwspec;
	struct node_queue_opt	scheduler;
	int			priority;
	int			tbrsize;
	int			qlimit;
} queue_opts;

struct table_opts {
	int			flags;
	int			init_addr;
	struct node_tinithead	init_nodes;
} table_opts;

struct node_hfsc_opts	 hfsc_opts;
struct node_state_opt	*keep_state_defaults = NULL;

int		 disallow_table(struct node_host *, const char *);
int		 disallow_urpf_failed(struct node_host *, const char *);
int		 disallow_alias(struct node_host *, const char *);
int		 rule_consistent(struct pf_rule *, int);
int		 process_tabledef(char *, struct table_opts *);
void		 expand_label_str(char *, size_t, const char *, const char *);
void		 expand_label_if(const char *, char *, size_t, const char *);
void		 expand_label_addr(const char *, char *, size_t, u_int8_t,
		    struct node_host *);
void		 expand_label_port(const char *, char *, size_t,
		    struct node_port *);
void		 expand_label_proto(const char *, char *, size_t, u_int8_t);
void		 expand_label_nr(const char *, char *, size_t);
void		 expand_label(char *, size_t, const char *, u_int8_t,
		    struct node_host *, struct node_port *, struct node_host *,
		    struct node_port *, u_int8_t);
int		 collapse_redirspec(struct pf_pool *, struct pf_rule *,
		    struct redirspec *rs, u_int8_t);
int		 apply_redirspec(struct pf_pool *, struct pf_rule *,
		    struct redirspec *, int, struct node_port *);
void		 expand_rule(struct pf_rule *, int, struct node_if *,
		    struct redirspec *, struct redirspec *, struct redirspec *,
		    struct node_proto *,
		    struct node_os *, struct node_host *, struct node_port *,
		    struct node_host *, struct node_port *, struct node_uid *,
		    struct node_gid *, struct node_if *, struct node_icmp *,
		    const char *);
int		 expand_altq(struct pf_altq *, struct node_if *,
		    struct node_queue *, struct node_queue_bw bwspec,
		    struct node_queue_opt *);
int		 expand_queue(struct pf_altq *, struct node_if *,
		    struct node_queue *, struct node_queue_bw,
		    struct node_queue_opt *);
int		 expand_skip_interface(struct node_if *);

int	 check_rulestate(int);
int	 getservice(char *);
int	 rule_label(struct pf_rule *, char *);

void	 mv_rules(struct pf_ruleset *, struct pf_ruleset *);
void	 decide_address_family(struct node_host *, sa_family_t *);
int	 invalid_redirect(struct node_host *, sa_family_t);
u_int16_t parseicmpspec(char *, sa_family_t);
int	 kw_casecmp(const void *, const void *);
int	 map_tos(char *string, int *);

TAILQ_HEAD(loadanchorshead, loadanchors)
    loadanchorshead = TAILQ_HEAD_INITIALIZER(loadanchorshead);

struct loadanchors {
	TAILQ_ENTRY(loadanchors)	 entries;
	char				*anchorname;
	char				*filename;
};

typedef struct {
	union {
		int64_t			 number;
		double			 probability;
		int			 i;
		char			*string;
		u_int			 rtableid;
		struct {
			u_int8_t	 b1;
			u_int8_t	 b2;
			u_int16_t	 w;
			u_int16_t	 w2;
		}			 b;
		struct range		 range;
		struct node_if		*interface;
		struct node_proto	*proto;
		struct node_icmp	*icmp;
		struct node_host	*host;
		struct node_os		*os;
		struct node_port	*port;
		struct node_uid		*uid;
		struct node_gid		*gid;
		struct node_state_opt	*state_opt;
		struct peer		 peer;
		struct {
			struct peer	 src, dst;
			struct node_os	*src_os;
		}			 fromto;
		struct redirection	*redirection;
		struct {
			int			 action;
			struct node_state_opt	*options;
		}			 keep_state;
		struct {
			u_int8_t	 log;
			u_int8_t	 logif;
			u_int8_t	 quick;
		}			 logquick;
		struct {
			int		 neg;
			char		*name;
		}			 tagged;
		struct pf_poolhashkey	*hashkey;
		struct node_queue	*queue;
		struct node_queue_opt	 queue_options;
		struct node_queue_bw	 queue_bwspec;
		struct node_qassign	 qassign;
		struct filter_opts	 filter_opts;
		struct antispoof_opts	 antispoof_opts;
		struct queue_opts	 queue_opts;
		struct scrub_opts	 scrub_opts;
		struct table_opts	 table_opts;
		struct pool_opts	 pool_opts;
		struct node_hfsc_opts	 hfsc_opts;
	} v;
	int lineno;
} YYSTYPE;

#define PPORT_RANGE	1
#define PPORT_STAR	2
int	parseport(char *, struct range *r, int);

#define DYNIF_MULTIADDR(addr) ((addr).type == PF_ADDR_DYNIFTL && \
	(!((addr).iflags & PFI_AFLAG_NOALIAS) ||		 \
	!isdigit((addr).v.ifname[strlen((addr).v.ifname)-1])))

#line 435 "y.tab.c"
#define PASS 257
#define BLOCK 258
#define MATCH 259
#define SCRUB 260
#define RETURN 261
#define IN 262
#define OS 263
#define OUT 264
#define LOG 265
#define QUICK 266
#define ON 267
#define FROM 268
#define TO 269
#define FLAGS 270
#define RETURNRST 271
#define RETURNICMP 272
#define RETURNICMP6 273
#define PROTO 274
#define INET 275
#define INET6 276
#define ALL 277
#define ANY 278
#define ICMPTYPE 279
#define ICMP6TYPE 280
#define CODE 281
#define KEEP 282
#define MODULATE 283
#define STATE 284
#define PORT 285
#define BINATTO 286
#define NODF 287
#define MINTTL 288
#define ERROR 289
#define ALLOWOPTS 290
#define FASTROUTE 291
#define FILENAME 292
#define ROUTETO 293
#define DUPTO 294
#define REPLYTO 295
#define NO 296
#define LABEL 297
#define NOROUTE 298
#define URPFFAILED 299
#define FRAGMENT 300
#define USER 301
#define GROUP 302
#define MAXMSS 303
#define MAXIMUM 304
#define TTL 305
#define TOS 306
#define DROP 307
#define TABLE 308
#define REASSEMBLE 309
#define ANCHOR 310
#define SET 311
#define OPTIMIZATION 312
#define TIMEOUT 313
#define LIMIT 314
#define LOGINTERFACE 315
#define BLOCKPOLICY 316
#define RANDOMID 317
#define REQUIREORDER 318
#define SYNPROXY 319
#define FINGERPRINTS 320
#define NOSYNC 321
#define DEBUG 322
#define SKIP 323
#define HOSTID 324
#define ANTISPOOF 325
#define FOR 326
#define INCLUDE 327
#define MATCHES 328
#define BITMASK 329
#define RANDOM 330
#define SOURCEHASH 331
#define ROUNDROBIN 332
#define STATICPORT 333
#define PROBABILITY 334
#define ALTQ 335
#define CBQ 336
#define PRIQ 337
#define HFSC 338
#define BANDWIDTH 339
#define TBRSIZE 340
#define LINKSHARE 341
#define REALTIME 342
#define UPPERLIMIT 343
#define QUEUE 344
#define PRIORITY 345
#define QLIMIT 346
#define RTABLE 347
#define LOAD 348
#define RULESET_OPTIMIZATION 349
#define STICKYADDRESS 350
#define MAXSRCSTATES 351
#define MAXSRCNODES 352
#define SOURCETRACK 353
#define GLOBAL 354
#define RULE 355
#define MAXSRCCONN 356
#define MAXSRCCONNRATE 357
#define OVERLOAD 358
#define FLUSH 359
#define SLOPPY 360
#define PFLOW 361
#define TAGGED 362
#define TAG 363
#define IFBOUND 364
#define FLOATING 365
#define STATEPOLICY 366
#define STATEDEFAULTS 367
#define ROUTE 368
#define SETTOS 369
#define DIVERTTO 370
#define DIVERTREPLY 371
#define DIVERTPACKET 372
#define NATTO 373
#define RDRTO 374
#define RECEIVEDON 375
#define NE 376
#define LE 377
#define GE 378
#define STRING 379
#define NUMBER 380
#define PORTBINARY 381
#define YYERRCODE 256
#if defined(__cplusplus) || defined(__STDC__)
const short yylhs[] =
#else
short yylhs[] =
#endif
	{                                        -1,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  117,  127,  127,  127,  127,   17,
   13,   13,  118,  118,  118,  118,  118,  118,  118,  118,
  118,  118,  118,  118,  118,  118,  118,  118,  118,   69,
   69,   71,   71,   72,   72,   73,   73,  124,   70,   70,
  133,  133,  133,  133,  135,  134,  134,  120,  121,  136,
  108,  110,  110,  109,  109,  109,  109,  109,  109,  125,
   83,   83,   84,   84,   85,   85,  138,  102,  102,  104,
  104,  103,  103,   11,   11,  126,  139,  111,  111,  113,
  113,  112,  112,  112,  112,  122,  123,  140,  105,  105,
  107,  107,  106,  106,  106,  106,  106,   98,   98,   90,
   90,   90,   90,   90,   90,   91,   91,   92,   93,   93,
   94,  141,   97,   95,   95,   96,   96,   96,   96,   96,
   96,   96,   87,   87,   87,   88,   88,   89,  119,  142,
   99,   99,  101,  101,  100,  100,  100,  100,  100,  100,
  100,  100,  100,  100,  100,  100,  100,  100,  100,  100,
  100,  100,  100,  100,  100,  100,  100,  100,  100,  100,
   14,   14,   22,   22,   22,   25,   25,   25,   25,   25,
   25,   25,   25,   25,   25,   39,   39,   40,   40,   15,
   15,   15,   79,   79,   78,   78,   78,   78,   78,   80,
   80,   81,   81,   82,   82,   82,   82,   82,    1,    1,
    1,    2,    2,    3,    4,   16,   16,   16,   30,   30,
   30,   31,   31,   32,   33,   33,   41,   41,   55,   55,
   55,   56,   57,   57,   43,   43,   44,   44,   42,   42,
   42,  129,  129,   45,   45,   45,   49,   49,   46,   46,
   46,   47,   47,   47,   47,   47,   47,   47,   47,    5,
    5,   48,   58,   58,   59,   59,   60,   60,   60,   26,
   28,   61,   61,   62,   62,   63,   63,   63,    8,    8,
   64,   64,   65,   65,   66,   66,   66,    9,    9,   24,
   23,   23,   23,   34,   34,   34,   34,   35,   35,   37,
   37,   36,   36,   36,   38,   38,   38,    6,    6,    7,
    7,   10,   10,   18,   18,   18,   21,   21,   74,   74,
   74,   74,   19,   19,   19,   75,   75,   76,   76,   77,
   77,   77,   77,   77,   77,   77,   77,   77,   77,   77,
   77,   68,   86,   86,   86,   27,   51,   51,   50,   50,
   67,   67,   29,   29,  143,  114,  114,  116,  116,  115,
  115,  115,  115,  115,  115,   52,   52,   52,   52,   52,
   53,   53,   54,   54,  128,  130,  130,  131,  132,  132,
  137,  137,   12,   12,   20,   20,   20,   20,   20,   20,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yylen[] =
#else
short yylen[] =
#endif
	{                                         2,
    0,    3,    2,    3,    3,    3,    3,    3,    3,    3,
    3,    3,    4,    3,    2,    2,    3,    3,    3,    1,
    0,    1,    4,    3,    3,    3,    6,    3,    6,    3,
    3,    3,    3,    3,    3,    3,    3,    3,    3,    1,
    1,    2,    1,    2,    1,    1,    1,    3,    1,    0,
    0,    2,    3,    3,    0,    5,    0,   10,    5,    0,
    2,    3,    1,    1,    2,    2,    2,    2,    1,    5,
    2,    5,    2,    4,    1,    3,    0,    2,    0,    2,
    1,    2,    2,    1,    0,    5,    0,    2,    0,    2,
    1,    1,    3,    4,    2,    5,    5,    0,    2,    0,
    2,    1,    2,    2,    2,    1,    2,    1,    1,    1,
    4,    1,    4,    1,    4,    1,    3,    1,    1,    3,
    1,    0,    2,    1,    3,    2,    8,    2,    8,    2,
    8,    1,    0,    1,    4,    2,    4,    1,    8,    0,
    2,    0,    2,    1,    2,    2,    1,    1,    2,    1,
    1,    1,    2,    2,    2,    3,    2,    2,    4,    1,
    3,    4,    3,    3,    3,    1,    3,    3,    3,    2,
    1,    1,    1,    1,    2,    0,    1,    1,    5,    1,
    1,    4,    4,    6,    1,    1,    1,    1,    1,    0,
    1,    1,    0,    1,    0,    1,    1,    2,    2,    1,
    4,    1,    3,    1,    1,    1,    1,    2,    0,    2,
    5,    2,    4,    2,    1,    0,    1,    1,    0,    2,
    5,    2,    4,    1,    1,    1,    1,    3,    0,    2,
    5,    1,    2,    4,    0,    2,    0,    2,    1,    3,
    2,    2,    0,    1,    1,    4,    2,    4,    2,    2,
    2,    1,    3,    3,    3,    1,    3,    3,    2,    1,
    1,    3,    1,    4,    2,    4,    1,    2,    3,    1,
    1,    1,    4,    2,    4,    1,    2,    3,    1,    1,
    1,    4,    2,    4,    1,    2,    3,    1,    1,    1,
    4,    3,    2,    2,    5,    2,    5,    2,    4,    2,
    4,    1,    3,    3,    1,    3,    3,    1,    1,    1,
    1,    1,    1,    0,    1,    1,    1,    1,    2,    3,
    3,    3,    0,    1,    2,    3,    0,    1,    3,    2,
    1,    2,    2,    4,    5,    2,    2,    1,    1,    1,
    2,    1,    1,    3,    5,    1,    1,    4,    2,    4,
    1,    3,    0,    1,    0,    2,    0,    2,    1,    1,
    1,    2,    1,    1,    1,    1,    3,    3,    3,    4,
    2,    4,    1,    4,    2,    4,    2,    2,    4,    2,
    1,    0,    1,    1,    1,    1,    1,    1,    1,    1,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yydefred[] =
#else
short yydefred[] =
#endif
	{                                      0,
    0,    0,    0,    0,  173,    0,  174,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    3,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   16,
    0,    0,    0,   14,  185,    0,    0,    0,  177,  175,
    0,   49,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   15,    0,    0,    0,    0,    0,  191,  192,    0,
    2,    4,    5,    6,    7,    8,    9,   10,   11,   12,
   19,   13,   18,   17,    0,    0,    0,    0,    0,  383,
  384,    0,   24,    0,    0,   26,    0,    0,   28,   41,
   40,   30,   33,   32,   34,   35,   37,   38,  261,  260,
   31,    0,   25,   20,  317,  318,   36,    0,  331,    0,
    0,    0,    0,    0,    0,  339,  340,    0,  338,    0,
  328,    0,  199,    0,    0,  198,    0,   84,  210,    0,
    0,    0,    0,    0,   47,   46,   48,    0,    0,    0,
  186,  187,    0,  188,  189,    0,    0,  194,    0,   22,
   23,  375,    0,    0,  378,    0,   42,  330,  332,  336,
  315,  316,  337,  333,    0,    0,  341,  381,    0,    0,
  204,  206,  207,  205,    0,  202,  215,    0,    0,   75,
   71,  217,  218,    0,    0,  214,    0,    0,    0,    0,
    0,    0,    0,    0,  106,  102,    0,    0,    0,   44,
    0,    0,  182,    0,  183,   86,    0,    0,  242,    0,
    0,    0,    0,    0,    0,  329,  208,  201,    0,    0,
    0,   70,    0,    0,    0,  138,    0,   96,  134,    0,
    0,  122,  108,  109,  103,  107,  104,  105,  101,   97,
   59,    0,  179,    0,    0,   92,    0,   91,    0,    0,
  377,   27,    0,  380,   29,    0,  334,    0,  203,    0,
    0,   76,    0,    0,   81,    0,  211,    0,  212,    0,
  118,    0,  116,  121,    0,  119,    0,    0,    0,    0,
  184,   95,    0,   90,    0,    0,    0,    0,  335,   72,
    0,   73,  342,   82,   83,   80,    0,    0,    0,  111,
    0,  113,    0,  115,    0,    0,    0,  132,    0,  124,
  225,  226,    0,  220,  224,    0,  227,    0,    0,  244,
    0,   93,    0,    0,  245,    0,    0,  376,  379,  325,
    0,  213,  135,    0,  136,  117,  120,    0,  126,    0,
  128,    0,  130,    0,    0,    0,  236,    0,  139,    0,
    0,    0,    0,  250,  251,    0,    0,    0,    0,    0,
  249,    0,  247,   94,    0,    0,   74,    0,    0,    0,
    0,  125,    0,    0,  386,  387,  389,    0,  385,  388,
  390,    0,    0,  241,  263,  271,    0,    0,    0,    0,
    0,    0,    0,    0,  152,  166,    0,    0,    0,    0,
    0,  151,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  160,    0,    0,    0,    0,    0,  147,  148,  150,
  144,    0,  232,    0,  230,    0,  228,    0,  259,    0,
    0,    0,    0,    0,    0,    0,   55,   58,  137,    0,
    0,    0,  221,    0,  222,    0,  268,    0,  240,   60,
  293,  290,    0,    0,  308,  309,    0,    0,  294,  310,
  311,    0,    0,  296,    0,    0,    0,  347,    0,    0,
    0,    0,    0,    0,    0,  373,    0,    0,    0,  319,
  153,  279,  280,    0,    0,    0,  145,  272,  288,  289,
    0,    0,    0,  146,  281,  312,  313,  149,    0,  171,
  172,  157,  343,    0,  154,  158,  155,    0,    0,    0,
    0,  170,    0,  143,    0,  238,  246,  253,  254,  255,
  262,  258,  257,  248,    0,    0,    0,    0,    0,    0,
    0,  269,    0,    0,  292,    0,    0,    0,    0,    0,
    0,  320,  321,    0,    0,  165,    0,    0,    0,    0,
    0,    0,  167,  169,  168,    0,    0,  277,    0,    0,
  286,  322,    0,    0,  161,  163,  164,  156,    0,    0,
   51,    0,    0,    0,  223,  264,    0,  265,  162,   64,
    0,    0,    0,   69,    0,   63,    0,  291,    0,    0,
  303,  304,    0,    0,  306,  307,    0,    0,    0,  352,
  346,  360,  361,    0,  363,  364,  365,  359,    0,  367,
    0,    0,    0,  368,  369,    0,    0,  278,    0,    0,
  287,  344,    0,  159,  270,  233,  231,    0,    0,    0,
    0,    0,    0,   65,   66,   68,   67,    0,  295,    0,
  298,  297,    0,  300,  326,  349,  348,    0,  362,  354,
  358,  371,  374,    0,  370,  273,    0,  274,  282,    0,
  283,    0,    0,   52,   56,    0,    0,  127,  129,  131,
  266,   62,    0,    0,    0,    0,    0,    0,  345,  234,
   53,   54,  299,  301,  350,  372,  275,  284,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yydgoto[] =
#else
short yydgoto[] =
#endif
	{                                       2,
   64,  234,  139,  190,  111,  468,  473,  495,  502,  508,
  333,   92,  161,  512,   70,  194,  113,  173,  299,  392,
  129,   18,  428,  464,   40,  634,  610,  393,  659,  290,
  383,  324,  325,  429,  599,  469,  603,  474,  153,  156,
  328,  357,  329,  437,  334,  335,  478,  372,  336,  609,
  479,  486,  622,  487,  362,  435,  580,  394,  540,  395,
  497,  626,  498,  504,  629,  505,  480,  304,  102,   43,
  114,  147,  396,  430,  552,  130,  131,   60,  159,   61,
  185,  186,  135,  270,  191,  515,  238,  308,  239,  205,
  282,  283,  285,  286,  319,  320,  287,  245,  359,  431,
  432,  232,  275,  276,  141,  206,  207,  543,  596,  597,
  216,  258,  259,  556,  618,  619,   19,   20,   21,   22,
   23,   24,   25,   26,   27,   28,    3,   96,  164,  221,
   99,  223,  639,  448,  535,  544,  179,  233,  217,  142,
  288,  360,  557,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yysindex[] =
#else
short yysindex[] =
#endif
	{                                    -19,
    0,  540,   27,   53,    0,  588,    0,   65, -243, 1408,
  -33, -241,  -62, -157,  -86,  178,    0, -181,  234,  259,
  261,  283,  306,  315,  326,  370,  396,  407,  412,    0,
  417,  421,  428,    0,    0,  300,  402,  404,    0,    0,
   69,    0, -181, -214,   80,  -85,  -84, -215,  -65, -214,
   82,   88,  -62, -101,  111,  -60, 1220,  458,  238,  181,
  243,    0,   21,    0,  -62,  111,  -80,    0,    0,  -33,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  210,  -70,  -45,  449,  253,    0,
    0,  237,    0,  150,  536,    0,  182,  536,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  111,    0,    0,    0,    0,    0,  188,    0,  198,
  200,  -13,  202,  204,  504,    0,    0,  225,    0,  557,
    0,  420,    0,   -4,  179,    0,  536,    0,    0,  229,
  273,  641,    0,  354,    0,    0,    0,  -80,  -62,  245,
    0,    0,  175,    0,    0,  597,    0,    0,  -62,    0,
    0,    0,  536,  268,    0,  282,    0,    0,    0,    0,
    0,    0,    0,    0,  608,  294,    0,    0, 1220,  111,
    0,    0,    0,    0,  193,    0,    0,  536,  229,    0,
    0,    0,    0,    0,  635,    0,  -78,  636,  662,  671,
  149,  301,  340,  343,    0,    0,  641,  -78,  111,    0,
  179,  683,    0,  -45,    0,    0, -105,  179,    0,  536,
   44,  536,   54,  349,  666,    0,    0,    0,  420,   29,
  689,    0,  -82,   70,  536,    0,  536,    0,    0,  358,
  361,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  469,    0,  703,  366,    0,  536,    0, -105,  469,
    0,    0,  268,    0,    0,  282,    0,  401,    0,   74,
  536,    0,  388,  389,    0,  -82,    0,  635,    0,  395,
    0,  276,    0,    0,  289,    0,  727,  228, -112,  -47,
    0,    0,  481,    0,  -47,  536,  536,  422,    0,    0,
   29,    0,    0,    0,    0,    0,  536,   79,  536,    0,
  358,    0,  361,    0,    8,   15,   35,    0,  557,    0,
    0,    0,  536,    0,    0,   43,    0,    0,  515,    0,
  536,    0,  138,  536,    0,   83,    0,    0,    0,    0,
  536,    0,    0,  395,    0,    0,    0,  149,    0,  149,
    0,  149,    0,  228,  153,  711,    0,  492,    0, 4867,
  -73,  513,    9,    0,    0,  413,   63,  736,  415,  416,
    0,  744,    0,    0,    9,  678,    0,  536,  557,  557,
  557,    0,   93,  536,    0,    0,    0,  536,    0,    0,
    0,  -80,  424,    0,    0,    0,  711,  762,   18, -103,
  -99,  529,  530,   94,    0,    0,  -17,  -17,  -17,  532,
  388,    0,  719,  777,  159,  539,  173,   33,  437,  111,
  446,    0,  547,   94,   94,  229,  471,    0,    0,    0,
    0, 4867,    0,  536,    0,   43,    0,   98,    0,  461,
  472,  478,  800,  804,  488,  536,    0,    0,    0,  494,
  496,  497,    0,  153,    0,  704,    0,  -80,    0,    0,
    0,    0,  501,  834,    0,    0,  536,  601,    0,    0,
    0,  536,  605,    0,  847,  847,  536,    0,  604,    0,
  843,  536,  518,  520,  845,    0,    0,    0,    0,    0,
    0,    0,    0,  536,  512,  196,    0,    0,    0,    0,
  536,  521,  241,    0,    0,    0,    0,    0,  847,    0,
    0,    0,    0,  543,    0,    0,    0,  609, -101,    0,
    0,    0,  111,    0,  544,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  899,  557,  557,  557,  536,  101,
  536,    0,  874,  -97,    0,  501,  290,  299,  311,  330,
 1220,    0,    0,   71,  -80,    0,  514,  548,    6,  206,
  849,  546,    0,    0,    0,  844,  196,    0,  898,  241,
    0,    0,  408,  -80,    0,    0,    0,    0,  536,  104,
    0,  149,  149,  149,    0,    0,  704,    0,    0,    0,
  556,  567,  570,    0,  159,    0,  557,    0,  116,  536,
    0,    0,  123,  536,    0,    0,  482,  536,  124,    0,
    0,    0,    0,  111,    0,    0,    0,    0,  514,    0,
  536,  126,  909,    0,    0,  132,  536,    0,  133,  536,
    0,    0,  572,    0,    0,    0,    0,  544,  474,  911,
  920,  921,  536,    0,    0,    0,    0,  -97,    0,  290,
    0,    0,  311,    0,    0,    0,    0,   71,    0,    0,
    0,    0,    0,    6,    0,    0,  844,    0,    0,  898,
    0,  922,  536,    0,    0,  944,  946,    0,    0,    0,
    0,    0,  536,  536,  536,  536,  536,  536,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short yyrindex[] =
#else
short yyrindex[] =
#endif
	{                                      4,
    0,    0,    0,    0,    0, 1522,    0,    0, 1638,    0,
  639,    0,  780,    0,    0,    0,    0, 2127,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0, 1760, 1876, 2005,    0,    0,
    0,    0, 2243,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  954,    0,    0,    0,    0, 2372, 2494,    0,
 2610,    0,  587,  858,  517,    0,    0,    0,    0, 2842,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0, 2726,    0,
    0,  957,    0,    0,  589,    0,    0,  589,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0, 1406,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    3,    0,    0,    0,    0,    0,    0,    0,  293,
    0,    0,    0,    0,   49,    0,  -26,    0,    0,    0,
    0,    0,  533,    0,    0,    0,    0,  961, 3074,    0,
    0,    0,  335,    0,    0,    0,   -1,    0, 2958,    0,
    0,    0,   24,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  668,    0,    0,   37,    0,    0,
    0,    0,    0,  110,  587,    0,  964,  141,  221,  348,
    0,    0,    0,    0,    0,    0,    5,  964,    0,    0,
 3602,    0,    0,    0,    0,    0,    0, 3485,    0,  -34,
  610,  -34,  610,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  -14,  -28,    0,  589,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0, 3834,    0,    0,    0,    0,  870,    0,  966, 3718,
    0,    0,    0,    0,    0,    0,    0,   68,    0,   39,
   -9,    0,    0,    0,    0,  370,    0,  587,    0,    0,
    0,  610,    0,    0,  610,    0,    0,    0,    0, 4182,
    0,    0,  142,    0, 3950,  -34,  -34,  184,    0,    0,
    0,    0,    0,    0,    0,    0,  -28,  610,  -34,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  122,    0,
    0,    0,  338,    0,    0,  142,    0, 4770, 4281,    0,
  913,    0,    0,  988,    0,  915, 4379,    0,    0,    0,
   -9,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0, 4066,    0,  621,
    0, 4476,  142,    0,    0,    0,  333,    0,    0,    0,
    0,  456,    0,    0,  142,  974,    0,  -34,  611,  611,
  611,    0,  335,   89,    0,    0,    0,  963,    0,    0,
    0,    0,  638,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    7,    0,  589,    0,  142,    0,  915,    0,    0,
    0,    0,    0,    0,    0,  988,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  338, 1019,    0,    0,
    0,  338, 1140,    0, 4574, 4574,  215,    0, 3173, 3271,
 1263,   12,    0,    0,    0,    0, 3271, 3271, 3271,    0,
    0,    0,    0,  963,  760,    0,    0,    0,    0,    0,
  963,  881,    0,    0,    0,    0,    0,    0, 4574,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0, 3271,
 3271,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  335,  335,  335,   89, 1085,
  431,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  610,    0,    0,    0,    0,    0,  -34,  610,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   10,    0,  335,   89,
    0,    0,  335,   89,    0,    0, 1294,   55,  230,    0,
    0,    0,    0, 3368,    0,    0,    0,    0, 4673,    0,
  -32,   20,    0,    0,    0, 1085,  431,    0, 1085,  431,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  431,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  -34,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   89,   89,   55,  -32,  431,  431,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short yygindex[] =
#else
short yygindex[] =
#endif
	{                                      0,
   48,    0,  -95, -118,  473,    0,    0, -393, -382,  393,
  -42,  940,    0,    0,  951,   -8,    0,    0,    0,  246,
  941,    0,    0, -361,    0,    0,    0, -199,    0,  738,
    0, -281,    0,    0,    0, -491,    0, -496,    0,  785,
  707,  569,    0,    0, -286,    0, -228, -375,  640,    0,
    0, -529,    0,  146,    0, -498,    0,  622,    0, -431,
    0,    0, -505,    0,    0, -499,  148,  596,    0,    0,
  -63,  878,  -61,    0, -236,  476,  852,  952,    0,  975,
    0,  806,    0,    0,  -58,    0,  825,    0,  -94,    0,
    0,  726,    0,  728,    0,  690,    0,  753,  708,  615,
    0,    0,  773,    0,  916,  851,    0,    0,  419,    0,
    0,  805,    0,  154,  452,    0,    0,    0,   -3,   -2,
    0,    0,    0,    0,    0,    0,    0,  -74,  -96,    0,
 -137,    0,    0,    0,    0,    0, -127,    0,    0,    0,
    0,    0,    0,
};
#define YYTABLESIZE 5242
#if defined(__cplusplus) || defined(__STDC__)
const short yytable[] =
#else
short yytable[] =
#endif
	{                                      32,
   33,  166,  144,    1,  243,  148,  243,  243,   89,  243,
  323,  243,  314,    1,   99,  243,  141,  257,  382,  467,
  140,  196,  483,  472,  541,  214,  579,  243,  222,  621,
  243,  485,  485,  485,  243,  189,   30,   95,   98,  358,
  195,  138,  484,  314,  237,  483,  314,  348,  167,  434,
   61,  243,  604,  138,  350,  600,  243,  229,  216,  382,
  627,  100,   34,  243,  463,  484,  219,  243,  189,  630,
  231,  243,  514,  384,  352,  138,  243,  323,  382,  382,
   68,   90,   69,  243,  243,  243,  148,  178,  446,  220,
  243,  230,  243,  263,  243,  266,  243,  178,  243,  235,
  108,  545,  568,    1,  371,  482,  278,  440,  323,  441,
  369,  323,  143,  178,  243,  243,  227,  178,  188,   79,
  571,   87,  178,  261,   41,  264,  178,   99,  297,  141,
  370,  331,  243,  369,  686,   42,  178,   62,  279,  673,
  280,  178,  301,  137,  178,  251,  243,  178,  243,  358,
  110,   31,  140,  370,  311,  643,  684,  313,  683,  178,
  293,  687,  123,  101,   91,  331,  178,  178,  262,  178,
  688,  271,  539,  628,  302,  178,  178,  369,  265,  243,
  344,   85,  307,  485,  598,  309,  255,  631,  296,  590,
  591,  354,  457,  324,  277,  103,  211,  370,  300,  338,
  339,   85,  252,  343,   63,  592,  218,  374,  375,  260,
  342,  593,  345,  243,  273,  213,  477,  453,  178,  594,
  326,   65,  527,   66,  324,  586,  355,  324,  637,  327,
  112,   58,   59,  228,  363,  140,  178,  373,   67,  553,
  649,  104,  341,   71,  377,  369,  531,  652,  657,  378,
  663,  450,  451,  452,  243,  454,  666,  669,  542,    1,
    1,    1,    1,  110,  274,  370,  321,  322,   72,  382,
   73,  595,  572,  256,  243,  465,  466,  109,  110,  470,
  471,  449,   29,    5,    6,    7,  330,  455,  485,  382,
   87,  456,   74,   94,   97,  461,  382,  382,  145,  146,
  236,  243,   39,  115,  116,  433,  314,  522,  151,  152,
  375,    1,  382,    1,    1,   75,  310,  427,  382,  178,
  330,  243,  243,  314,   76,  608,  382,  356,    1,  312,
    1,  623,  178,  154,  155,   77,    9,  525,    1,   85,
  171,  172,  252,  112,  243,  216,  243,    1,   99,  534,
  243,    1,  243,  314,  314,  314,  517,  114,  314,  314,
  314,  481,  314,  314,  382,  252,  314,  314,   85,  243,
  547,  323,  252,  252,  187,  549,  252,   87,  382,   78,
  554,  314,    1,   99,  481,  559,  243,  244,  323,  427,
  243,  243,  252,  243,  244,  216,  462,  566,  382,  243,
  243,  243,  243,  243,  569,   79,   77,  187,  582,  583,
  584,  513,  587,  243,  244,  243,   80,  382,  323,  323,
  323,   81,  243,  323,  323,  323,   82,  323,  323,  685,
   83,  323,  323,  243,  243,  364,  365,   84,  366,   85,
   85,   86,  585,   87,  588,  633,  323,   88,  632,  367,
  368,  178,  638,  192,  193,  252,   77,  252,   93,  578,
  106,  366,  382,  382,  382,  256,  107,  243,  243,  648,
  114,  650,  367,  368,  243,  653,  110,  110,  110,  110,
  110,  658,  636,  674,  110,  110,  110,  324,  256,  112,
  243,  243,  243,  611,  664,  256,  256,  132,  667,  256,
  382,  670,   58,  651,  324,  366,  134,  654,  136,   85,
  157,  656,  635,  138,  150,  256,  367,  368,  158,  110,
   85,   85,  655,  160,  662,  178,  209,  243,  244,  162,
  668,  321,  322,  671,  324,  324,  324,  506,  507,  324,
  324,  324,  100,  324,  324,  163,  681,  324,  324,   17,
  660,  510,  511,  488,  489,  243,  112,  112,  112,  112,
  112,  165,  324,  176,  112,  112,  112,  168,  315,  316,
  317,  520,  521,  366,  492,  493,  690,  169,  256,  170,
  256,  174,  243,  175,  367,  368,  693,  694,  695,  696,
  697,  698,  252,  243,  243,  252,  382,  382,  675,  112,
  178,  252,  252,  331,  177,  332,  318,  187,  382,  382,
  252,  252,  252,  382,  252,  252,  197,  252,  252,  499,
  500,  209,  252,  252,  212,  252,  252,  252,  252,  252,
  252,  252,  252,  252,  252,  676,  677,  215,  252,  209,
  563,  564,  565,  382,  382,  382,   94,  267,  382,  382,
  382,  252,  382,  382,  224,  100,  382,  382,  496,  503,
   97,  252,  252,  252,  252,  252,  252,  138,  465,  466,
  267,  382,  225,  576,  577,  240,  252,  601,  602,  252,
  246,  267,  252,  114,  114,  114,  114,  114,  180,  470,
  471,  114,  114,  114,  252,  252,  181,  267,  267,  267,
  252,  241,  252,  252,  252,  252,  252,  252,  605,  606,
  242,  252,  252,  382,  382,  256,  243,  243,  256,  247,
  182,  183,  248,  253,  256,  256,  114,  268,  267,  272,
    5,    6,    7,  256,  256,  256,  281,  256,  256,  284,
  256,  256,  289,  291,  292,  256,  256,  184,  256,  256,
  256,  256,  256,  256,  256,  256,  256,  256,  330,  298,
  267,  256,  267,  390,  389,  391,  303,  314,  305,  276,
  390,  389,  391,  236,  256,  340,  397,  361,  390,  389,
  391,  436,  442,    9,  256,  256,  256,  256,  256,  256,
  445,  439,  276,  443,  444,    4,    5,    6,    7,  256,
  447,  460,  256,  276,  458,  256,  243,  243,  243,  243,
  243,  496,  475,  476,  503,  490,  516,  256,  256,  276,
  276,  276,  509,  256,  518,  256,  256,  256,  256,  256,
  256,  519,  523,  388,  256,  256,  390,  389,  391,  528,
  531,  494,  612,  613,  614,  615,  616,    8,   35,    9,
   10,  529,  209,  209,  209,  209,  209,  530,   36,   37,
   38,  209,  209,  617,   11,  532,   12,  533,   98,   98,
   98,   98,   98,  536,   13,  537,  538,   98,   98,  462,
  546,  548,  276,   14,  276,  550,  551,   15,  555,  558,
  285,  562,  567,  574,   39,  209,  560,  267,  561,  501,
  267,  570,  243,  390,  389,  391,  267,  267,  581,  243,
  624,  100,  496,  285,  589,  503,  267,  267,   16,  267,
  267,  573,  433,  267,  285,  625,  620,  267,  267,  243,
  267,  267,  267,  267,  267,  644,  382,  267,  267,  267,
  285,  285,  285,  267,  382,  243,  645,  382,  646,  665,
  672,  678,  243,  691,  382,  692,  267,  390,  389,  391,
  679,  680,  689,  209,  195,   85,   21,  243,  382,  382,
   45,  267,  243,  133,  382,   88,  198,  199,  200,  201,
  202,  267,   85,   57,  267,  203,  204,  647,  382,  105,
  382,  575,  243,   89,  243,  382,  117,  295,  254,  267,
  267,  337,  438,  285,  526,  285,  491,  267,  267,  267,
  267,  267,  267,  267,  267,  267,  267,  267,  459,  276,
  243,  149,  243,  243,  243,  210,  607,  243,  302,  276,
  226,  243,  250,  133,  269,  243,  346,  382,  276,  276,
  347,  276,  276,  382,  376,  276,  524,  243,  306,  276,
  276,  302,  276,  276,  276,  276,  276,  249,  208,  276,
  276,  276,  302,  294,    0,  276,  682,  349,  351,  353,
  661,    0,    0,    0,    0,    0,    0,    0,  276,  385,
  386,  387,  145,  146,    0,    0,  385,  386,  387,  145,
  146,    0,    0,  276,  385,  386,  387,  492,  493,    0,
  379,    0,  380,  276,  381,    0,  276,    0,    0,    0,
  243,    0,  243,    0,    0,  209,  209,  209,  209,  209,
    0,  276,  276,  209,  209,  209,    0,    0,    0,  276,
  276,  276,  276,  276,  276,  276,  276,  276,  276,  276,
  285,  302,    0,  302,  382,  382,  382,  243,    0,  305,
  285,    0,  385,  386,  387,  499,  500,    0,    0,  285,
  285,    0,  285,  285,    0,    0,  285,  243,  243,    0,
  285,  285,  305,  285,  285,  285,  285,  285,    0,    0,
  285,  285,  285,  305,    0,    0,  285,    0,    0,    0,
  243,    0,  382,   98,   98,   98,   98,   98,    0,  285,
    0,  100,   98,   98,    0,    0,    0,    0,    0,    0,
  243,  243,  382,  382,  285,    0,    0,    0,    0,  385,
  386,  387,  492,  493,  285,    0,    0,  285,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  243,    0,    0,
    0,    0,  285,  285,    0,    0,    0,    0,  243,  243,
  285,  285,  285,  285,  285,  285,  285,  285,  285,  285,
  285,    0,  305,    0,  305,  243,    0,    0,    0,    0,
    0,    0,  366,  385,  386,  387,  499,  500,  302,    0,
  243,    0,  382,    0,    0,  243,  243,    0,  302,    0,
    0,  243,  243,  382,  382,  366,    0,  302,  302,    0,
  302,  302,  366,    0,  302,    0,  366,    0,  302,  302,
    0,  302,  302,  302,  302,  302,    0,    0,  302,  302,
  302,    0,  366,    0,  302,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  640,  641,  642,  302,  243,  243,
  243,  243,  243,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  302,    0,    0,  243,    0,    0,    0,    0,
    0,    0,  302,    0,    0,  302,  243,  243,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  302,  302,    0,    0,    0,  366,    0,  366,  302,  302,
  302,  302,  302,  302,    0,    0,    0,  302,  302,  305,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  305,
    0,    0,    0,    0,    0,   43,    0,    0,  305,  305,
    0,  305,  305,    0,    0,  305,    0,    0,    0,  305,
  305,    0,  305,  305,  305,  305,  305,    0,   43,  305,
  305,  305,    0,    0,    0,  305,   43,    0,    0,   43,
    0,    0,    0,    0,    0,    0,    0,    0,  305,    0,
  382,  382,  382,  382,  382,    0,    0,    0,    0,    0,
    0,    0,    0,  305,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  305,    0,    0,  305,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  305,  305,    0,    0,    0,    0,    0,    0,  305,
  305,  305,  305,  305,  305,    0,    0,    0,  305,  305,
    0,    0,  366,  118,    0,    0,    0,    0,   43,    0,
    0,  176,  366,    0,    0,    0,    0,    0,    0,    0,
  119,  366,  366,    0,  366,  366,    0,    0,  366,    0,
    0,    0,  366,  366,  176,  366,  366,  366,  366,  366,
    0,    0,  366,  366,  366,    0,    0,    0,  366,    0,
  120,  121,  122,    0,    0,  123,  124,  125,    0,  126,
  127,  366,    0,  115,  116,    0,    0,    0,    0,    0,
    0,  366,  366,  366,  366,  366,  366,  382,  128,    0,
    0,    0,    0,    0,    0,    0,  366,    0,    0,  366,
    0,    0,  366,    0,  382,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  366,  366,    0,    0,    0,    0,
    0,    0,  366,  366,  366,  366,  366,  366,    0,    0,
    0,  366,    0,    0,  382,  382,  382,   50,    0,  382,
  382,  382,    0,  382,  382,    0,    0,  382,  382,    0,
    0,    0,    0,    0,    0,   43,    0,    0,    0,    0,
   50,    0,  382,   43,   43,   43,    0,    0,    0,    0,
    0,    0,   43,    0,   43,   43,    0,   43,   43,    0,
    0,   43,    0,    0,    0,   43,   43,    0,   43,   43,
   43,   43,   43,    0,    0,   43,   43,   43,    0,    0,
    0,   43,    0,    0,    0,    0,   44,    0,    0,   45,
   46,   47,   48,   49,   43,   50,    0,   51,    0,   52,
   53,   54,    0,   43,   43,   43,   43,   43,   43,   43,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   43,
    0,    0,   43,    0,    0,   43,   55,    0,    0,    0,
   50,    0,    0,    0,    0,    0,    0,   43,   43,  178,
    0,    0,    0,   56,   57,   43,   43,   43,   43,   43,
   43,  176,    0,  176,  176,  176,  176,  176,  176,  176,
  176,  176,  178,    0,    0,  176,  176,  176,  176,    0,
  176,  176,    0,  176,  176,    0,    0,  176,    0,    0,
    0,  176,  176,    0,  176,  176,  176,  176,  176,    0,
    0,  176,  176,  176,    0,    0,    0,  176,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  176,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  176,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  176,    0,    0,  176,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  176,  176,  180,    0,    0,    0,    0,
    0,  176,  176,  176,  176,  176,  176,   50,    0,   50,
   50,   50,    0,   50,   50,   50,   50,   50,  180,    0,
    0,   50,   50,   50,   50,    0,   50,   50,    0,   50,
   50,    0,    0,   50,    0,    0,    0,   50,   50,    0,
   50,   50,   50,   50,   50,    0,    0,   50,   50,   50,
    0,    0,    0,   50,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   50,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   50,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   50,    0,    0,   50,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   50,
   50,    0,    0,    0,    0,    0,    0,   50,   50,   50,
   50,   50,   50,    0,  181,    0,    0,    0,    0,  178,
    0,  178,  178,  178,  178,  178,  178,  178,  178,  178,
    0,    0,    0,  178,  178,  178,  178,  181,  178,  178,
    0,  178,  178,    0,    0,  178,    0,    0,    0,  178,
  178,    0,  178,  178,  178,  178,  178,    0,    0,  178,
  178,  178,    0,    0,    0,  178,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  178,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  178,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  178,    0,    0,  178,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  178,  178,    0,    0,    0,    0,    0,    0,  178,
  178,  178,  178,  178,  178,  180,  190,  180,  180,  180,
  180,  180,  180,  180,  180,  180,    0,    0,    0,  180,
  180,  180,  180,    0,  180,  180,    0,  180,  180,  190,
    0,  180,    0,    0,    0,  180,  180,    0,  180,  180,
  180,  180,  180,    0,    0,  180,  180,  180,    0,    0,
    0,  180,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  180,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  180,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  180,
    0,    0,  180,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  180,  180,    0,
    0,    0,    0,    0,    0,  180,  180,  180,  180,  180,
  180,    0,  190,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  181,    0,  181,  181,  181,  181,
  181,  181,  181,  181,  181,  190,    0,    0,  181,  181,
  181,  181,    0,  181,  181,    0,  181,  181,    0,    0,
  181,    0,    0,    0,  181,  181,    0,  181,  181,  181,
  181,  181,    0,    0,  181,  181,  181,    0,    0,    0,
  181,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  181,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  181,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  181,    0,
    0,  181,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  190,  181,  181,    0,    0,
    0,    0,    0,    0,  181,  181,  181,  181,  181,  181,
    0,  200,    0,    0,    0,    0,  190,    0,    0,  190,
    0,  190,  190,  190,  190,  190,  190,    0,    0,    0,
  190,  190,  190,  190,  200,  190,  190,    0,  190,  190,
    0,    0,  190,    0,    0,    0,  190,  190,    0,  190,
  190,  190,  190,  190,    0,    0,  190,  190,  190,    0,
    0,    0,  190,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  190,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  190,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  190,    0,    0,  190,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  190,  190,
    0,    0,    0,    0,    0,    0,  190,  190,  190,  190,
  190,  190,  190,  197,    0,  190,    0,    0,  190,  190,
  190,  190,  190,    0,    0,    0,  190,  190,  190,  190,
    0,  190,  190,    0,  190,  190,  197,    0,  190,    0,
    0,    0,  190,  190,    0,  190,  190,  190,  190,  190,
    0,    0,  190,  190,  190,    0,    0,    0,  190,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  190,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  190,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  190,    0,    0,  190,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  190,  190,    0,    0,    0,    0,
    0,    0,  190,  190,  190,  190,  190,  190,    0,  196,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  200,    0,    0,  200,    0,    0,  200,  200,  200,
  200,  200,  196,    0,    0,  200,  200,  200,  200,    0,
  200,  200,    0,  200,  200,    0,    0,  200,    0,    0,
    0,  200,  200,    0,  200,  200,  200,  200,  200,    0,
    0,  200,  200,  200,    0,    0,    0,  200,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  200,    0,    0,    0,    0,    0,    0,  200,    0,    0,
    0,    0,    0,    0,    0,  200,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  200,    0,    0,  200,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  200,  200,  193,    0,    0,    0,    0,
    0,  200,  200,  200,  200,  200,  200,    0,    0,    0,
    0,    0,    0,  197,    0,    0,  197,    0,  193,    0,
  197,  197,  197,  197,    0,    0,    0,  197,  197,  197,
  197,    0,  197,  197,    0,  197,  197,    0,    0,  197,
    0,    0,    0,  197,  197,    0,  197,  197,  197,  197,
  197,    0,    0,  197,  197,  197,    0,    0,    0,  197,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  197,    0,    0,    0,    0,    0,    0,  197,
    0,    0,    0,    0,    0,    0,    0,  197,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  197,    0,    0,
  197,    0,    0,    0,    0,    0,    0,    0,  193,    0,
    0,  195,    0,    0,    0,  197,  197,    0,    0,    0,
    0,    0,    0,  197,  197,  197,  197,  197,  197,  196,
    0,    0,  196,    0,  195,    0,  196,  196,  196,  196,
    0,    0,    0,  196,  196,  196,  196,    0,  196,  196,
    0,  196,  196,    0,    0,  196,    0,    0,    0,  196,
  196,    0,  196,  196,  196,  196,  196,    0,    0,  196,
  196,  196,    0,    0,    0,  196,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  196,    0,
    0,    0,    0,    0,    0,  196,    0,    0,    0,    0,
    0,    0,    0,  196,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  196,    0,    0,  196,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  209,    0,    0,
    0,  196,  196,    0,    0,    0,    0,    0,    0,  196,
  196,  196,  196,  196,  196,  193,    0,    0,  193,    0,
  209,    0,  193,  193,  193,  193,    0,    0,    0,  193,
  193,  193,  193,    0,  193,  193,    0,  193,  193,    0,
    0,  193,    0,    0,    0,  193,  193,    0,  193,  193,
  193,  193,  193,    0,    0,  193,  193,  193,    0,    0,
    0,  193,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  193,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  193,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  193,
    0,    0,  193,    0,    0,    0,    0,    0,    0,    0,
  209,    0,    0,  209,    0,    0,    0,  193,  193,    0,
    0,    0,    0,    0,    0,  193,  193,  193,  193,  193,
  193,  195,    0,    0,  195,    0,  209,    0,  195,  195,
  195,  195,    0,    0,    0,  195,  195,  195,  195,    0,
  195,  195,    0,  195,  195,    0,    0,  195,    0,    0,
    0,  195,  195,    0,  195,  195,  195,  195,  195,    0,
    0,  195,  195,  195,    0,    0,    0,  195,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  195,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  195,    0,    0,    0,    0,
    0,    0,  351,    0,    0,  195,    0,    0,  195,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  195,  195,  351,    0,    0,    0,    0,
    0,  195,  195,  195,  195,  195,  195,  209,    0,    0,
  209,    0,    0,    0,    0,  209,  209,  209,    0,    0,
    0,  209,  209,  209,  209,    0,  209,  209,    0,  209,
  209,    0,    0,  209,    0,    0,    0,  209,  209,    0,
  209,  209,  209,  209,  209,    0,    0,  209,  209,  209,
    0,    0,    0,  209,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  209,    0,    0,    0,
  357,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  209,    0,    0,    0,  351,    0,    0,    0,    0,
    0,  209,    0,  357,  209,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  209,
  209,    0,    0,    0,    0,    0,    0,  209,  209,  209,
  209,  209,  209,  209,    0,    0,  209,    0,    0,    0,
    0,  209,  209,  209,    0,    0,    0,  209,  209,  209,
  209,    0,  209,  209,    0,  209,  209,    0,    0,  209,
    0,    0,    0,  209,  209,    0,  209,  209,  209,  209,
  209,    0,    0,  209,  209,  209,    0,  353,    0,  209,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  209,  357,    0,    0,    0,    0,    0,    0,
  353,    0,    0,    0,    0,    0,    0,  209,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  209,    0,    0,
  209,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  351,    0,    0,  209,  209,    0,    0,    0,
    0,    0,  351,  209,  209,  209,  209,  209,  209,    0,
    0,  351,  351,    0,  351,  351,    0,    0,  351,    0,
    0,    0,  351,  351,    0,  351,  351,  351,  351,  351,
    0,    0,  351,  351,  351,    0,    0,    0,  351,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  353,  351,    0,    0,  216,    0,    0,    0,    0,    0,
    0,  351,  351,  351,  351,  351,  351,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  351,  216,    0,  351,
    0,    0,  351,    0,    0,    0,    0,    0,    0,    0,
  357,    0,    0,    0,  351,  351,    0,    0,    0,    0,
  357,    0,  351,  351,  351,  351,  351,  351,    0,  357,
  357,    0,  357,  357,    0,    0,  357,    0,    0,    0,
  357,  357,    0,  357,  357,  357,  357,  357,    0,    0,
  357,  357,  357,    0,    0,    0,  357,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  357,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  355,
  355,  355,  355,  355,  357,    0,    0,  216,    0,    0,
    0,  216,    0,    0,  357,    0,    0,  357,    0,    0,
  355,    0,    0,    0,    0,    0,    0,  353,    0,    0,
    0,    0,  357,  357,  216,    0,    0,  353,    0,    0,
  357,  357,  357,  357,  357,  357,  353,  353,    0,  353,
  353,    0,    0,  353,    0,    0,    0,  353,  353,    0,
  353,  353,  353,  353,  353,    0,    0,  353,  353,  353,
    0,    0,    0,  353,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  353,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  353,  353,  353,  353,
  353,  353,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  353,    0,    0,  353,    0,    0,  353,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  219,    0,  353,
  353,    0,    0,    0,    0,    0,    0,  353,  353,  353,
  353,  353,  353,    0,  216,    0,    0,  216,    0,    0,
  219,    0,  216,  216,  216,    0,    0,    0,  216,    0,
    0,  216,    0,  216,  216,    0,  216,  216,    0,    0,
  216,    0,    0,    0,  216,  216,    0,  216,  216,  216,
  216,  216,    0,    0,  216,  216,  216,    0,    0,    0,
  216,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  216,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  216,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  216,    0,
    0,  216,    0,    0,    0,    0,    0,    0,    0,    0,
  219,    0,    0,  219,    0,    0,  216,  216,    0,    0,
    0,    0,    0,    0,  216,  216,  216,  216,  216,  216,
    0,  216,    0,    0,  216,    0,  219,    0,    0,  216,
  216,  216,    0,    0,    0,  216,    0,    0,  216,    0,
  216,  216,    0,  216,  216,    0,    0,  216,    0,    0,
    0,  216,  216,    0,  216,  216,  216,  216,  216,    0,
    0,  216,  216,  216,    0,    0,    0,  216,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  216,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  216,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  216,    0,    0,  216,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  235,
    0,    0,    0,  216,  216,    0,    0,    0,    0,    0,
    0,  216,  216,  216,  216,  216,  216,  219,    0,    0,
  219,    0,  235,    0,    0,  219,  219,  219,    0,    0,
    0,    0,    0,    0,  219,    0,  219,  219,    0,  219,
  219,    0,    0,  219,    0,    0,    0,  219,  219,    0,
  219,  219,  219,  219,  219,    0,    0,  219,  219,  219,
    0,    0,    0,  219,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  219,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  219,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  219,    0,    0,  219,    0,    0,    0,    0,    0,
    0,    0,  235,    0,    0,  239,    0,    0,    0,  219,
  219,    0,    0,    0,    0,    0,    0,  219,  219,  219,
  219,  219,  219,  219,    0,    0,  219,    0,  239,    0,
    0,  219,  219,  219,    0,    0,    0,    0,    0,    0,
  219,    0,  219,  219,    0,  219,  219,    0,    0,  219,
    0,    0,    0,  219,  219,    0,  219,  219,  219,  219,
  219,    0,    0,  219,  219,  219,    0,    0,    0,  219,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  219,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  219,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  219,    0,    0,
  219,    0,    0,    0,    0,    0,    0,    0,  239,    0,
    0,  235,    0,    0,    0,  219,  219,    0,    0,    0,
    0,    0,    0,  219,  219,  219,  219,  219,  219,  235,
    0,    0,  235,    0,  235,    0,    0,    0,  235,  235,
    0,    0,    0,    0,    0,    0,    0,    0,  235,  235,
    0,  235,  235,    0,    0,  235,    0,    0,    0,  235,
  235,    0,  235,  235,  235,  235,  235,    0,    0,  235,
  235,  235,    0,    0,    0,  235,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  235,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  235,    0,    0,    0,    0,    0,    0,
  229,    0,    0,  235,    0,    0,  235,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  235,  235,  229,    0,    0,    0,    0,    0,  235,
  235,  235,  235,  235,  235,  239,    0,    0,  239,    0,
    0,    0,    0,    0,  239,  239,    0,    0,    0,    0,
    0,    0,    0,    0,  239,  239,    0,  239,  239,    0,
    0,  239,    0,    0,    0,  239,  239,    0,  239,  239,
  239,  239,  239,    0,    0,  239,  239,  239,    0,    0,
    0,  239,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  239,    0,    0,    0,  142,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  239,
    0,    0,    0,  229,    0,    0,    0,    0,    0,  239,
    0,  140,  239,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  239,  239,    0,
    0,    0,    0,    0,    0,  239,  239,  239,  239,  239,
  239,  235,    0,    0,  235,    0,    0,    0,    0,    0,
  235,  235,    0,    0,    0,    0,    0,    0,    0,    0,
  235,  235,    0,  235,  235,    0,    0,  235,    0,    0,
    0,  235,  235,    0,  235,  235,  235,  235,  235,    0,
    0,  235,  235,  235,    0,  237,    0,  235,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  235,  142,    0,    0,    0,    0,    0,    0,  237,    0,
    0,    0,    0,    0,    0,  235,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  235,    0,    0,  235,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  229,    0,    0,  235,  235,    0,    0,    0,    0,  229,
  229,  235,  235,  235,  235,  235,  235,    0,    0,  229,
  229,    0,  229,  229,    0,    0,  229,    0,    0,    0,
  229,  229,    0,  229,  229,  229,  229,  229,    0,    0,
  229,  229,  229,  327,    0,    0,  229,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  237,  229,
    0,    0,    0,    0,    0,    0,  327,    0,    0,    0,
    0,    0,    0,    0,  229,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  229,    0,    0,  229,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  140,    0,
    0,    0,  229,  229,    0,    0,    0,    0,  140,    0,
  229,  229,  229,  229,  229,  229,    0,  140,  140,    0,
  140,  140,    0,    0,  140,    0,    0,    0,  140,  140,
    0,  140,  140,  140,  140,  140,    0,    0,  140,  140,
  140,    0,  356,    0,  140,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  327,  140,    0,    0,
    0,    0,    0,    0,    0,  356,    0,    0,    0,    0,
    0,    0,  140,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  140,    0,    0,  140,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  237,    0,    0,    0,    0,
  140,  140,    0,    0,    0,  237,    0,    0,  140,  140,
  140,  140,  140,  140,  237,  237,    0,  237,  237,    0,
    0,  237,    0,    0,    0,  237,  237,    0,  237,  237,
  237,  237,  237,    0,    0,  237,  237,  237,    0,  142,
    0,  237,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  237,  356,    0,    0,    0,    0,
    0,    0,  140,    0,    0,    0,    0,    0,    0,  237,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  237,
    0,    0,  237,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  327,    0,    0,    0,  237,  237,    0,
    0,    0,    0,  327,    0,  237,  237,  237,  237,  237,
  237,    0,  327,  327,    0,  327,  327,    0,    0,  327,
    0,    0,    0,  327,  327,    0,  327,  327,  327,  327,
  327,    0,    0,  327,  327,  327,    0,    0,    0,  327,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  327,    0,    0,    0,    0,    0,    0,  138,
    0,    0,    0,    0,    0,    0,    0,  327,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  327,    0,    0,
  327,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  356,    0,    0,  327,  327,    0,    0,    0,
    0,    0,  356,  327,  327,  327,  327,  327,  327,    0,
    0,  356,  356,    0,  356,  356,    0,    0,  356,    0,
    0,    0,  356,  356,    0,  356,  356,  356,  356,  356,
    0,    0,  356,  356,  356,    0,    0,    0,  356,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  356,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  356,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  356,    0,    0,  356,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  140,
    0,    0,    0,    0,  356,  356,    0,    0,    0,  140,
    0,    0,  356,  356,  356,  356,  356,  356,  140,  140,
    0,  140,  140,    0,    0,  140,    0,    0,    0,  140,
  140,    0,  140,  140,  140,  140,  140,    0,    0,  140,
  140,  140,    0,    0,    0,  140,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  140,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  140,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  140,    0,    0,  140,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  398,    0,    0,    0,
    0,  140,  140,    0,    0,    0,  399,    0,    0,  140,
  140,  140,  140,  140,  140,  400,  401,    0,  402,  403,
    0,    0,  404,    0,    0,    0,  405,  406,    0,  407,
  408,  409,  410,  411,    0,    0,  412,  413,  414,    0,
    0,    0,  415,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  416,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  417,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  418,    0,    0,  419,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  420,
    0,    0,    0,    0,    0,    0,  421,  422,  423,  424,
  425,  426,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yycheck[] =
#else
short yycheck[] =
#endif
	{                                       3,
    3,   98,   66,    0,   33,   67,   33,   40,   10,   44,
  123,   44,   10,   10,   10,   44,   10,  123,   33,  123,
   63,  140,   40,  123,  456,  153,  525,   60,  166,  559,
   40,  407,  408,  409,   44,   40,   10,  123,  123,  326,
  137,   33,   60,   41,  123,   40,   44,   40,  112,  123,
   41,   40,  549,   33,   40,  547,   33,  185,   10,   40,
  566,  277,   10,   40,   47,   60,  163,   44,   40,  569,
  189,   60,   40,  355,   40,   33,   40,   10,   40,   60,
  262,  296,  264,   60,   61,   62,  148,   44,  375,  164,
  125,  188,  125,  221,   40,  223,  125,   44,   44,  195,
   53,  463,  496,  123,  333,  123,  234,   45,   41,   47,
   40,   44,   65,   44,   60,  125,  180,   44,  123,   10,
  503,  123,   44,  220,   60,  222,   44,  123,  266,  123,
   60,  123,   44,   40,  664,  379,   44,  379,  235,  638,
  237,   44,  270,  123,   44,  209,  123,   44,  125,  436,
   10,  125,  195,   60,  282,  587,  653,  285,  650,   44,
  257,  667,   41,  379,  379,  123,   44,   44,  125,   44,
  670,  230,  454,  567,  271,   44,   44,   40,  125,  125,
  308,   40,  278,  559,  546,  280,  292,  570,  263,  287,
  288,  319,  392,   10,  125,  261,  149,   60,  125,  296,
  297,   60,  211,  125,  267,  303,  159,  125,  336,  218,
  307,  309,  309,  125,  297,   41,  123,  125,   44,  317,
  268,  379,  125,  310,   41,  125,  323,   44,  125,  277,
   10,  265,  266,   41,  331,  278,   44,  334,   61,  476,
  125,  307,  301,   10,  341,   40,   41,  125,  125,  344,
  125,  379,  380,  381,   40,  383,  125,  125,  458,  256,
  257,  258,  259,  123,  347,   60,  379,  380,   10,   40,
   10,  369,  509,  379,   60,  379,  380,  379,  380,  379,
  380,  378,  256,  257,  258,  259,  278,  384,  664,   60,
  292,  388,   10,  379,  379,  278,  287,  288,  379,  380,
  379,  278,   10,  364,  365,  379,  304,  426,  379,  380,
  438,  308,  303,  310,  311,   10,   41,  360,  309,   44,
  278,  298,  299,  321,   10,  554,  317,  285,  325,   41,
  327,  560,   44,  379,  380,   10,  310,  434,  335,   40,
  354,  355,   10,  123,  379,  297,  379,  344,  344,  446,
  379,  348,  379,  351,  352,  353,  420,   10,  356,  357,
  358,  379,  360,  361,  379,   33,  364,  365,  362,  379,
  467,  304,   40,   41,  379,  472,   44,  379,  369,   10,
  477,  379,  379,  379,  379,  482,  379,  380,  321,  432,
  379,  368,   60,  379,  380,  347,  379,  494,  379,  376,
  377,  378,  379,  380,  501,   10,  297,  379,  536,  537,
  538,  379,  540,  379,  380,  379,   10,  379,  351,  352,
  353,   10,  368,  356,  357,  358,   10,  360,  361,  658,
   10,  364,  365,  379,  380,  298,  299,   10,  368,  298,
  299,   40,  539,   40,  541,  573,  379,  379,   41,  379,
  380,   44,  580,  275,  276,  123,  347,  125,  379,  523,
  379,  368,  341,  342,  343,   10,  379,  379,  380,  597,
  123,  599,  379,  380,   44,  603,  336,  337,  338,  339,
  340,  609,  579,   10,  344,  345,  346,  304,   33,  379,
   60,   61,   62,  555,  622,   40,   41,   40,  626,   44,
  379,  629,  265,  600,  321,  368,  326,  604,  266,  368,
   62,  608,  574,   33,  305,   60,  379,  380,  266,  379,
  379,  380,   41,  287,  621,   44,   10,  379,  380,  380,
  627,  379,  380,  630,  351,  352,  353,  379,  380,  356,
  357,  358,   10,  360,  361,   10,  643,  364,  365,   10,
  614,  379,  380,  408,  409,  125,  336,  337,  338,  339,
  340,  380,  379,   60,  344,  345,  346,  380,  341,  342,
  343,  424,  425,  368,  379,  380,  673,  380,  123,  380,
  125,  380,  368,  380,  379,  380,  683,  684,  685,  686,
  687,  688,  260,  379,  380,  263,  304,  368,  125,  379,
   44,  269,  270,  123,  380,  125,  379,  379,  379,  380,
  278,  279,  280,  321,  282,  283,  344,  285,  286,  379,
  380,  268,  290,  291,  380,  293,  294,  295,  296,  297,
  298,  299,  300,  301,  302,  639,  639,   41,  306,  123,
  487,  488,  489,  351,  352,  353,  379,   10,  356,  357,
  358,  319,  360,  361,   47,  123,  364,  365,  413,  414,
  379,  329,  330,  331,  332,  333,  334,   33,  379,  380,
   33,  379,  379,  520,  521,   40,  344,  379,  380,  347,
  380,   44,  350,  336,  337,  338,  339,  340,  269,  379,
  380,  344,  345,  346,  362,  363,  277,   60,   61,   62,
  368,   40,  370,  371,  372,  373,  374,  375,  379,  380,
   40,  379,  380,  379,  380,  260,  379,  380,  263,  380,
  301,  302,  380,   41,  269,  270,  379,   62,  380,   41,
  257,  258,  259,  278,  279,  280,  379,  282,  283,  379,
  285,  286,  274,   41,  379,  290,  291,  328,  293,  294,
  295,  296,  297,  298,  299,  300,  301,  302,  278,  359,
  123,  306,  125,   60,   61,   62,  379,   41,  380,   10,
   60,   61,   62,  379,  319,  354,  285,  263,   60,   61,
   62,  269,   47,  310,  329,  330,  331,  332,  333,  334,
   47,  379,   33,  379,  379,  256,  257,  258,  259,  344,
  123,   40,  347,   44,  381,  350,  376,  377,  378,  379,
  380,  566,  284,  284,  569,  284,  380,  362,  363,   60,
   61,   62,  284,  368,  379,  370,  371,  372,  373,  374,
  375,  285,  362,  123,  379,  380,   60,   61,   62,  379,
   41,  123,  329,  330,  331,  332,  333,  308,  261,  310,
  311,  380,  336,  337,  338,  339,  340,  380,  271,  272,
  273,  345,  346,  350,  325,   62,  327,  380,  336,  337,
  338,  339,  340,  380,  335,  380,  380,  345,  346,  379,
   47,  281,  123,  344,  125,  281,   40,  348,  285,   47,
   10,   47,  381,  285,  307,  379,  379,  260,  379,  123,
  263,  381,   33,   60,   61,   62,  269,  270,   10,   40,
   62,  379,  667,   33,   41,  670,  279,  280,  379,  282,
  283,  379,  379,  286,   44,  380,  379,  290,  291,   60,
  293,  294,  295,  296,  297,  380,  269,  300,  301,  302,
   60,   61,   62,  306,  277,   33,  380,   33,  379,   41,
  379,   41,   40,   10,   40,   10,  319,   60,   61,   62,
   41,   41,   41,   10,  326,  379,   10,  379,  301,  302,
   10,  334,   60,   10,   60,   10,  336,  337,  338,  339,
  340,  344,  362,   10,  347,  345,  346,  595,  379,   50,
  380,  519,  123,   43,  125,  328,   56,  260,  214,  362,
  363,  295,  363,  123,  436,  125,  411,  370,  371,  372,
  373,  374,  375,  376,  377,  378,  379,  380,  397,  260,
   33,   70,   60,   61,   62,  148,  551,   40,   10,  270,
  179,   44,  208,   59,  229,  123,  311,  123,  279,  280,
  313,  282,  283,  354,  337,  286,  432,   60,  276,  290,
  291,   33,  293,  294,  295,  296,  297,  207,  143,  300,
  301,  302,   44,  259,   -1,  306,  648,  315,  316,  317,
  619,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  319,  376,
  377,  378,  379,  380,   -1,   -1,  376,  377,  378,  379,
  380,   -1,   -1,  334,  376,  377,  378,  379,  380,   -1,
  348,   -1,  350,  344,  352,   -1,  347,   -1,   -1,   -1,
  123,   -1,  125,   -1,   -1,  336,  337,  338,  339,  340,
   -1,  362,  363,  344,  345,  346,   -1,   -1,   -1,  370,
  371,  372,  373,  374,  375,  376,  377,  378,  379,  380,
  260,  123,   -1,  125,   60,   61,   62,  278,   -1,   10,
  270,   -1,  376,  377,  378,  379,  380,   -1,   -1,  279,
  280,   -1,  282,  283,   -1,   -1,  286,  298,  299,   -1,
  290,  291,   33,  293,  294,  295,  296,  297,   -1,   -1,
  300,  301,  302,   44,   -1,   -1,  306,   -1,   -1,   -1,
  278,   -1,  278,  336,  337,  338,  339,  340,   -1,  319,
   -1,  344,  345,  346,   -1,   -1,   -1,   -1,   -1,   -1,
  298,  299,  298,  299,  334,   -1,   -1,   -1,   -1,  376,
  377,  378,  379,  380,  344,   -1,   -1,  347,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  368,   -1,   -1,
   -1,   -1,  362,  363,   -1,   -1,   -1,   -1,  379,  380,
  370,  371,  372,  373,  374,  375,  376,  377,  378,  379,
  380,   -1,  123,   -1,  125,  278,   -1,   -1,   -1,   -1,
   -1,   -1,   10,  376,  377,  378,  379,  380,  260,   -1,
  368,   -1,  368,   -1,   -1,  298,  299,   -1,  270,   -1,
   -1,  379,  380,  379,  380,   33,   -1,  279,  280,   -1,
  282,  283,   40,   -1,  286,   -1,   44,   -1,  290,  291,
   -1,  293,  294,  295,  296,  297,   -1,   -1,  300,  301,
  302,   -1,   60,   -1,  306,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  582,  583,  584,  319,  376,  377,
  378,  379,  380,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  334,   -1,   -1,  368,   -1,   -1,   -1,   -1,
   -1,   -1,  344,   -1,   -1,  347,  379,  380,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  362,  363,   -1,   -1,   -1,  123,   -1,  125,  370,  371,
  372,  373,  374,  375,   -1,   -1,   -1,  379,  380,  260,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  270,
   -1,   -1,   -1,   -1,   -1,   10,   -1,   -1,  279,  280,
   -1,  282,  283,   -1,   -1,  286,   -1,   -1,   -1,  290,
  291,   -1,  293,  294,  295,  296,  297,   -1,   33,  300,
  301,  302,   -1,   -1,   -1,  306,   41,   -1,   -1,   44,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  319,   -1,
  376,  377,  378,  379,  380,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  334,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  344,   -1,   -1,  347,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  362,  363,   -1,   -1,   -1,   -1,   -1,   -1,  370,
  371,  372,  373,  374,  375,   -1,   -1,   -1,  379,  380,
   -1,   -1,  260,  304,   -1,   -1,   -1,   -1,  123,   -1,
   -1,   10,  270,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  321,  279,  280,   -1,  282,  283,   -1,   -1,  286,   -1,
   -1,   -1,  290,  291,   33,  293,  294,  295,  296,  297,
   -1,   -1,  300,  301,  302,   -1,   -1,   -1,  306,   -1,
  351,  352,  353,   -1,   -1,  356,  357,  358,   -1,  360,
  361,  319,   -1,  364,  365,   -1,   -1,   -1,   -1,   -1,
   -1,  329,  330,  331,  332,  333,  334,  304,  379,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  344,   -1,   -1,  347,
   -1,   -1,  350,   -1,  321,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  362,  363,   -1,   -1,   -1,   -1,
   -1,   -1,  370,  371,  372,  373,  374,  375,   -1,   -1,
   -1,  379,   -1,   -1,  351,  352,  353,   10,   -1,  356,
  357,  358,   -1,  360,  361,   -1,   -1,  364,  365,   -1,
   -1,   -1,   -1,   -1,   -1,  260,   -1,   -1,   -1,   -1,
   33,   -1,  379,  268,  269,  270,   -1,   -1,   -1,   -1,
   -1,   -1,  277,   -1,  279,  280,   -1,  282,  283,   -1,
   -1,  286,   -1,   -1,   -1,  290,  291,   -1,  293,  294,
  295,  296,  297,   -1,   -1,  300,  301,  302,   -1,   -1,
   -1,  306,   -1,   -1,   -1,   -1,  309,   -1,   -1,  312,
  313,  314,  315,  316,  319,  318,   -1,  320,   -1,  322,
  323,  324,   -1,  328,  329,  330,  331,  332,  333,  334,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  344,
   -1,   -1,  347,   -1,   -1,  350,  349,   -1,   -1,   -1,
  123,   -1,   -1,   -1,   -1,   -1,   -1,  362,  363,   10,
   -1,   -1,   -1,  366,  367,  370,  371,  372,  373,  374,
  375,  260,   -1,  262,  263,  264,  265,  266,  267,  268,
  269,  270,   33,   -1,   -1,  274,  275,  276,  277,   -1,
  279,  280,   -1,  282,  283,   -1,   -1,  286,   -1,   -1,
   -1,  290,  291,   -1,  293,  294,  295,  296,  297,   -1,
   -1,  300,  301,  302,   -1,   -1,   -1,  306,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  319,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  334,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  344,   -1,   -1,  347,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  362,  363,   10,   -1,   -1,   -1,   -1,
   -1,  370,  371,  372,  373,  374,  375,  260,   -1,  262,
  263,  264,   -1,  266,  267,  268,  269,  270,   33,   -1,
   -1,  274,  275,  276,  277,   -1,  279,  280,   -1,  282,
  283,   -1,   -1,  286,   -1,   -1,   -1,  290,  291,   -1,
  293,  294,  295,  296,  297,   -1,   -1,  300,  301,  302,
   -1,   -1,   -1,  306,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  319,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  334,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  344,   -1,   -1,  347,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  362,
  363,   -1,   -1,   -1,   -1,   -1,   -1,  370,  371,  372,
  373,  374,  375,   -1,   10,   -1,   -1,   -1,   -1,  260,
   -1,  262,  263,  264,  265,  266,  267,  268,  269,  270,
   -1,   -1,   -1,  274,  275,  276,  277,   33,  279,  280,
   -1,  282,  283,   -1,   -1,  286,   -1,   -1,   -1,  290,
  291,   -1,  293,  294,  295,  296,  297,   -1,   -1,  300,
  301,  302,   -1,   -1,   -1,  306,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  319,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  334,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  344,   -1,   -1,  347,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  362,  363,   -1,   -1,   -1,   -1,   -1,   -1,  370,
  371,  372,  373,  374,  375,  260,   10,  262,  263,  264,
  265,  266,  267,  268,  269,  270,   -1,   -1,   -1,  274,
  275,  276,  277,   -1,  279,  280,   -1,  282,  283,   33,
   -1,  286,   -1,   -1,   -1,  290,  291,   -1,  293,  294,
  295,  296,  297,   -1,   -1,  300,  301,  302,   -1,   -1,
   -1,  306,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  319,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  334,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  344,
   -1,   -1,  347,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  362,  363,   -1,
   -1,   -1,   -1,   -1,   -1,  370,  371,  372,  373,  374,
  375,   -1,   10,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  260,   -1,  262,  263,  264,  265,
  266,  267,  268,  269,  270,   33,   -1,   -1,  274,  275,
  276,  277,   -1,  279,  280,   -1,  282,  283,   -1,   -1,
  286,   -1,   -1,   -1,  290,  291,   -1,  293,  294,  295,
  296,  297,   -1,   -1,  300,  301,  302,   -1,   -1,   -1,
  306,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  319,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  334,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  344,   -1,
   -1,  347,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  123,  362,  363,   -1,   -1,
   -1,   -1,   -1,   -1,  370,  371,  372,  373,  374,  375,
   -1,   10,   -1,   -1,   -1,   -1,  260,   -1,   -1,  263,
   -1,  265,  266,  267,  268,  269,  270,   -1,   -1,   -1,
  274,  275,  276,  277,   33,  279,  280,   -1,  282,  283,
   -1,   -1,  286,   -1,   -1,   -1,  290,  291,   -1,  293,
  294,  295,  296,  297,   -1,   -1,  300,  301,  302,   -1,
   -1,   -1,  306,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  319,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  334,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  344,   -1,   -1,  347,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  362,  363,
   -1,   -1,   -1,   -1,   -1,   -1,  370,  371,  372,  373,
  374,  375,  260,   10,   -1,  263,   -1,   -1,  266,  267,
  268,  269,  270,   -1,   -1,   -1,  274,  275,  276,  277,
   -1,  279,  280,   -1,  282,  283,   33,   -1,  286,   -1,
   -1,   -1,  290,  291,   -1,  293,  294,  295,  296,  297,
   -1,   -1,  300,  301,  302,   -1,   -1,   -1,  306,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  319,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  334,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  344,   -1,   -1,  347,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  362,  363,   -1,   -1,   -1,   -1,
   -1,   -1,  370,  371,  372,  373,  374,  375,   -1,   10,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  260,   -1,   -1,  263,   -1,   -1,  266,  267,  268,
  269,  270,   33,   -1,   -1,  274,  275,  276,  277,   -1,
  279,  280,   -1,  282,  283,   -1,   -1,  286,   -1,   -1,
   -1,  290,  291,   -1,  293,  294,  295,  296,  297,   -1,
   -1,  300,  301,  302,   -1,   -1,   -1,  306,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  319,   -1,   -1,   -1,   -1,   -1,   -1,  326,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  334,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  344,   -1,   -1,  347,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  362,  363,   10,   -1,   -1,   -1,   -1,
   -1,  370,  371,  372,  373,  374,  375,   -1,   -1,   -1,
   -1,   -1,   -1,  260,   -1,   -1,  263,   -1,   33,   -1,
  267,  268,  269,  270,   -1,   -1,   -1,  274,  275,  276,
  277,   -1,  279,  280,   -1,  282,  283,   -1,   -1,  286,
   -1,   -1,   -1,  290,  291,   -1,  293,  294,  295,  296,
  297,   -1,   -1,  300,  301,  302,   -1,   -1,   -1,  306,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  319,   -1,   -1,   -1,   -1,   -1,   -1,  326,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  334,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  344,   -1,   -1,
  347,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  123,   -1,
   -1,   10,   -1,   -1,   -1,  362,  363,   -1,   -1,   -1,
   -1,   -1,   -1,  370,  371,  372,  373,  374,  375,  260,
   -1,   -1,  263,   -1,   33,   -1,  267,  268,  269,  270,
   -1,   -1,   -1,  274,  275,  276,  277,   -1,  279,  280,
   -1,  282,  283,   -1,   -1,  286,   -1,   -1,   -1,  290,
  291,   -1,  293,  294,  295,  296,  297,   -1,   -1,  300,
  301,  302,   -1,   -1,   -1,  306,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  319,   -1,
   -1,   -1,   -1,   -1,   -1,  326,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  334,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  344,   -1,   -1,  347,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   10,   -1,   -1,
   -1,  362,  363,   -1,   -1,   -1,   -1,   -1,   -1,  370,
  371,  372,  373,  374,  375,  260,   -1,   -1,  263,   -1,
   33,   -1,  267,  268,  269,  270,   -1,   -1,   -1,  274,
  275,  276,  277,   -1,  279,  280,   -1,  282,  283,   -1,
   -1,  286,   -1,   -1,   -1,  290,  291,   -1,  293,  294,
  295,  296,  297,   -1,   -1,  300,  301,  302,   -1,   -1,
   -1,  306,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  319,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  334,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  344,
   -1,   -1,  347,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  123,   -1,   -1,   10,   -1,   -1,   -1,  362,  363,   -1,
   -1,   -1,   -1,   -1,   -1,  370,  371,  372,  373,  374,
  375,  260,   -1,   -1,  263,   -1,   33,   -1,  267,  268,
  269,  270,   -1,   -1,   -1,  274,  275,  276,  277,   -1,
  279,  280,   -1,  282,  283,   -1,   -1,  286,   -1,   -1,
   -1,  290,  291,   -1,  293,  294,  295,  296,  297,   -1,
   -1,  300,  301,  302,   -1,   -1,   -1,  306,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  319,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  334,   -1,   -1,   -1,   -1,
   -1,   -1,   10,   -1,   -1,  344,   -1,   -1,  347,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  362,  363,   33,   -1,   -1,   -1,   -1,
   -1,  370,  371,  372,  373,  374,  375,  260,   -1,   -1,
  263,   -1,   -1,   -1,   -1,  268,  269,  270,   -1,   -1,
   -1,  274,  275,  276,  277,   -1,  279,  280,   -1,  282,
  283,   -1,   -1,  286,   -1,   -1,   -1,  290,  291,   -1,
  293,  294,  295,  296,  297,   -1,   -1,  300,  301,  302,
   -1,   -1,   -1,  306,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  319,   -1,   -1,   -1,
   10,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  334,   -1,   -1,   -1,  123,   -1,   -1,   -1,   -1,
   -1,  344,   -1,   33,  347,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  362,
  363,   -1,   -1,   -1,   -1,   -1,   -1,  370,  371,  372,
  373,  374,  375,  260,   -1,   -1,  263,   -1,   -1,   -1,
   -1,  268,  269,  270,   -1,   -1,   -1,  274,  275,  276,
  277,   -1,  279,  280,   -1,  282,  283,   -1,   -1,  286,
   -1,   -1,   -1,  290,  291,   -1,  293,  294,  295,  296,
  297,   -1,   -1,  300,  301,  302,   -1,   10,   -1,  306,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  319,  123,   -1,   -1,   -1,   -1,   -1,   -1,
   33,   -1,   -1,   -1,   -1,   -1,   -1,  334,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  344,   -1,   -1,
  347,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  260,   -1,   -1,  362,  363,   -1,   -1,   -1,
   -1,   -1,  270,  370,  371,  372,  373,  374,  375,   -1,
   -1,  279,  280,   -1,  282,  283,   -1,   -1,  286,   -1,
   -1,   -1,  290,  291,   -1,  293,  294,  295,  296,  297,
   -1,   -1,  300,  301,  302,   -1,   -1,   -1,  306,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  123,  319,   -1,   -1,   10,   -1,   -1,   -1,   -1,   -1,
   -1,  329,  330,  331,  332,  333,  334,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  344,   33,   -1,  347,
   -1,   -1,  350,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  260,   -1,   -1,   -1,  362,  363,   -1,   -1,   -1,   -1,
  270,   -1,  370,  371,  372,  373,  374,  375,   -1,  279,
  280,   -1,  282,  283,   -1,   -1,  286,   -1,   -1,   -1,
  290,  291,   -1,  293,  294,  295,  296,  297,   -1,   -1,
  300,  301,  302,   -1,   -1,   -1,  306,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  319,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  329,
  330,  331,  332,  333,  334,   -1,   -1,  123,   -1,   -1,
   -1,   10,   -1,   -1,  344,   -1,   -1,  347,   -1,   -1,
  350,   -1,   -1,   -1,   -1,   -1,   -1,  260,   -1,   -1,
   -1,   -1,  362,  363,   33,   -1,   -1,  270,   -1,   -1,
  370,  371,  372,  373,  374,  375,  279,  280,   -1,  282,
  283,   -1,   -1,  286,   -1,   -1,   -1,  290,  291,   -1,
  293,  294,  295,  296,  297,   -1,   -1,  300,  301,  302,
   -1,   -1,   -1,  306,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  319,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  329,  330,  331,  332,
  333,  334,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  344,   -1,   -1,  347,   -1,   -1,  350,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   10,   -1,  362,
  363,   -1,   -1,   -1,   -1,   -1,   -1,  370,  371,  372,
  373,  374,  375,   -1,  260,   -1,   -1,  263,   -1,   -1,
   33,   -1,  268,  269,  270,   -1,   -1,   -1,  274,   -1,
   -1,  277,   -1,  279,  280,   -1,  282,  283,   -1,   -1,
  286,   -1,   -1,   -1,  290,  291,   -1,  293,  294,  295,
  296,  297,   -1,   -1,  300,  301,  302,   -1,   -1,   -1,
  306,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  319,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  334,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  344,   -1,
   -1,  347,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  123,   -1,   -1,   10,   -1,   -1,  362,  363,   -1,   -1,
   -1,   -1,   -1,   -1,  370,  371,  372,  373,  374,  375,
   -1,  260,   -1,   -1,  263,   -1,   33,   -1,   -1,  268,
  269,  270,   -1,   -1,   -1,  274,   -1,   -1,  277,   -1,
  279,  280,   -1,  282,  283,   -1,   -1,  286,   -1,   -1,
   -1,  290,  291,   -1,  293,  294,  295,  296,  297,   -1,
   -1,  300,  301,  302,   -1,   -1,   -1,  306,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  319,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  334,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  344,   -1,   -1,  347,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   10,
   -1,   -1,   -1,  362,  363,   -1,   -1,   -1,   -1,   -1,
   -1,  370,  371,  372,  373,  374,  375,  260,   -1,   -1,
  263,   -1,   33,   -1,   -1,  268,  269,  270,   -1,   -1,
   -1,   -1,   -1,   -1,  277,   -1,  279,  280,   -1,  282,
  283,   -1,   -1,  286,   -1,   -1,   -1,  290,  291,   -1,
  293,  294,  295,  296,  297,   -1,   -1,  300,  301,  302,
   -1,   -1,   -1,  306,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  319,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  334,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  344,   -1,   -1,  347,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  123,   -1,   -1,   10,   -1,   -1,   -1,  362,
  363,   -1,   -1,   -1,   -1,   -1,   -1,  370,  371,  372,
  373,  374,  375,  260,   -1,   -1,  263,   -1,   33,   -1,
   -1,  268,  269,  270,   -1,   -1,   -1,   -1,   -1,   -1,
  277,   -1,  279,  280,   -1,  282,  283,   -1,   -1,  286,
   -1,   -1,   -1,  290,  291,   -1,  293,  294,  295,  296,
  297,   -1,   -1,  300,  301,  302,   -1,   -1,   -1,  306,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  319,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  334,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  344,   -1,   -1,
  347,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  123,   -1,
   -1,   10,   -1,   -1,   -1,  362,  363,   -1,   -1,   -1,
   -1,   -1,   -1,  370,  371,  372,  373,  374,  375,  260,
   -1,   -1,  263,   -1,   33,   -1,   -1,   -1,  269,  270,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  279,  280,
   -1,  282,  283,   -1,   -1,  286,   -1,   -1,   -1,  290,
  291,   -1,  293,  294,  295,  296,  297,   -1,   -1,  300,
  301,  302,   -1,   -1,   -1,  306,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  319,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  334,   -1,   -1,   -1,   -1,   -1,   -1,
   10,   -1,   -1,  344,   -1,   -1,  347,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  362,  363,   33,   -1,   -1,   -1,   -1,   -1,  370,
  371,  372,  373,  374,  375,  260,   -1,   -1,  263,   -1,
   -1,   -1,   -1,   -1,  269,  270,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  279,  280,   -1,  282,  283,   -1,
   -1,  286,   -1,   -1,   -1,  290,  291,   -1,  293,  294,
  295,  296,  297,   -1,   -1,  300,  301,  302,   -1,   -1,
   -1,  306,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  319,   -1,   -1,   -1,   10,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  334,
   -1,   -1,   -1,  123,   -1,   -1,   -1,   -1,   -1,  344,
   -1,   33,  347,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  362,  363,   -1,
   -1,   -1,   -1,   -1,   -1,  370,  371,  372,  373,  374,
  375,  260,   -1,   -1,  263,   -1,   -1,   -1,   -1,   -1,
  269,  270,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  279,  280,   -1,  282,  283,   -1,   -1,  286,   -1,   -1,
   -1,  290,  291,   -1,  293,  294,  295,  296,  297,   -1,
   -1,  300,  301,  302,   -1,   10,   -1,  306,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  319,  123,   -1,   -1,   -1,   -1,   -1,   -1,   33,   -1,
   -1,   -1,   -1,   -1,   -1,  334,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  344,   -1,   -1,  347,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  260,   -1,   -1,  362,  363,   -1,   -1,   -1,   -1,  269,
  270,  370,  371,  372,  373,  374,  375,   -1,   -1,  279,
  280,   -1,  282,  283,   -1,   -1,  286,   -1,   -1,   -1,
  290,  291,   -1,  293,  294,  295,  296,  297,   -1,   -1,
  300,  301,  302,   10,   -1,   -1,  306,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  123,  319,
   -1,   -1,   -1,   -1,   -1,   -1,   33,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  334,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  344,   -1,   -1,  347,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  260,   -1,
   -1,   -1,  362,  363,   -1,   -1,   -1,   -1,  270,   -1,
  370,  371,  372,  373,  374,  375,   -1,  279,  280,   -1,
  282,  283,   -1,   -1,  286,   -1,   -1,   -1,  290,  291,
   -1,  293,  294,  295,  296,  297,   -1,   -1,  300,  301,
  302,   -1,   10,   -1,  306,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  123,  319,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   33,   -1,   -1,   -1,   -1,
   -1,   -1,  334,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  344,   -1,   -1,  347,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  260,   -1,   -1,   -1,   -1,
  362,  363,   -1,   -1,   -1,  270,   -1,   -1,  370,  371,
  372,  373,  374,  375,  279,  280,   -1,  282,  283,   -1,
   -1,  286,   -1,   -1,   -1,  290,  291,   -1,  293,  294,
  295,  296,  297,   -1,   -1,  300,  301,  302,   -1,   10,
   -1,  306,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  319,  123,   -1,   -1,   -1,   -1,
   -1,   -1,   33,   -1,   -1,   -1,   -1,   -1,   -1,  334,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  344,
   -1,   -1,  347,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  260,   -1,   -1,   -1,  362,  363,   -1,
   -1,   -1,   -1,  270,   -1,  370,  371,  372,  373,  374,
  375,   -1,  279,  280,   -1,  282,  283,   -1,   -1,  286,
   -1,   -1,   -1,  290,  291,   -1,  293,  294,  295,  296,
  297,   -1,   -1,  300,  301,  302,   -1,   -1,   -1,  306,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  319,   -1,   -1,   -1,   -1,   -1,   -1,   33,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  334,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  344,   -1,   -1,
  347,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  260,   -1,   -1,  362,  363,   -1,   -1,   -1,
   -1,   -1,  270,  370,  371,  372,  373,  374,  375,   -1,
   -1,  279,  280,   -1,  282,  283,   -1,   -1,  286,   -1,
   -1,   -1,  290,  291,   -1,  293,  294,  295,  296,  297,
   -1,   -1,  300,  301,  302,   -1,   -1,   -1,  306,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  319,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  334,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  344,   -1,   -1,  347,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  260,
   -1,   -1,   -1,   -1,  362,  363,   -1,   -1,   -1,  270,
   -1,   -1,  370,  371,  372,  373,  374,  375,  279,  280,
   -1,  282,  283,   -1,   -1,  286,   -1,   -1,   -1,  290,
  291,   -1,  293,  294,  295,  296,  297,   -1,   -1,  300,
  301,  302,   -1,   -1,   -1,  306,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  319,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  334,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  344,   -1,   -1,  347,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  260,   -1,   -1,   -1,
   -1,  362,  363,   -1,   -1,   -1,  270,   -1,   -1,  370,
  371,  372,  373,  374,  375,  279,  280,   -1,  282,  283,
   -1,   -1,  286,   -1,   -1,   -1,  290,  291,   -1,  293,
  294,  295,  296,  297,   -1,   -1,  300,  301,  302,   -1,
   -1,   -1,  306,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  319,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  334,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  344,   -1,   -1,  347,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  363,
   -1,   -1,   -1,   -1,   -1,   -1,  370,  371,  372,  373,
  374,  375,
};
#define YYFINAL 2
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 381
#if YYDEBUG
#if defined(__cplusplus) || defined(__STDC__)
const char * const yyname[] =
#else
char *yyname[] =
#endif
	{
"end-of-file",0,0,0,0,0,0,0,0,0,"'\\n'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,"'!'",0,0,0,0,0,0,"'('","')'",0,0,"','","'-'",0,"'/'",0,0,0,0,0,0,0,0,0,0,0,
0,"'<'","'='","'>'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,"PASS","BLOCK","MATCH","SCRUB","RETURN","IN","OS","OUT","LOG",
"QUICK","ON","FROM","TO","FLAGS","RETURNRST","RETURNICMP","RETURNICMP6","PROTO",
"INET","INET6","ALL","ANY","ICMPTYPE","ICMP6TYPE","CODE","KEEP","MODULATE",
"STATE","PORT","BINATTO","NODF","MINTTL","ERROR","ALLOWOPTS","FASTROUTE",
"FILENAME","ROUTETO","DUPTO","REPLYTO","NO","LABEL","NOROUTE","URPFFAILED",
"FRAGMENT","USER","GROUP","MAXMSS","MAXIMUM","TTL","TOS","DROP","TABLE",
"REASSEMBLE","ANCHOR","SET","OPTIMIZATION","TIMEOUT","LIMIT","LOGINTERFACE",
"BLOCKPOLICY","RANDOMID","REQUIREORDER","SYNPROXY","FINGERPRINTS","NOSYNC",
"DEBUG","SKIP","HOSTID","ANTISPOOF","FOR","INCLUDE","MATCHES","BITMASK",
"RANDOM","SOURCEHASH","ROUNDROBIN","STATICPORT","PROBABILITY","ALTQ","CBQ",
"PRIQ","HFSC","BANDWIDTH","TBRSIZE","LINKSHARE","REALTIME","UPPERLIMIT","QUEUE",
"PRIORITY","QLIMIT","RTABLE","LOAD","RULESET_OPTIMIZATION","STICKYADDRESS",
"MAXSRCSTATES","MAXSRCNODES","SOURCETRACK","GLOBAL","RULE","MAXSRCCONN",
"MAXSRCCONNRATE","OVERLOAD","FLUSH","SLOPPY","PFLOW","TAGGED","TAG","IFBOUND",
"FLOATING","STATEPOLICY","STATEDEFAULTS","ROUTE","SETTOS","DIVERTTO",
"DIVERTREPLY","DIVERTPACKET","NATTO","RDRTO","RECEIVEDON","NE","LE","GE",
"STRING","NUMBER","PORTBINARY",
};
#if defined(__cplusplus) || defined(__STDC__)
const char * const yyrule[] =
#else
char *yyrule[] =
#endif
	{"$accept : ruleset",
"ruleset :",
"ruleset : ruleset include '\\n'",
"ruleset : ruleset '\\n'",
"ruleset : ruleset option '\\n'",
"ruleset : ruleset pfrule '\\n'",
"ruleset : ruleset anchorrule '\\n'",
"ruleset : ruleset loadrule '\\n'",
"ruleset : ruleset altqif '\\n'",
"ruleset : ruleset queuespec '\\n'",
"ruleset : ruleset varset '\\n'",
"ruleset : ruleset antispoof '\\n'",
"ruleset : ruleset tabledef '\\n'",
"ruleset : '{' fakeanchor '}' '\\n'",
"ruleset : ruleset error '\\n'",
"include : INCLUDE STRING",
"fakeanchor : fakeanchor '\\n'",
"fakeanchor : fakeanchor anchorrule '\\n'",
"fakeanchor : fakeanchor pfrule '\\n'",
"fakeanchor : fakeanchor error '\\n'",
"optimizer : string",
"optnodf :",
"optnodf : NODF",
"option : SET REASSEMBLE yesno optnodf",
"option : SET OPTIMIZATION STRING",
"option : SET RULESET_OPTIMIZATION optimizer",
"option : SET TIMEOUT timeout_spec",
"option : SET TIMEOUT '{' optnl timeout_list '}'",
"option : SET LIMIT limit_spec",
"option : SET LIMIT '{' optnl limit_list '}'",
"option : SET LOGINTERFACE stringall",
"option : SET HOSTID number",
"option : SET BLOCKPOLICY DROP",
"option : SET BLOCKPOLICY RETURN",
"option : SET REQUIREORDER yesno",
"option : SET FINGERPRINTS STRING",
"option : SET STATEPOLICY statelock",
"option : SET DEBUG STRING",
"option : SET SKIP interface",
"option : SET STATEDEFAULTS state_opt_list",
"stringall : STRING",
"stringall : ALL",
"string : STRING string",
"string : STRING",
"varstring : numberstring varstring",
"varstring : numberstring",
"numberstring : NUMBER",
"numberstring : STRING",
"varset : STRING '=' varstring",
"anchorname : STRING",
"anchorname :",
"pfa_anchorlist :",
"pfa_anchorlist : pfa_anchorlist '\\n'",
"pfa_anchorlist : pfa_anchorlist pfrule '\\n'",
"pfa_anchorlist : pfa_anchorlist anchorrule '\\n'",
"$$1 :",
"pfa_anchor : '{' $$1 '\\n' pfa_anchorlist '}'",
"pfa_anchor :",
"anchorrule : ANCHOR anchorname dir quick interface af proto fromto filter_opts pfa_anchor",
"loadrule : LOAD ANCHOR string FROM string",
"$$2 :",
"scrub_opts : $$2 scrub_opts_l",
"scrub_opts_l : scrub_opts_l comma scrub_opt",
"scrub_opts_l : scrub_opt",
"scrub_opt : NODF",
"scrub_opt : MINTTL NUMBER",
"scrub_opt : MAXMSS NUMBER",
"scrub_opt : SETTOS tos",
"scrub_opt : REASSEMBLE STRING",
"scrub_opt : RANDOMID",
"antispoof : ANTISPOOF logquick antispoof_ifspc af antispoof_opts",
"antispoof_ifspc : FOR antispoof_if",
"antispoof_ifspc : FOR '{' optnl antispoof_iflst '}'",
"antispoof_iflst : antispoof_if optnl",
"antispoof_iflst : antispoof_iflst comma antispoof_if optnl",
"antispoof_if : if_item",
"antispoof_if : '(' if_item ')'",
"$$3 :",
"antispoof_opts : $$3 antispoof_opts_l",
"antispoof_opts :",
"antispoof_opts_l : antispoof_opts_l antispoof_opt",
"antispoof_opts_l : antispoof_opt",
"antispoof_opt : LABEL label",
"antispoof_opt : RTABLE NUMBER",
"not : '!'",
"not :",
"tabledef : TABLE '<' STRING '>' table_opts",
"$$4 :",
"table_opts : $$4 table_opts_l",
"table_opts :",
"table_opts_l : table_opts_l table_opt",
"table_opts_l : table_opt",
"table_opt : STRING",
"table_opt : '{' optnl '}'",
"table_opt : '{' optnl host_list '}'",
"table_opt : FILENAME STRING",
"altqif : ALTQ interface queue_opts QUEUE qassign",
"queuespec : QUEUE STRING interface queue_opts qassign",
"$$5 :",
"queue_opts : $$5 queue_opts_l",
"queue_opts :",
"queue_opts_l : queue_opts_l queue_opt",
"queue_opts_l : queue_opt",
"queue_opt : BANDWIDTH bandwidth",
"queue_opt : PRIORITY NUMBER",
"queue_opt : QLIMIT NUMBER",
"queue_opt : scheduler",
"queue_opt : TBRSIZE NUMBER",
"bandwidth : STRING",
"bandwidth : NUMBER",
"scheduler : CBQ",
"scheduler : CBQ '(' cbqflags_list ')'",
"scheduler : PRIQ",
"scheduler : PRIQ '(' priqflags_list ')'",
"scheduler : HFSC",
"scheduler : HFSC '(' hfsc_opts ')'",
"cbqflags_list : cbqflags_item",
"cbqflags_list : cbqflags_list comma cbqflags_item",
"cbqflags_item : STRING",
"priqflags_list : priqflags_item",
"priqflags_list : priqflags_list comma priqflags_item",
"priqflags_item : STRING",
"$$6 :",
"hfsc_opts : $$6 hfscopts_list",
"hfscopts_list : hfscopts_item",
"hfscopts_list : hfscopts_list comma hfscopts_item",
"hfscopts_item : LINKSHARE bandwidth",
"hfscopts_item : LINKSHARE '(' bandwidth comma NUMBER comma bandwidth ')'",
"hfscopts_item : REALTIME bandwidth",
"hfscopts_item : REALTIME '(' bandwidth comma NUMBER comma bandwidth ')'",
"hfscopts_item : UPPERLIMIT bandwidth",
"hfscopts_item : UPPERLIMIT '(' bandwidth comma NUMBER comma bandwidth ')'",
"hfscopts_item : STRING",
"qassign :",
"qassign : qassign_item",
"qassign : '{' optnl qassign_list '}'",
"qassign_list : qassign_item optnl",
"qassign_list : qassign_list comma qassign_item optnl",
"qassign_item : STRING",
"pfrule : action dir logquick interface af proto fromto filter_opts",
"$$7 :",
"filter_opts : $$7 filter_opts_l",
"filter_opts :",
"filter_opts_l : filter_opts_l filter_opt",
"filter_opts_l : filter_opt",
"filter_opt : USER uids",
"filter_opt : GROUP gids",
"filter_opt : flags",
"filter_opt : icmpspec",
"filter_opt : TOS tos",
"filter_opt : keep",
"filter_opt : FRAGMENT",
"filter_opt : ALLOWOPTS",
"filter_opt : LABEL label",
"filter_opt : QUEUE qname",
"filter_opt : TAG string",
"filter_opt : not TAGGED string",
"filter_opt : PROBABILITY probability",
"filter_opt : RTABLE NUMBER",
"filter_opt : DIVERTTO STRING PORT portplain",
"filter_opt : DIVERTREPLY",
"filter_opt : DIVERTPACKET PORT number",
"filter_opt : SCRUB '(' scrub_opts ')'",
"filter_opt : NATTO redirpool pool_opts",
"filter_opt : RDRTO redirpool pool_opts",
"filter_opt : BINATTO redirpool pool_opts",
"filter_opt : FASTROUTE",
"filter_opt : ROUTETO routespec pool_opts",
"filter_opt : REPLYTO routespec pool_opts",
"filter_opt : DUPTO routespec pool_opts",
"filter_opt : RECEIVEDON if_item",
"probability : STRING",
"probability : NUMBER",
"action : PASS",
"action : MATCH",
"action : BLOCK blockspec",
"blockspec :",
"blockspec : DROP",
"blockspec : RETURNRST",
"blockspec : RETURNRST '(' TTL NUMBER ')'",
"blockspec : RETURNICMP",
"blockspec : RETURNICMP6",
"blockspec : RETURNICMP '(' reticmpspec ')'",
"blockspec : RETURNICMP6 '(' reticmp6spec ')'",
"blockspec : RETURNICMP '(' reticmpspec comma reticmp6spec ')'",
"blockspec : RETURN",
"reticmpspec : STRING",
"reticmpspec : NUMBER",
"reticmp6spec : STRING",
"reticmp6spec : NUMBER",
"dir :",
"dir : IN",
"dir : OUT",
"quick :",
"quick : QUICK",
"logquick :",
"logquick : log",
"logquick : QUICK",
"logquick : log QUICK",
"logquick : QUICK log",
"log : LOG",
"log : LOG '(' logopts ')'",
"logopts : logopt",
"logopts : logopts comma logopt",
"logopt : ALL",
"logopt : MATCHES",
"logopt : USER",
"logopt : GROUP",
"logopt : TO string",
"interface :",
"interface : ON if_item_not",
"interface : ON '{' optnl if_list '}'",
"if_list : if_item_not optnl",
"if_list : if_list comma if_item_not optnl",
"if_item_not : not if_item",
"if_item : STRING",
"af :",
"af : INET",
"af : INET6",
"proto :",
"proto : PROTO proto_item",
"proto : PROTO '{' optnl proto_list '}'",
"proto_list : proto_item optnl",
"proto_list : proto_list comma proto_item optnl",
"proto_item : protoval",
"protoval : STRING",
"protoval : NUMBER",
"fromto : ALL",
"fromto : from os to",
"os :",
"os : OS xos",
"os : OS '{' optnl os_list '}'",
"xos : STRING",
"os_list : xos optnl",
"os_list : os_list comma xos optnl",
"from :",
"from : FROM ipportspec",
"to :",
"to : TO ipportspec",
"ipportspec : ipspec",
"ipportspec : ipspec PORT portspec",
"ipportspec : PORT portspec",
"optnl : '\\n' optnl",
"optnl :",
"ipspec : ANY",
"ipspec : xhost",
"ipspec : '{' optnl host_list '}'",
"host_list : ipspec optnl",
"host_list : host_list comma ipspec optnl",
"xhost : not host",
"xhost : not NOROUTE",
"xhost : not URPFFAILED",
"host : STRING",
"host : STRING '-' STRING",
"host : STRING '/' NUMBER",
"host : NUMBER '/' NUMBER",
"host : dynaddr",
"host : dynaddr '/' NUMBER",
"host : '<' STRING '>'",
"host : ROUTE STRING",
"number : NUMBER",
"number : STRING",
"dynaddr : '(' STRING ')'",
"portspec : port_item",
"portspec : '{' optnl port_list '}'",
"port_list : port_item optnl",
"port_list : port_list comma port_item optnl",
"port_item : portrange",
"port_item : unaryop portrange",
"port_item : portrange PORTBINARY portrange",
"portplain : numberstring",
"portrange : numberstring",
"uids : uid_item",
"uids : '{' optnl uid_list '}'",
"uid_list : uid_item optnl",
"uid_list : uid_list comma uid_item optnl",
"uid_item : uid",
"uid_item : unaryop uid",
"uid_item : uid PORTBINARY uid",
"uid : STRING",
"uid : NUMBER",
"gids : gid_item",
"gids : '{' optnl gid_list '}'",
"gid_list : gid_item optnl",
"gid_list : gid_list comma gid_item optnl",
"gid_item : gid",
"gid_item : unaryop gid",
"gid_item : gid PORTBINARY gid",
"gid : STRING",
"gid : NUMBER",
"flag : STRING",
"flags : FLAGS flag '/' flag",
"flags : FLAGS '/' flag",
"flags : FLAGS ANY",
"icmpspec : ICMPTYPE icmp_item",
"icmpspec : ICMPTYPE '{' optnl icmp_list '}'",
"icmpspec : ICMP6TYPE icmp6_item",
"icmpspec : ICMP6TYPE '{' optnl icmp6_list '}'",
"icmp_list : icmp_item optnl",
"icmp_list : icmp_list comma icmp_item optnl",
"icmp6_list : icmp6_item optnl",
"icmp6_list : icmp6_list comma icmp6_item optnl",
"icmp_item : icmptype",
"icmp_item : icmptype CODE STRING",
"icmp_item : icmptype CODE NUMBER",
"icmp6_item : icmp6type",
"icmp6_item : icmp6type CODE STRING",
"icmp6_item : icmp6type CODE NUMBER",
"icmptype : STRING",
"icmptype : NUMBER",
"icmp6type : STRING",
"icmp6type : NUMBER",
"tos : STRING",
"tos : NUMBER",
"sourcetrack :",
"sourcetrack : GLOBAL",
"sourcetrack : RULE",
"statelock : IFBOUND",
"statelock : FLOATING",
"keep : NO STATE",
"keep : KEEP STATE state_opt_spec",
"keep : MODULATE STATE state_opt_spec",
"keep : SYNPROXY STATE state_opt_spec",
"flush :",
"flush : FLUSH",
"flush : FLUSH GLOBAL",
"state_opt_spec : '(' state_opt_list ')'",
"state_opt_spec :",
"state_opt_list : state_opt_item",
"state_opt_list : state_opt_list comma state_opt_item",
"state_opt_item : MAXIMUM NUMBER",
"state_opt_item : NOSYNC",
"state_opt_item : MAXSRCSTATES NUMBER",
"state_opt_item : MAXSRCCONN NUMBER",
"state_opt_item : MAXSRCCONNRATE NUMBER '/' NUMBER",
"state_opt_item : OVERLOAD '<' STRING '>' flush",
"state_opt_item : MAXSRCNODES NUMBER",
"state_opt_item : SOURCETRACK sourcetrack",
"state_opt_item : statelock",
"state_opt_item : SLOPPY",
"state_opt_item : PFLOW",
"state_opt_item : STRING NUMBER",
"label : STRING",
"qname : STRING",
"qname : '(' STRING ')'",
"qname : '(' STRING comma STRING ')'",
"portstar : numberstring",
"redirspec : host",
"redirspec : '{' optnl redir_host_list '}'",
"redir_host_list : host optnl",
"redir_host_list : redir_host_list comma host optnl",
"redirpool : redirspec",
"redirpool : redirspec PORT portstar",
"hashkey :",
"hashkey : string",
"$$8 :",
"pool_opts : $$8 pool_opts_l",
"pool_opts :",
"pool_opts_l : pool_opts_l pool_opt",
"pool_opts_l : pool_opt",
"pool_opt : BITMASK",
"pool_opt : RANDOM",
"pool_opt : SOURCEHASH hashkey",
"pool_opt : ROUNDROBIN",
"pool_opt : STATICPORT",
"pool_opt : STICKYADDRESS",
"route_host : STRING",
"route_host : STRING '/' STRING",
"route_host : '<' STRING '>'",
"route_host : dynaddr '/' NUMBER",
"route_host : '(' STRING host ')'",
"route_host_list : route_host optnl",
"route_host_list : route_host_list comma route_host optnl",
"routespec : route_host",
"routespec : '{' optnl route_host_list '}'",
"timeout_spec : STRING NUMBER",
"timeout_list : timeout_list comma timeout_spec optnl",
"timeout_list : timeout_spec optnl",
"limit_spec : STRING NUMBER",
"limit_list : limit_list comma limit_spec optnl",
"limit_list : limit_spec optnl",
"comma : ','",
"comma :",
"yesno : NO",
"yesno : STRING",
"unaryop : '='",
"unaryop : NE",
"unaryop : LE",
"unaryop : '<'",
"unaryop : GE",
"unaryop : '>'",
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
#line 3898 "parse.y"

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;

	file->errors++;
	va_start(ap, fmt);
	fprintf(stderr, "%s:%d: ", file->name, yylval.lineno);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	return (0);
}

int
disallow_table(struct node_host *h, const char *fmt)
{
	for (; h != NULL; h = h->next)
		if (h->addr.type == PF_ADDR_TABLE) {
			yyerror(fmt, h->addr.v.tblname);
			return (1);
		}
	return (0);
}

int
disallow_urpf_failed(struct node_host *h, const char *fmt)
{
	for (; h != NULL; h = h->next)
		if (h->addr.type == PF_ADDR_URPFFAILED) {
			yyerror(fmt);
			return (1);
		}
	return (0);
}

int
disallow_alias(struct node_host *h, const char *fmt)
{
	for (; h != NULL; h = h->next)
		if (DYNIF_MULTIADDR(h->addr)) {
			yyerror(fmt, h->addr.v.tblname);
			return (1);
		}
	return (0);
}

int
rule_consistent(struct pf_rule *r, int anchor_call)
{
	int	problems = 0;

	if (r->proto != IPPROTO_TCP && r->proto != IPPROTO_UDP &&
	    (r->src.port_op || r->dst.port_op)) {
		yyerror("port only applies to tcp/udp");
		problems++;
	}
	if (r->proto != IPPROTO_ICMP && r->proto != IPPROTO_ICMPV6 &&
	    (r->type || r->code)) {
		yyerror("icmp-type/code only applies to icmp");
		problems++;
	}
	if (!r->af && (r->type || r->code)) {
		yyerror("must indicate address family with icmp-type/code");
		problems++;
	}
	if (r->overload_tblname[0] &&
	    r->max_src_conn == 0 && r->max_src_conn_rate.seconds == 0) {
		yyerror("'overload' requires 'max-src-conn' "
		    "or 'max-src-conn-rate'");
		problems++;
	}
	if ((r->proto == IPPROTO_ICMP && r->af == AF_INET6) ||
	    (r->proto == IPPROTO_ICMPV6 && r->af == AF_INET)) {
		yyerror("proto %s doesn't match address family %s",
		    r->proto == IPPROTO_ICMP ? "icmp" : "icmp6",
		    r->af == AF_INET ? "inet" : "inet6");
		problems++;
	}
	if (r->allow_opts && r->action != PF_PASS) {
		yyerror("allow-opts can only be specified for pass rules");
		problems++;
	}
	if (r->rule_flag & PFRULE_FRAGMENT && (r->src.port_op ||
	    r->dst.port_op || r->flagset || r->type || r->code)) {
		yyerror("fragments can be filtered only on IP header fields");
		problems++;
	}
	if (r->rule_flag & PFRULE_RETURNRST && r->proto != IPPROTO_TCP) {
		yyerror("return-rst can only be applied to TCP rules");
		problems++;
	}
	if (r->max_src_nodes && !(r->rule_flag & PFRULE_RULESRCTRACK)) {
		yyerror("max-src-nodes requires 'source-track rule'");
		problems++;
	}
	if (r->action != PF_PASS && r->keep_state) {
		yyerror("keep state is great, but only for pass rules");
		problems++;
	}
	if (r->rule_flag & PFRULE_STATESLOPPY &&
	    (r->keep_state == PF_STATE_MODULATE ||
	    r->keep_state == PF_STATE_SYNPROXY)) {
		yyerror("sloppy state matching cannot be used with "
		    "synproxy state or modulate state");
		problems++;
	}
	if ((r->nat.addr.type != PF_ADDR_NONE ||
	    r->rdr.addr.type != PF_ADDR_NONE) &&
	    r->action != PF_MATCH && !r->keep_state) {
		yyerror("nat-to and rdr-to require keep state");
		problems++;
	}
	if (r->direction == PF_INOUT && (r->nat.addr.type != PF_ADDR_NONE ||
	    r->rdr.addr.type != PF_ADDR_NONE)) {
		yyerror("nat-to and rdr-to require a direction");
		problems++;
	}
	if (r->af == AF_INET6 && (r->scrub_flags &
	    (PFSTATE_NODF|PFSTATE_RANDOMID|PFSTATE_SETTOS))) {
		yyerror("address family inet6 does not support scrub options "
		    "no-df, random-id, set-tos");
		problems++;
	}

	/* match rules rules */
	if (r->action == PF_MATCH) {
		if (r->divert.port) {
			yyerror("divert is not supported on match rules");
			problems++;
		}
		if (r->divert_packet.port) {
			yyerror("divert is not supported on match rules");
			problems++;
		}
		if (r->rt) {
			yyerror("route-to, reply-to, dup-to and fastroute "
			   "must not be used on match rules");
			problems++;
		}
	}
	return (-problems);
}

int
process_tabledef(char *name, struct table_opts *opts)
{
	struct pfr_buffer	 ab;
	struct node_tinit	*ti;

	bzero(&ab, sizeof(ab));
	ab.pfrb_type = PFRB_ADDRS;
	SIMPLEQ_FOREACH(ti, &opts->init_nodes, entries) {
		if (ti->file)
			if (pfr_buf_load(&ab, ti->file, 0, append_addr)) {
				if (errno)
					yyerror("cannot load \"%s\": %s",
					    ti->file, strerror(errno));
				else
					yyerror("file \"%s\" contains bad data",
					    ti->file);
				goto _error;
			}
		if (ti->host)
			if (append_addr_host(&ab, ti->host, 0, 0)) {
				yyerror("cannot create address buffer: %s",
				    strerror(errno));
				goto _error;
			}
	}
	if (pf->opts & PF_OPT_VERBOSE)
		print_tabledef(name, opts->flags, opts->init_addr,
		    &opts->init_nodes);
	if (!(pf->opts & PF_OPT_NOACTION) &&
	    pfctl_define_table(name, opts->flags, opts->init_addr,
	    pf->anchor->name, &ab, pf->anchor->ruleset.tticket)) {
		yyerror("cannot define table %s: %s", name,
		    pfr_strerror(errno));
		goto _error;
	}
	pf->tdirty = 1;
	pfr_buf_clear(&ab);
	return (0);
_error:
	pfr_buf_clear(&ab);
	return (-1);
}

struct keywords {
	const char	*k_name;
	int		 k_val;
};

/* macro gore, but you should've seen the prior indentation nightmare... */

#define FREE_LIST(T,r) \
	do { \
		T *p, *node = r; \
		while (node != NULL) { \
			p = node; \
			node = node->next; \
			free(p); \
		} \
	} while (0)

#define LOOP_THROUGH(T,n,r,C) \
	do { \
		T *n; \
		if (r == NULL) { \
			r = calloc(1, sizeof(T)); \
			if (r == NULL) \
				err(1, "LOOP: calloc"); \
			r->next = NULL; \
		} \
		n = r; \
		while (n != NULL) { \
			do { \
				C; \
			} while (0); \
			n = n->next; \
		} \
	} while (0)

void
expand_label_str(char *label, size_t len, const char *srch, const char *repl)
{
	char *tmp;
	char *p, *q;

	if ((tmp = calloc(1, len)) == NULL)
		err(1, "expand_label_str: calloc");
	p = q = label;
	while ((q = strstr(p, srch)) != NULL) {
		*q = '\0';
		if ((strlcat(tmp, p, len) >= len) ||
		    (strlcat(tmp, repl, len) >= len))
			errx(1, "expand_label: label too long");
		q += strlen(srch);
		p = q;
	}
	if (strlcat(tmp, p, len) >= len)
		errx(1, "expand_label: label too long");
	strlcpy(label, tmp, len);	/* always fits */
	free(tmp);
}

void
expand_label_if(const char *name, char *label, size_t len, const char *ifname)
{
	if (strstr(label, name) != NULL) {
		if (!*ifname)
			expand_label_str(label, len, name, "any");
		else
			expand_label_str(label, len, name, ifname);
	}
}

void
expand_label_addr(const char *name, char *label, size_t len, sa_family_t af,
    struct node_host *h)
{
	char tmp[64], tmp_not[66];

	if (strstr(label, name) != NULL) {
		switch (h->addr.type) {
		case PF_ADDR_DYNIFTL:
			snprintf(tmp, sizeof(tmp), "(%s)", h->addr.v.ifname);
			break;
		case PF_ADDR_TABLE:
			snprintf(tmp, sizeof(tmp), "<%s>", h->addr.v.tblname);
			break;
		case PF_ADDR_NOROUTE:
			snprintf(tmp, sizeof(tmp), "no-route");
			break;
		case PF_ADDR_URPFFAILED:
			snprintf(tmp, sizeof(tmp), "urpf-failed");
			break;
		case PF_ADDR_ADDRMASK:
			if (!af || (PF_AZERO(&h->addr.v.a.addr, af) &&
			    PF_AZERO(&h->addr.v.a.mask, af)))
				snprintf(tmp, sizeof(tmp), "any");
			else {
				char	a[48];
				int	bits;

				if (inet_ntop(af, &h->addr.v.a.addr, a,
				    sizeof(a)) == NULL)
					snprintf(tmp, sizeof(tmp), "?");
				else {
					bits = unmask(&h->addr.v.a.mask, af);
					if ((af == AF_INET && bits < 32) ||
					    (af == AF_INET6 && bits < 128))
						snprintf(tmp, sizeof(tmp),
						    "%s/%d", a, bits);
					else
						snprintf(tmp, sizeof(tmp),
						    "%s", a);
				}
			}
			break;
		default:
			snprintf(tmp, sizeof(tmp), "?");
			break;
		}

		if (h->not) {
			snprintf(tmp_not, sizeof(tmp_not), "! %s", tmp);
			expand_label_str(label, len, name, tmp_not);
		} else
			expand_label_str(label, len, name, tmp);
	}
}

void
expand_label_port(const char *name, char *label, size_t len,
    struct node_port *port)
{
	char	 a1[6], a2[6], op[13] = "";

	if (strstr(label, name) != NULL) {
		snprintf(a1, sizeof(a1), "%u", ntohs(port->port[0]));
		snprintf(a2, sizeof(a2), "%u", ntohs(port->port[1]));
		if (!port->op)
			;
		else if (port->op == PF_OP_IRG)
			snprintf(op, sizeof(op), "%s><%s", a1, a2);
		else if (port->op == PF_OP_XRG)
			snprintf(op, sizeof(op), "%s<>%s", a1, a2);
		else if (port->op == PF_OP_EQ)
			snprintf(op, sizeof(op), "%s", a1);
		else if (port->op == PF_OP_NE)
			snprintf(op, sizeof(op), "!=%s", a1);
		else if (port->op == PF_OP_LT)
			snprintf(op, sizeof(op), "<%s", a1);
		else if (port->op == PF_OP_LE)
			snprintf(op, sizeof(op), "<=%s", a1);
		else if (port->op == PF_OP_GT)
			snprintf(op, sizeof(op), ">%s", a1);
		else if (port->op == PF_OP_GE)
			snprintf(op, sizeof(op), ">=%s", a1);
		expand_label_str(label, len, name, op);
	}
}

void
expand_label_proto(const char *name, char *label, size_t len, u_int8_t proto)
{
	struct protoent *pe;
	char n[4];

	if (strstr(label, name) != NULL) {
		pe = getprotobynumber(proto);
		if (pe != NULL)
			expand_label_str(label, len, name, pe->p_name);
		else {
			snprintf(n, sizeof(n), "%u", proto);
			expand_label_str(label, len, name, n);
		}
	}
}

void
expand_label_nr(const char *name, char *label, size_t len)
{
	char n[11];

	if (strstr(label, name) != NULL) {
		snprintf(n, sizeof(n), "%u", pf->anchor->match);
		expand_label_str(label, len, name, n);
	}
}

void
expand_label(char *label, size_t len, const char *ifname, sa_family_t af,
    struct node_host *src_host, struct node_port *src_port,
    struct node_host *dst_host, struct node_port *dst_port,
    u_int8_t proto)
{
	expand_label_if("$if", label, len, ifname);
	expand_label_addr("$srcaddr", label, len, af, src_host);
	expand_label_addr("$dstaddr", label, len, af, dst_host);
	expand_label_port("$srcport", label, len, src_port);
	expand_label_port("$dstport", label, len, dst_port);
	expand_label_proto("$proto", label, len, proto);
	expand_label_nr("$nr", label, len);
}

int
expand_altq(struct pf_altq *a, struct node_if *interfaces,
    struct node_queue *nqueues, struct node_queue_bw bwspec,
    struct node_queue_opt *opts)
{
	struct pf_altq		 pa, pb;
	char			 qname[PF_QNAME_SIZE];
	struct node_queue	*n;
	struct node_queue_bw	 bw;
	int			 errs = 0;

	LOOP_THROUGH(struct node_if, interface, interfaces,
		memcpy(&pa, a, sizeof(struct pf_altq));
		if (strlcpy(pa.ifname, interface->ifname,
		    sizeof(pa.ifname)) >= sizeof(pa.ifname))
			errx(1, "expand_altq: strlcpy");

		if (interface->not) {
			yyerror("altq on ! <interface> is not supported");
			errs++;
		} else {
			if (eval_pfaltq(pf, &pa, &bwspec, opts))
				errs++;
			else
				if (pfctl_add_altq(pf, &pa))
					errs++;

			if (pf->opts & PF_OPT_VERBOSE) {
				print_altq(&pf->paltq->altq, 0,
				    &bwspec, opts);
				if (nqueues && nqueues->tail) {
					printf("queue { ");
					LOOP_THROUGH(struct node_queue, queue,
					    nqueues,
						printf("%s ",
						    queue->queue);
					);
					printf("}");
				}
				printf("\n");
			}

			if (pa.scheduler == ALTQT_CBQ ||
			    pa.scheduler == ALTQT_HFSC) {
				/* now create a root queue */
				memset(&pb, 0, sizeof(struct pf_altq));
				if (strlcpy(qname, "root_", sizeof(qname)) >=
				    sizeof(qname))
					errx(1, "expand_altq: strlcpy");
				if (strlcat(qname, interface->ifname,
				    sizeof(qname)) >= sizeof(qname))
					errx(1, "expand_altq: strlcat");
				if (strlcpy(pb.qname, qname,
				    sizeof(pb.qname)) >= sizeof(pb.qname))
					errx(1, "expand_altq: strlcpy");
				if (strlcpy(pb.ifname, interface->ifname,
				    sizeof(pb.ifname)) >= sizeof(pb.ifname))
					errx(1, "expand_altq: strlcpy");
				pb.qlimit = pa.qlimit;
				pb.scheduler = pa.scheduler;
				bw.bw_absolute = pa.ifbandwidth;
				bw.bw_percent = 0;
				if (eval_pfqueue(pf, &pb, &bw, opts))
					errs++;
				else
					if (pfctl_add_altq(pf, &pb))
						errs++;
			}

			LOOP_THROUGH(struct node_queue, queue, nqueues,
				n = calloc(1, sizeof(struct node_queue));
				if (n == NULL)
					err(1, "expand_altq: calloc");
				if (pa.scheduler == ALTQT_CBQ ||
				    pa.scheduler == ALTQT_HFSC)
					if (strlcpy(n->parent, qname,
					    sizeof(n->parent)) >=
					    sizeof(n->parent))
						errx(1, "expand_altq: strlcpy");
				if (strlcpy(n->queue, queue->queue,
				    sizeof(n->queue)) >= sizeof(n->queue))
					errx(1, "expand_altq: strlcpy");
				if (strlcpy(n->ifname, interface->ifname,
				    sizeof(n->ifname)) >= sizeof(n->ifname))
					errx(1, "expand_altq: strlcpy");
				n->scheduler = pa.scheduler;
				n->next = NULL;
				n->tail = n;
				if (queues == NULL)
					queues = n;
				else {
					queues->tail->next = n;
					queues->tail = n;
				}
			);
		}
	);
	FREE_LIST(struct node_if, interfaces);
	FREE_LIST(struct node_queue, nqueues);

	return (errs);
}

int
expand_queue(struct pf_altq *a, struct node_if *interfaces,
    struct node_queue *nqueues, struct node_queue_bw bwspec,
    struct node_queue_opt *opts)
{
	struct node_queue	*n, *nq;
	struct pf_altq		 pa;
	u_int8_t		 found = 0;
	u_int8_t		 errs = 0;

	if (queues == NULL) {
		yyerror("queue %s has no parent", a->qname);
		FREE_LIST(struct node_queue, nqueues);
		return (1);
	}

	LOOP_THROUGH(struct node_if, interface, interfaces,
		LOOP_THROUGH(struct node_queue, tqueue, queues,
			if (!strncmp(a->qname, tqueue->queue, PF_QNAME_SIZE) &&
			    (interface->ifname[0] == 0 ||
			    (!interface->not && !strncmp(interface->ifname,
			    tqueue->ifname, IFNAMSIZ)) ||
			    (interface->not && strncmp(interface->ifname,
			    tqueue->ifname, IFNAMSIZ)))) {
				/* found ourself in queues */
				found++;

				memcpy(&pa, a, sizeof(struct pf_altq));

				if (pa.scheduler != ALTQT_NONE &&
				    pa.scheduler != tqueue->scheduler) {
					yyerror("exactly one scheduler type "
					    "per interface allowed");
					return (1);
				}
				pa.scheduler = tqueue->scheduler;

				/* scheduler dependent error checking */
				switch (pa.scheduler) {
				case ALTQT_PRIQ:
					if (nqueues != NULL) {
						yyerror("priq queues cannot "
						    "have child queues");
						return (1);
					}
					if (bwspec.bw_absolute > 0 ||
					    bwspec.bw_percent < 100) {
						yyerror("priq doesn't take "
						    "bandwidth");
						return (1);
					}
					break;
				default:
					break;
				}

				if (strlcpy(pa.ifname, tqueue->ifname,
				    sizeof(pa.ifname)) >= sizeof(pa.ifname))
					errx(1, "expand_queue: strlcpy");
				if (strlcpy(pa.parent, tqueue->parent,
				    sizeof(pa.parent)) >= sizeof(pa.parent))
					errx(1, "expand_queue: strlcpy");

				if (eval_pfqueue(pf, &pa, &bwspec, opts))
					errs++;
				else
					if (pfctl_add_altq(pf, &pa))
						errs++;

				for (nq = nqueues; nq != NULL; nq = nq->next) {
					if (!strcmp(a->qname, nq->queue)) {
						yyerror("queue cannot have "
						    "itself as child");
						errs++;
						continue;
					}
					n = calloc(1,
					    sizeof(struct node_queue));
					if (n == NULL)
						err(1, "expand_queue: calloc");
					if (strlcpy(n->parent, a->qname,
					    sizeof(n->parent)) >=
					    sizeof(n->parent))
						errx(1, "expand_queue strlcpy");
					if (strlcpy(n->queue, nq->queue,
					    sizeof(n->queue)) >=
					    sizeof(n->queue))
						errx(1, "expand_queue strlcpy");
					if (strlcpy(n->ifname, tqueue->ifname,
					    sizeof(n->ifname)) >=
					    sizeof(n->ifname))
						errx(1, "expand_queue strlcpy");
					n->scheduler = tqueue->scheduler;
					n->next = NULL;
					n->tail = n;
					if (queues == NULL)
						queues = n;
					else {
						queues->tail->next = n;
						queues->tail = n;
					}
				}
				if ((pf->opts & PF_OPT_VERBOSE) && (
				    (found == 1 && interface->ifname[0] == 0) ||
				    (found > 0 && interface->ifname[0] != 0))) {
					print_queue(&pf->paltq->altq, 0,
					    &bwspec, interface->ifname[0] != 0,
					    opts);
					if (nqueues && nqueues->tail) {
						printf("{ ");
						LOOP_THROUGH(struct node_queue,
						    queue, nqueues,
							printf("%s ",
							    queue->queue);
						);
						printf("}");
					}
					printf("\n");
				}
			}
		);
	);

	FREE_LIST(struct node_queue, nqueues);
	FREE_LIST(struct node_if, interfaces);

	if (!found) {
		yyerror("queue %s has no parent", a->qname);
		errs++;
	}

	if (errs)
		return (1);
	else
		return (0);
}

int
collapse_redirspec(struct pf_pool *rpool, struct pf_rule *r,
    struct redirspec *rs, u_int8_t allow_if)
{
	struct pf_opt_tbl *tbl = NULL;
	struct node_host *h;
	struct pf_rule_addr ra;
	int	i = 0;


	if (!rs || !rs->rdr || rs->rdr->host == NULL) {
		rpool->addr.type = PF_ADDR_NONE;
		return (0);
	}

	/* count matching addresses */
	for (h = rs->rdr->host; h != NULL; h = h->next) {
		if (!r->af || !h->af || h->af == r->af) {
			i++;
			if (h->af && !r->af)
				r->af = h->af;
		}
	}

	if (i == 0) {		/* no pool address */
		yyerror("af mismatch in %s spec",
		    allow_if ? "routing" : "translation");
		return (1);
	} else if (i == 1) {	/* only one address */
		for (h = rs->rdr->host; h != NULL; h = h->next)
			if (!h->af || !r->af || r->af == h->af)
				break;
		rpool->addr = h->addr;
		if (!allow_if && h->ifname) {
			yyerror("@if not permitted for translation");
			return (1);
		}
		if (h->ifname && strlcpy(rpool->ifname, h->ifname,
		    sizeof(rpool->ifname)) >= sizeof(rpool->ifname))
			errx(1, "collapse_redirspec: strlcpy");

		return (0);
	} else {		/* more than one address */
		if (rs->pool_opts.type &&
		     rs->pool_opts.type != PF_POOL_ROUNDROBIN) {
			yyerror("only round-robin valid for multiple "
			    "translation or routing addresses");
			return (1);
		}
		for (h = rs->rdr->host; h != NULL; h = h->next) {
			if (r->af != h->af)
				continue;
			if (h->addr.type != PF_ADDR_ADDRMASK &&
			    h->addr.type != PF_ADDR_NONE) {
				yyerror("multiple tables or dynamic interfaces "
				    "not supported for translation or routing");
				return (1);
			}
			if (!allow_if && h->ifname) {
				yyerror("@if not permitted for translation");
				return (1);
			}
			memset(&ra, 0, sizeof(ra));
			ra.addr = h->addr;
			if (add_opt_table(pf, &tbl,
			    h->af, &ra, h->ifname))
				return (1);
                }
	}
	if (tbl) {
		if ((pf->opts & PF_OPT_NOACTION) == 0 &&
		     pf_opt_create_table(pf, tbl))
				return (1);

		pf->tdirty = 1;

		if (pf->opts & PF_OPT_VERBOSE)
			print_tabledef(tbl->pt_name, PFR_TFLAG_CONST,
			    1, &tbl->pt_nodes);

		memset(&rpool->addr, 0, sizeof(rpool->addr));
		rpool->addr.type = PF_ADDR_TABLE;
		strlcpy(rpool->addr.v.tblname, tbl->pt_name,
		    sizeof(rpool->addr.v.tblname));

		pfr_buf_clear(tbl->pt_buf);
		free(tbl->pt_buf);
		tbl->pt_buf = NULL;
		free(tbl);
	}
	return (0);
}


int
apply_redirspec(struct pf_pool *rpool, struct pf_rule *r, struct redirspec *rs,
    int isrdr, struct node_port *np)
{
	if (!rs || !rs->rdr)
		return (0);

	rpool->proxy_port[0] = ntohs(rs->rdr->rport.a);

	if (isrdr) {
		if (!rs->rdr->rport.b && rs->rdr->rport.t && np->port != NULL) {
			rpool->proxy_port[1] = ntohs(rs->rdr->rport.a) +
			    (ntohs(np->port[1]) - ntohs(np->port[0]));
		} else
			rpool->proxy_port[1] = ntohs(rs->rdr->rport.b);
	} else {
		rpool->proxy_port[1] = ntohs(rs->rdr->rport.b);
		if (!rpool->proxy_port[0] && !rpool->proxy_port[1]) {
			rpool->proxy_port[0] = PF_NAT_PROXY_PORT_LOW;
			rpool->proxy_port[1] = PF_NAT_PROXY_PORT_HIGH;
		} else if (!rpool->proxy_port[1])
			rpool->proxy_port[1] = rpool->proxy_port[0];
	}

	rpool->opts = rs->pool_opts.type;
	if (rpool->addr.type == PF_ADDR_TABLE ||
	    DYNIF_MULTIADDR(rpool->addr))
		rpool->opts |= PF_POOL_ROUNDROBIN;

	if (rs->pool_opts.key != NULL)
		memcpy(&rpool->key, rs->pool_opts.key,
		    sizeof(struct pf_poolhashkey));

	if (rs->pool_opts.opts)
		rpool->opts |= rs->pool_opts.opts;

	if (rs->pool_opts.staticport) {
		if (isrdr) {
			yyerror("the 'static-port' option is only valid with "
			    "nat rules");
			return (1);
		}
		if (rpool->proxy_port[0] != PF_NAT_PROXY_PORT_LOW &&
		    rpool->proxy_port[1] != PF_NAT_PROXY_PORT_HIGH) {
			yyerror("the 'static-port' option can't be used when "
			    "specifying a port range");
			return (1);
		}
		rpool->proxy_port[0] = 0;
		rpool->proxy_port[1] = 0;
	}

	return (0);
}


void
expand_rule(struct pf_rule *r, int keeprule, struct node_if *interfaces,
    struct redirspec *nat, struct redirspec *rdr, struct redirspec *rroute,
    struct node_proto *protos, struct node_os *src_oses,
    struct node_host *src_hosts, struct node_port *src_ports,
    struct node_host *dst_hosts, struct node_port *dst_ports,
    struct node_uid *uids, struct node_gid *gids, struct node_if *rcv,
    struct node_icmp *icmp_types, const char *anchor_call)
{
	sa_family_t		 af = r->af;
	int			 added = 0, error = 0;
	char			 ifname[IF_NAMESIZE];
	char			 label[PF_RULE_LABEL_SIZE];
	char			 tagname[PF_TAG_NAME_SIZE];
	char			 match_tagname[PF_TAG_NAME_SIZE];
	u_int8_t		 flags, flagset, keep_state;
	struct node_host	*srch, *dsth;
	struct redirspec	 binat;
	struct pf_rule		 rb;
	int			 dir = r->direction;

	if (strlcpy(label, r->label, sizeof(label)) >= sizeof(label))
		errx(1, "expand_rule: strlcpy");
	if (strlcpy(tagname, r->tagname, sizeof(tagname)) >= sizeof(tagname))
		errx(1, "expand_rule: strlcpy");
	if (strlcpy(match_tagname, r->match_tagname, sizeof(match_tagname)) >=
	    sizeof(match_tagname))
		errx(1, "expand_rule: strlcpy");
	flags = r->flags;
	flagset = r->flagset;
	keep_state = r->keep_state;

	r->src.addr.type = r->dst.addr.type = PF_ADDR_ADDRMASK;

	LOOP_THROUGH(struct node_if, interface, interfaces,
	LOOP_THROUGH(struct node_proto, proto, protos,
	LOOP_THROUGH(struct node_icmp, icmp_type, icmp_types,
	LOOP_THROUGH(struct node_host, src_host, src_hosts,
	LOOP_THROUGH(struct node_port, src_port, src_ports,
	LOOP_THROUGH(struct node_os, src_os, src_oses,
	LOOP_THROUGH(struct node_host, dst_host, dst_hosts,
	LOOP_THROUGH(struct node_port, dst_port, dst_ports,
	LOOP_THROUGH(struct node_uid, uid, uids,
	LOOP_THROUGH(struct node_gid, gid, gids,

		r->af = af;

		error += collapse_redirspec(&r->rdr, r, rdr, 0);
		error += collapse_redirspec(&r->nat, r, nat, 0);
		error += collapse_redirspec(&r->route, r, rroute, 1);

		/* disallow @if in from or to for the time being */
		if ((src_host->addr.type == PF_ADDR_ADDRMASK &&
		    src_host->ifname) ||
		    (dst_host->addr.type == PF_ADDR_ADDRMASK &&
		    dst_host->ifname)) {
			yyerror("@if syntax not permitted in from or to");
			error++;
		}
		/* for link-local IPv6 address, interface must match up */
		if ((r->af && src_host->af && r->af != src_host->af) ||
		    (r->af && dst_host->af && r->af != dst_host->af) ||
		    (src_host->af && dst_host->af &&
		    src_host->af != dst_host->af) ||
		    (src_host->ifindex && dst_host->ifindex &&
		    src_host->ifindex != dst_host->ifindex) ||
		    (src_host->ifindex && *interface->ifname &&
		    src_host->ifindex != if_nametoindex(interface->ifname)) ||
		    (dst_host->ifindex && *interface->ifname &&
		    dst_host->ifindex != if_nametoindex(interface->ifname)))
			continue;
		if (!r->af && src_host->af)
			r->af = src_host->af;
		else if (!r->af && dst_host->af)
			r->af = dst_host->af;

		if (*interface->ifname)
			strlcpy(r->ifname, interface->ifname,
			    sizeof(r->ifname));
		else if (if_indextoname(src_host->ifindex, ifname))
			strlcpy(r->ifname, ifname, sizeof(r->ifname));
		else if (if_indextoname(dst_host->ifindex, ifname))
			strlcpy(r->ifname, ifname, sizeof(r->ifname));
		else
			memset(r->ifname, '\0', sizeof(r->ifname));

		if (strlcpy(r->label, label, sizeof(r->label)) >=
		    sizeof(r->label))
			errx(1, "expand_rule: strlcpy");
		if (strlcpy(r->tagname, tagname, sizeof(r->tagname)) >=
		    sizeof(r->tagname))
			errx(1, "expand_rule: strlcpy");
		if (strlcpy(r->match_tagname, match_tagname,
		    sizeof(r->match_tagname)) >= sizeof(r->match_tagname))
			errx(1, "expand_rule: strlcpy");
		expand_label(r->label, PF_RULE_LABEL_SIZE, r->ifname, r->af,
		    src_host, src_port, dst_host, dst_port, proto->proto);
		expand_label(r->tagname, PF_TAG_NAME_SIZE, r->ifname, r->af,
		    src_host, src_port, dst_host, dst_port, proto->proto);
		expand_label(r->match_tagname, PF_TAG_NAME_SIZE, r->ifname,
		    r->af, src_host, src_port, dst_host, dst_port,
		    proto->proto);

		error += check_netmask(src_host, r->af);
		error += check_netmask(dst_host, r->af);

		r->ifnot = interface->not;
		r->proto = proto->proto;
		r->src.addr = src_host->addr;
		r->src.neg = src_host->not;
		r->src.port[0] = src_port->port[0];
		r->src.port[1] = src_port->port[1];
		r->src.port_op = src_port->op;
		r->dst.addr = dst_host->addr;
		r->dst.neg = dst_host->not;
		r->dst.port[0] = dst_port->port[0];
		r->dst.port[1] = dst_port->port[1];
		r->dst.port_op = dst_port->op;
		r->uid.op = uid->op;
		r->uid.uid[0] = uid->uid[0];
		r->uid.uid[1] = uid->uid[1];
		r->gid.op = gid->op;
		r->gid.gid[0] = gid->gid[0];
		r->gid.gid[1] = gid->gid[1];
		if (rcv) {
			strlcpy(r->rcv_ifname, rcv->ifname,
			    sizeof(r->rcv_ifname));
		}
		r->type = icmp_type->type;
		r->code = icmp_type->code;

		if ((keep_state == PF_STATE_MODULATE ||
		    keep_state == PF_STATE_SYNPROXY) &&
		    r->proto && r->proto != IPPROTO_TCP)
			r->keep_state = PF_STATE_NORMAL;
		else
			r->keep_state = keep_state;

		if (r->proto && r->proto != IPPROTO_TCP) {
			r->flags = 0;
			r->flagset = 0;
		} else {
			r->flags = flags;
			r->flagset = flagset;
		}
		if (icmp_type->proto && r->proto != icmp_type->proto) {
			yyerror("icmp-type mismatch");
			error++;
		}

		if (src_os && src_os->os) {
			r->os_fingerprint = pfctl_get_fingerprint(src_os->os);
			if ((pf->opts & PF_OPT_VERBOSE2) &&
			    r->os_fingerprint == PF_OSFP_NOMATCH)
				fprintf(stderr,
				    "warning: unknown '%s' OS fingerprint\n",
				    src_os->os);
		} else {
			r->os_fingerprint = PF_OSFP_ANY;
		}

		if (nat && nat->rdr && nat->binat) {
			if (disallow_table(src_host, "invalid use of table "
			    "<%s> as the source address of a binat-to rule") ||
			    disallow_alias(src_host, "invalid use of interface "
			    "(%s) as the source address of a binat-to rule")) {
				error++;
			} else if ((r->src.addr.type != PF_ADDR_ADDRMASK &&
			    r->src.addr.type != PF_ADDR_DYNIFTL) ||
			    (r->nat.addr.type != PF_ADDR_ADDRMASK &&
			    r->nat.addr.type != PF_ADDR_DYNIFTL)) {
				yyerror("binat-to requires a specified "
				    "source and redirect address");
				error++;
			}
			if (DYNIF_MULTIADDR(r->src.addr) ||
			    DYNIF_MULTIADDR(r->nat.addr)) {
				yyerror ("dynamic interfaces must be used with "
				    ":0 in a binat-to rule");
				error++;
			}
			if (PF_AZERO(&r->src.addr.v.a.mask, af) ||
			    PF_AZERO(&r->nat.addr.v.a.mask, af)) {
				yyerror ("source and redir addresess must have "
				    "a matching network mask in binat-rule");
				error++;
			}
			if (r->nat.addr.type == PF_ADDR_TABLE) {
				yyerror ("tables cannot be used as the redirect "
				    "address of a binat-to rule");
				error++;
			}
			if (r->direction != PF_INOUT) {
				yyerror("binat-to cannot be specified "
				    "with a direction");
				error++;
			}

			/* first specify outbound NAT rule */
			r->direction = PF_OUT;
		}

		error += apply_redirspec(&r->nat, r, nat, 0, dst_port);
		error += apply_redirspec(&r->rdr, r, rdr, 1, dst_port);
		error += apply_redirspec(&r->route, r, rroute, 2, dst_port);

		if (rule_consistent(r, anchor_call[0]) < 0 || error)
			yyerror("skipping rule due to errors");
		else {
			r->nr = pf->astack[pf->asd]->match++;
			pfctl_add_rule(pf, r, anchor_call);
			added++;
		}
		r->direction = dir;

		/* Generate binat's matching inbound rule */
		if (!error && nat && nat->rdr && nat->binat) {
			bcopy(r, &rb, sizeof(rb));

			/* now specify inbound rdr rule */
			rb.direction = PF_IN;

			if ((srch = calloc(1, sizeof(*srch))) == NULL)
				err(1, "expand_rule: calloc");
			bcopy(src_host, srch, sizeof(*srch));
			srch->ifname = NULL;
			srch->next = NULL;
			srch->tail = NULL;

			if ((dsth = calloc(1, sizeof(*dsth))) == NULL)
				err(1, "expand_rule: calloc");
			bcopy(&rb.nat.addr, &dsth->addr, sizeof(dsth->addr));
			dsth->ifname = NULL;
			dsth->next = NULL;
			dsth->tail = NULL;

			if ((binat.rdr =
			    calloc(1, sizeof(*binat.rdr))) == NULL)
				err(1, "expand_rule: calloc");
			bcopy(nat->rdr, binat.rdr, sizeof(*binat.rdr));
			bcopy(&nat->pool_opts, &binat.pool_opts,
			    sizeof(binat.pool_opts));
			binat.pool_opts.staticport = 0;
			binat.rdr->host = srch;

			expand_rule(&rb, 1, interface, NULL, &binat, NULL,
			    proto,
			    src_os, dst_host, dst_port, dsth, src_port,
			    uid, gid, rcv, icmp_type, anchor_call);
		}

	))))))))));

	if (!keeprule) {
		FREE_LIST(struct node_if, interfaces);
		FREE_LIST(struct node_proto, protos);
		FREE_LIST(struct node_host, src_hosts);
		FREE_LIST(struct node_port, src_ports);
		FREE_LIST(struct node_os, src_oses);
		FREE_LIST(struct node_host, dst_hosts);
		FREE_LIST(struct node_port, dst_ports);
		FREE_LIST(struct node_uid, uids);
		FREE_LIST(struct node_gid, gids);
		FREE_LIST(struct node_icmp, icmp_types);
		if (nat && nat->rdr)
			FREE_LIST(struct node_host, nat->rdr->host);
		if (rdr && rdr->rdr)
			FREE_LIST(struct node_host, rdr->rdr->host);

	}

	if (!added)
		yyerror("rule expands to no valid combination");
}

int
expand_skip_interface(struct node_if *interfaces)
{
	int	errs = 0;

	if (!interfaces || (!interfaces->next && !interfaces->not &&
	    !strcmp(interfaces->ifname, "none"))) {
		if (pf->opts & PF_OPT_VERBOSE)
			printf("set skip on none\n");
		errs = pfctl_set_interface_flags(pf, "", PFI_IFLAG_SKIP, 0);
		return (errs);
	}

	if (pf->opts & PF_OPT_VERBOSE)
		printf("set skip on {");
	LOOP_THROUGH(struct node_if, interface, interfaces,
		if (pf->opts & PF_OPT_VERBOSE)
			printf(" %s", interface->ifname);
		if (interface->not) {
			yyerror("skip on ! <interface> is not supported");
			errs++;
		} else
			errs += pfctl_set_interface_flags(pf,
			    interface->ifname, PFI_IFLAG_SKIP, 1);
	);
	if (pf->opts & PF_OPT_VERBOSE)
		printf(" }\n");

	FREE_LIST(struct node_if, interfaces);

	if (errs)
		return (1);
	else
		return (0);
}

void
freehostlist(struct node_host *h)
{
	struct node_host *n;

	for (n = h; n != NULL; n = n->next)
		if (n->ifname)
			free(n->ifname);
	FREE_LIST(struct node_host, h);
}

#undef FREE_LIST
#undef LOOP_THROUGH

int
check_rulestate(int desired_state)
{
	if (require_order && (rulestate > desired_state)) {
		yyerror("Rules must be in order: options, normalization, "
		    "queueing, translation, filtering");
		return (1);
	}
	rulestate = desired_state;
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
		{ "all",		ALL},
		{ "allow-opts",		ALLOWOPTS},
		{ "altq",		ALTQ},
		{ "anchor",		ANCHOR},
		{ "antispoof",		ANTISPOOF},
		{ "any",		ANY},
		{ "bandwidth",		BANDWIDTH},
		{ "binat-to",		BINATTO},
		{ "bitmask",		BITMASK},
		{ "block",		BLOCK},
		{ "block-policy",	BLOCKPOLICY},
		{ "cbq",		CBQ},
		{ "code",		CODE},
		{ "debug",		DEBUG},
		{ "divert-packet",	DIVERTPACKET},
		{ "divert-reply",	DIVERTREPLY},
		{ "divert-to",		DIVERTTO},
		{ "drop",		DROP},
		{ "dup-to",		DUPTO},
		{ "fastroute",		FASTROUTE},
		{ "file",		FILENAME},
		{ "fingerprints",	FINGERPRINTS},
		{ "flags",		FLAGS},
		{ "floating",		FLOATING},
		{ "flush",		FLUSH},
		{ "for",		FOR},
		{ "fragment",		FRAGMENT},
		{ "from",		FROM},
		{ "global",		GLOBAL},
		{ "group",		GROUP},
		{ "hfsc",		HFSC},
		{ "hostid",		HOSTID},
		{ "icmp-type",		ICMPTYPE},
		{ "icmp6-type",		ICMP6TYPE},
		{ "if-bound",		IFBOUND},
		{ "in",			IN},
		{ "include",		INCLUDE},
		{ "inet",		INET},
		{ "inet6",		INET6},
		{ "keep",		KEEP},
		{ "label",		LABEL},
		{ "limit",		LIMIT},
		{ "linkshare",		LINKSHARE},
		{ "load",		LOAD},
		{ "log",		LOG},
		{ "loginterface",	LOGINTERFACE},
		{ "match",		MATCH},
		{ "matches",		MATCHES},
		{ "max",		MAXIMUM},
		{ "max-mss",		MAXMSS},
		{ "max-src-conn",	MAXSRCCONN},
		{ "max-src-conn-rate",	MAXSRCCONNRATE},
		{ "max-src-nodes",	MAXSRCNODES},
		{ "max-src-states",	MAXSRCSTATES},
		{ "min-ttl",		MINTTL},
		{ "modulate",		MODULATE},
		{ "nat-to",		NATTO},
		{ "no",			NO},
		{ "no-df",		NODF},
		{ "no-route",		NOROUTE},
		{ "no-sync",		NOSYNC},
		{ "on",			ON},
		{ "optimization",	OPTIMIZATION},
		{ "os",			OS},
		{ "out",		OUT},
		{ "overload",		OVERLOAD},
		{ "pass",		PASS},
		{ "pflow",		PFLOW},
		{ "port",		PORT},
		{ "priority",		PRIORITY},
		{ "priq",		PRIQ},
		{ "probability",	PROBABILITY},
		{ "proto",		PROTO},
		{ "qlimit",		QLIMIT},
		{ "queue",		QUEUE},
		{ "quick",		QUICK},
		{ "random",		RANDOM},
		{ "random-id",		RANDOMID},
		{ "rdr-to",		RDRTO},
		{ "realtime",		REALTIME},
		{ "reassemble",		REASSEMBLE},
		{ "received-on",	RECEIVEDON},
		{ "reply-to",		REPLYTO},
		{ "require-order",	REQUIREORDER},
		{ "return",		RETURN},
		{ "return-icmp",	RETURNICMP},
		{ "return-icmp6",	RETURNICMP6},
		{ "return-rst",		RETURNRST},
		{ "round-robin",	ROUNDROBIN},
		{ "route",		ROUTE},
		{ "route-to",		ROUTETO},
		{ "rtable",		RTABLE},
		{ "rule",		RULE},
		{ "ruleset-optimization",	RULESET_OPTIMIZATION},
		{ "scrub",		SCRUB},
		{ "set",		SET},
		{ "set-tos",		SETTOS},
		{ "skip",		SKIP},
		{ "sloppy",		SLOPPY},
		{ "source-hash",	SOURCEHASH},
		{ "source-track",	SOURCETRACK},
		{ "state",		STATE},
		{ "state-defaults",	STATEDEFAULTS},
		{ "state-policy",	STATEPOLICY},
		{ "static-port",	STATICPORT},
		{ "sticky-address",	STICKYADDRESS},
		{ "synproxy",		SYNPROXY},
		{ "table",		TABLE},
		{ "tag",		TAG},
		{ "tagged",		TAGGED},
		{ "tbrsize",		TBRSIZE},
		{ "timeout",		TIMEOUT},
		{ "to",			TO},
		{ "tos",		TOS},
		{ "ttl",		TTL},
		{ "upperlimit",		UPPERLIMIT},
		{ "urpf-failed",	URPFFAILED},
		{ "user",		USER},
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p) {
		if (debug > 1)
			fprintf(stderr, "%s: %d\n", s, p->k_val);
		return (p->k_val);
	} else {
		if (debug > 1)
			fprintf(stderr, "string: %s\n", s);
		return (STRING);
	}
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
	case '!':
		next = lgetc(0);
		if (next == '=')
			return (NE);
		lungetc(next);
		break;
	case '<':
		next = lgetc(0);
		if (next == '>') {
			yylval.v.i = PF_OP_XRG;
			return (PORTBINARY);
		} else if (next == '=')
			return (LE);
		lungetc(next);
		break;
	case '>':
		next = lgetc(0);
		if (next == '<') {
			yylval.v.i = PF_OP_IRG;
			return (PORTBINARY);
		} else if (next == '=')
			return (GE);
		lungetc(next);
		break;
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

	if ((nfile = calloc(1, sizeof(struct file))) == NULL ||
	    (nfile->name = strdup(name)) == NULL) {
		if (nfile)
			free(nfile);
		warn("malloc");
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

int
parse_config(char *filename, struct pfctl *xpf)
{
	int		 errors = 0;
	struct sym	*sym;

	pf = xpf;
	errors = 0;
	rulestate = PFCTL_STATE_NONE;
	returnicmpdefault = (ICMP_UNREACH << 8) | ICMP_UNREACH_PORT;
	returnicmp6default =
	    (ICMP6_DST_UNREACH << 8) | ICMP6_DST_UNREACH_NOPORT;
	blockpolicy = PFRULE_DROP;
	require_order = 0;

	if ((file = pushfile(filename, 0)) == NULL) {
		warn("cannot open the main config file!");
		return (-1);
	}

	yyparse();
	errors = file->errors;
	popfile();

	/* Free macros and check which have not been used. */
	while ((sym = TAILQ_FIRST(&symhead))) {
		if ((pf->opts & PF_OPT_VERBOSE2) && !sym->used)
			fprintf(stderr, "warning: macro '%s' not "
			    "used\n", sym->nam);
		free(sym->nam);
		free(sym->val);
		TAILQ_REMOVE(&symhead, sym, entry);
		free(sym);
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
pfctl_cmdline_symset(char *s)
{
	char	*sym, *val;
	int	 ret;

	if ((val = strrchr(s, '=')) == NULL)
		return (-1);

	if ((sym = malloc(strlen(s) - strlen(val) + 1)) == NULL)
		err(1, "pfctl_cmdline_symset: malloc");

	strlcpy(sym, s, strlen(s) - strlen(val) + 1);

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

void
mv_rules(struct pf_ruleset *src, struct pf_ruleset *dst)
{
	struct pf_rule *r;

	while ((r = TAILQ_FIRST(src->rules.active.ptr)) != NULL) {
		TAILQ_REMOVE(src->rules.active.ptr, r, entries);
		TAILQ_INSERT_TAIL(dst->rules.active.ptr, r, entries);
		dst->anchor->match++;
	}
	src->anchor->match = 0;
	while ((r = TAILQ_FIRST(src->rules.inactive.ptr)) != NULL) {
		TAILQ_REMOVE(src->rules.inactive.ptr, r, entries);
		TAILQ_INSERT_TAIL(dst->rules.inactive.ptr, r, entries);
	}
}

void
decide_address_family(struct node_host *n, sa_family_t *af)
{
	if (*af != 0 || n == NULL)
		return;
	*af = n->af;
	while ((n = n->next) != NULL) {
		if (n->af != *af) {
			*af = 0;
			return;
		}
	}
}

int
invalid_redirect(struct node_host *nh, sa_family_t af)
{
	if (!af) {
		struct node_host *n;

		/* tables and dyniftl are ok without an address family */
		for (n = nh; n != NULL; n = n->next) {
			if (n->addr.type != PF_ADDR_TABLE &&
			    n->addr.type != PF_ADDR_DYNIFTL) {
				yyerror("address family not given and "
				    "translation address expands to multiple "
				    "address families");
				return (1);
			}
		}
	}
	if (nh == NULL) {
		yyerror("no translation address with matching address family "
		    "found.");
		return (1);
	}
	return (0);
}

int
atoul(char *s, u_long *ulvalp)
{
	u_long	 ulval;
	char	*ep;

	errno = 0;
	ulval = strtoul(s, &ep, 0);
	if (s[0] == '\0' || *ep != '\0')
		return (-1);
	if (errno == ERANGE && ulval == ULONG_MAX)
		return (-1);
	*ulvalp = ulval;
	return (0);
}

int
getservice(char *n)
{
	struct servent	*s;
	u_long		 ulval;

	if (atoul(n, &ulval) == 0) {
		if (ulval > 65535) {
			yyerror("illegal port value %lu", ulval);
			return (-1);
		}
		return (htons(ulval));
	} else {
		s = getservbyname(n, "tcp");
		if (s == NULL)
			s = getservbyname(n, "udp");
		if (s == NULL) {
			yyerror("unknown port %s", n);
			return (-1);
		}
		return (s->s_port);
	}
}

int
rule_label(struct pf_rule *r, char *s)
{
	if (s) {
		if (strlcpy(r->label, s, sizeof(r->label)) >=
		    sizeof(r->label)) {
			yyerror("rule label too long (max %d chars)",
			    sizeof(r->label)-1);
			return (-1);
		}
	}
	return (0);
}

u_int16_t
parseicmpspec(char *w, sa_family_t af)
{
	const struct icmpcodeent	*p;
	u_long				 ulval;
	u_int8_t			 icmptype;

	if (af == AF_INET)
		icmptype = returnicmpdefault >> 8;
	else
		icmptype = returnicmp6default >> 8;

	if (atoul(w, &ulval) == -1) {
		if ((p = geticmpcodebyname(icmptype, w, af)) == NULL) {
			yyerror("unknown icmp code %s", w);
			return (0);
		}
		ulval = p->code;
	}
	if (ulval > 255) {
		yyerror("invalid icmp code %lu", ulval);
		return (0);
	}
	return (icmptype << 8 | ulval);
}

int
parseport(char *port, struct range *r, int extensions)
{
	char	*p = strchr(port, ':');

	if (p == NULL) {
		if ((r->a = getservice(port)) == -1)
			return (-1);
		r->b = 0;
		r->t = PF_OP_NONE;
		return (0);
	}
	if ((extensions & PPORT_STAR) && !strcmp(p+1, "*")) {
		*p = 0;
		if ((r->a = getservice(port)) == -1)
			return (-1);
		r->b = 0;
		r->t = PF_OP_IRG;
		return (0);
	}
	if ((extensions & PPORT_RANGE)) {
		*p++ = 0;
		if ((r->a = getservice(port)) == -1 ||
		    (r->b = getservice(p)) == -1)
			return (-1);
		if (r->a == r->b) {
			r->b = 0;
			r->t = PF_OP_NONE;
		} else
			r->t = PF_OP_RRG;
		return (0);
	}
	return (-1);
}

int
pfctl_load_anchors(int dev, struct pfctl *pf, struct pfr_buffer *trans)
{
	struct loadanchors	*la;

	TAILQ_FOREACH(la, &loadanchorshead, entries) {
		if (pf->opts & PF_OPT_VERBOSE)
			fprintf(stderr, "\nLoading anchor %s from %s\n",
			    la->anchorname, la->filename);
		if (pfctl_rules(dev, la->filename, pf->opts, pf->optimize,
		    la->anchorname, trans) == -1)
			return (-1);
	}

	return (0);
}

int
kw_casecmp(const void *k, const void *e)
{
	return (strcasecmp(k, ((const struct keywords *)e)->k_name));
}

int
map_tos(char *s, int *val)
{
	/* DiffServ Codepoints and other TOS mappings */
	const struct keywords	 toswords[] = {
		{ "af11",		IPTOS_DSCP_AF11 },
		{ "af12",		IPTOS_DSCP_AF12 },
		{ "af13",		IPTOS_DSCP_AF13 },
		{ "af21",		IPTOS_DSCP_AF21 },
		{ "af22",		IPTOS_DSCP_AF22 },
		{ "af23",		IPTOS_DSCP_AF23 },
		{ "af31",		IPTOS_DSCP_AF31 },
		{ "af32",		IPTOS_DSCP_AF32 },
		{ "af33",		IPTOS_DSCP_AF33 },
		{ "af41",		IPTOS_DSCP_AF41 },
		{ "af42",		IPTOS_DSCP_AF42 },
		{ "af43",		IPTOS_DSCP_AF43 },
		{ "critical",		IPTOS_PREC_CRITIC_ECP },
		{ "cs0",		IPTOS_DSCP_CS0 },
		{ "cs1",		IPTOS_DSCP_CS1 },
		{ "cs2",		IPTOS_DSCP_CS2 },
		{ "cs3",		IPTOS_DSCP_CS3 },
		{ "cs4",		IPTOS_DSCP_CS4 },
		{ "cs5",		IPTOS_DSCP_CS5 },
		{ "cs6",		IPTOS_DSCP_CS6 },
		{ "cs7",		IPTOS_DSCP_CS7 },
		{ "ef",			IPTOS_DSCP_EF },
		{ "inetcontrol",	IPTOS_PREC_INTERNETCONTROL },
		{ "lowdelay",		IPTOS_LOWDELAY },
		{ "netcontrol",		IPTOS_PREC_NETCONTROL },
		{ "reliability",	IPTOS_RELIABILITY },
		{ "throughput",		IPTOS_THROUGHPUT }
	};
	const struct keywords	*p;

	p = bsearch(s, toswords, sizeof(toswords)/sizeof(toswords[0]),
	    sizeof(toswords[0]), kw_casecmp);

	if (p) {
		*val = p->k_val;
		return (1);
	}
	return (0);
}
#line 4347 "y.tab.c"
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
case 14:
#line 533 "parse.y"
{ file->errors++; }
break;
case 15:
#line 536 "parse.y"
{
			struct file	*nfile;

			if ((nfile = pushfile(yyvsp[0].v.string, 0)) == NULL) {
				yyerror("failed to include file %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);

			file = nfile;
			lungetc('\n');
		}
break;
case 20:
#line 561 "parse.y"
{
			if (!strcmp(yyvsp[0].v.string, "none"))
				yyval.v.i = 0;
			else if (!strcmp(yyvsp[0].v.string, "basic"))
				yyval.v.i = PF_OPTIMIZE_BASIC;
			else if (!strcmp(yyvsp[0].v.string, "profile"))
				yyval.v.i = PF_OPTIMIZE_BASIC | PF_OPTIMIZE_PROFILE;
			else {
				yyerror("unknown ruleset-optimization %s", yyvsp[0].v.string);
				YYERROR;
			}
		}
break;
case 21:
#line 575 "parse.y"
{ yyval.v.number = 0; }
break;
case 22:
#line 576 "parse.y"
{ yyval.v.number = 1; }
break;
case 23:
#line 579 "parse.y"
{
			if (check_rulestate(PFCTL_STATE_OPTION))
				YYERROR;
			pfctl_set_reassembly(pf, yyvsp[-1].v.number, yyvsp[0].v.number);
		}
break;
case 24:
#line 584 "parse.y"
{
			if (check_rulestate(PFCTL_STATE_OPTION)) {
				free(yyvsp[0].v.string);
				YYERROR;
			}
			if (pfctl_set_optimization(pf, yyvsp[0].v.string) != 0) {
				yyerror("unknown optimization %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 25:
#line 596 "parse.y"
{
			if (!(pf->opts & PF_OPT_OPTIMIZE)) {
				pf->opts |= PF_OPT_OPTIMIZE;
				pf->optimize = yyvsp[0].v.i;
			}
		}
break;
case 30:
#line 606 "parse.y"
{
			if (check_rulestate(PFCTL_STATE_OPTION)) {
				free(yyvsp[0].v.string);
				YYERROR;
			}
			if (pfctl_set_logif(pf, yyvsp[0].v.string) != 0) {
				yyerror("error setting loginterface %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 31:
#line 618 "parse.y"
{
			if (yyvsp[0].v.number == 0 || yyvsp[0].v.number > UINT_MAX) {
				yyerror("hostid must be non-zero");
				YYERROR;
			}
			if (pfctl_set_hostid(pf, yyvsp[0].v.number) != 0) {
				yyerror("error setting hostid %08x", yyvsp[0].v.number);
				YYERROR;
			}
		}
break;
case 32:
#line 628 "parse.y"
{
			if (pf->opts & PF_OPT_VERBOSE)
				printf("set block-policy drop\n");
			if (check_rulestate(PFCTL_STATE_OPTION))
				YYERROR;
			blockpolicy = PFRULE_DROP;
		}
break;
case 33:
#line 635 "parse.y"
{
			if (pf->opts & PF_OPT_VERBOSE)
				printf("set block-policy return\n");
			if (check_rulestate(PFCTL_STATE_OPTION))
				YYERROR;
			blockpolicy = PFRULE_RETURN;
		}
break;
case 34:
#line 642 "parse.y"
{
			if (pf->opts & PF_OPT_VERBOSE)
				printf("set require-order %s\n",
				    yyvsp[0].v.number == 1 ? "yes" : "no");
			require_order = yyvsp[0].v.number;
		}
break;
case 35:
#line 648 "parse.y"
{
			if (pf->opts & PF_OPT_VERBOSE)
				printf("set fingerprints \"%s\"\n", yyvsp[0].v.string);
			if (check_rulestate(PFCTL_STATE_OPTION)) {
				free(yyvsp[0].v.string);
				YYERROR;
			}
			if (!pf->anchor->name[0]) {
				if (pfctl_file_fingerprints(pf->dev,
				    pf->opts, yyvsp[0].v.string)) {
					yyerror("error loading "
					    "fingerprints %s", yyvsp[0].v.string);
					free(yyvsp[0].v.string);
					YYERROR;
				}
			}
			free(yyvsp[0].v.string);
		}
break;
case 36:
#line 666 "parse.y"
{
			if (pf->opts & PF_OPT_VERBOSE)
				switch (yyvsp[0].v.i) {
				case 0:
					printf("set state-policy floating\n");
					break;
				case PFRULE_IFBOUND:
					printf("set state-policy if-bound\n");
					break;
				}
			default_statelock = yyvsp[0].v.i;
		}
break;
case 37:
#line 678 "parse.y"
{
			if (check_rulestate(PFCTL_STATE_OPTION)) {
				free(yyvsp[0].v.string);
				YYERROR;
			}
			if (pfctl_set_debug(pf, yyvsp[0].v.string) != 0) {
				yyerror("error setting debuglevel %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 38:
#line 690 "parse.y"
{
			if (expand_skip_interface(yyvsp[0].v.interface) != 0) {
				yyerror("error setting skip interface(s)");
				YYERROR;
			}
		}
break;
case 39:
#line 696 "parse.y"
{
			if (keep_state_defaults != NULL) {
				yyerror("cannot redefine state-defaults");
				YYERROR;
			}
			keep_state_defaults = yyvsp[0].v.state_opt;
		}
break;
case 40:
#line 705 "parse.y"
{ yyval.v.string = yyvsp[0].v.string; }
break;
case 41:
#line 706 "parse.y"
{
			if ((yyval.v.string = strdup("all")) == NULL) {
				err(1, "stringall: strdup");
			}
		}
break;
case 42:
#line 713 "parse.y"
{
			if (asprintf(&yyval.v.string, "%s %s", yyvsp[-1].v.string, yyvsp[0].v.string) == -1)
				err(1, "string: asprintf");
			free(yyvsp[-1].v.string);
			free(yyvsp[0].v.string);
		}
break;
case 44:
#line 722 "parse.y"
{
			if (asprintf(&yyval.v.string, "%s %s", yyvsp[-1].v.string, yyvsp[0].v.string) == -1)
				err(1, "string: asprintf");
			free(yyvsp[-1].v.string);
			free(yyvsp[0].v.string);
		}
break;
case 46:
#line 731 "parse.y"
{
			char	*s;
			if (asprintf(&s, "%lld", yyvsp[0].v.number) == -1) {
				yyerror("string: asprintf");
				YYERROR;
			}
			yyval.v.string = s;
		}
break;
case 48:
#line 742 "parse.y"
{
			if (pf->opts & PF_OPT_VERBOSE)
				printf("%s = \"%s\"\n", yyvsp[-2].v.string, yyvsp[0].v.string);
			if (symset(yyvsp[-2].v.string, yyvsp[0].v.string, 0) == -1)
				err(1, "cannot store variable %s", yyvsp[-2].v.string);
			free(yyvsp[-2].v.string);
			free(yyvsp[0].v.string);
		}
break;
case 49:
#line 752 "parse.y"
{ yyval.v.string = yyvsp[0].v.string; }
break;
case 50:
#line 753 "parse.y"
{ yyval.v.string = NULL; }
break;
case 55:
#line 763 "parse.y"
{
			char ta[PF_ANCHOR_NAME_SIZE];
			struct pf_ruleset *rs;

			/* steping into a brace anchor */
			pf->asd++;
			pf->bn++;
			pf->brace = 1;

			/*
			 * Anchor contents are parsed before the anchor rule
			 * production completes, so we don't know the real
			 * location yet. Create a holding ruleset in the root;
			 * contents will be moved afterwards.
			 */
			snprintf(ta, PF_ANCHOR_NAME_SIZE, "_%d", pf->bn);
			rs = pf_find_or_create_ruleset(ta);
			if (rs == NULL)
				err(1, "pfa_anchor: pf_find_or_create_ruleset");
			pf->astack[pf->asd] = rs->anchor;
			pf->anchor = rs->anchor;
		}
break;
case 56:
#line 785 "parse.y"
{
			pf->alast = pf->anchor;
			pf->asd--;
			pf->anchor = pf->astack[pf->asd];
		}
break;
case 58:
#line 795 "parse.y"
{
			struct pf_rule	r;
			struct node_proto	*proto;

			if (check_rulestate(PFCTL_STATE_FILTER)) {
				if (yyvsp[-8].v.string)
					free(yyvsp[-8].v.string);
				YYERROR;
			}

			if (yyvsp[-8].v.string && (yyvsp[-8].v.string[0] == '_' || strstr(yyvsp[-8].v.string, "/_") != NULL)) {
				free(yyvsp[-8].v.string);
				yyerror("anchor names beginning with '_' "
				    "are reserved for internal use");
				YYERROR;
			}

			memset(&r, 0, sizeof(r));
			if (pf->astack[pf->asd + 1]) {
				if (yyvsp[-8].v.string && strchr(yyvsp[-8].v.string, '/') != NULL) {
					free(yyvsp[-8].v.string);
					yyerror("anchor paths containing '/' "
				    	    "cannot be used for inline anchors.");
					YYERROR;
				}

				/* Move inline rules into relative location. */
				pf_anchor_setup(&r,
				    &pf->astack[pf->asd]->ruleset,
				    yyvsp[-8].v.string ? yyvsp[-8].v.string : pf->alast->name);

				if (r.anchor == NULL)
					err(1, "anchorrule: unable to "
					    "create ruleset");

				if (pf->alast != r.anchor) {
					if (r.anchor->match) {
						yyerror("inline anchor '%s' "
						    "already exists",
						    r.anchor->name);
						YYERROR;
					}
					mv_rules(&pf->alast->ruleset,
					    &r.anchor->ruleset);
				}
				pf_remove_if_empty_ruleset(&pf->alast->ruleset);
				pf->alast = r.anchor;
			} else {
				if (!yyvsp[-8].v.string) {
					yyerror("anchors without explicit "
					    "rules must specify a name");
					YYERROR;
				}
			}
			r.direction = yyvsp[-7].v.i;
			r.quick = yyvsp[-6].v.logquick.quick;
			r.af = yyvsp[-4].v.i;
			r.prob = yyvsp[-1].v.filter_opts.prob;
			r.rtableid = yyvsp[-1].v.filter_opts.rtableid;

			if (yyvsp[-1].v.filter_opts.tag)
				if (strlcpy(r.tagname, yyvsp[-1].v.filter_opts.tag,
				    PF_TAG_NAME_SIZE) >= PF_TAG_NAME_SIZE) {
					yyerror("tag too long, max %u chars",
					    PF_TAG_NAME_SIZE - 1);
					YYERROR;
				}
			if (yyvsp[-1].v.filter_opts.match_tag)
				if (strlcpy(r.match_tagname, yyvsp[-1].v.filter_opts.match_tag,
				    PF_TAG_NAME_SIZE) >= PF_TAG_NAME_SIZE) {
					yyerror("tag too long, max %u chars",
					    PF_TAG_NAME_SIZE - 1);
					YYERROR;
				}
			r.match_tag_not = yyvsp[-1].v.filter_opts.match_tag_not;
			if (rule_label(&r, yyvsp[-1].v.filter_opts.label))
				YYERROR;
			free(yyvsp[-1].v.filter_opts.label);
			r.flags = yyvsp[-1].v.filter_opts.flags.b1;
			r.flagset = yyvsp[-1].v.filter_opts.flags.b2;
			if ((yyvsp[-1].v.filter_opts.flags.b1 & yyvsp[-1].v.filter_opts.flags.b2) != yyvsp[-1].v.filter_opts.flags.b1) {
				yyerror("flags always false");
				YYERROR;
			}
			if (yyvsp[-1].v.filter_opts.flags.b1 || yyvsp[-1].v.filter_opts.flags.b2 || yyvsp[-2].v.fromto.src_os) {
				for (proto = yyvsp[-3].v.proto; proto != NULL &&
				    proto->proto != IPPROTO_TCP;
				    proto = proto->next)
					;	/* nothing */
				if (proto == NULL && yyvsp[-3].v.proto != NULL) {
					if (yyvsp[-1].v.filter_opts.flags.b1 || yyvsp[-1].v.filter_opts.flags.b2)
						yyerror(
						    "flags only apply to tcp");
					if (yyvsp[-2].v.fromto.src_os)
						yyerror(
						    "OS fingerprinting only "
						    "applies to tcp");
					YYERROR;
				}
			}

			r.tos = yyvsp[-1].v.filter_opts.tos;

			if (yyvsp[-1].v.filter_opts.keep.action) {
				yyerror("cannot specify state handling "
				    "on anchors");
				YYERROR;
			}

			if (yyvsp[-1].v.filter_opts.route.rt) {
				yyerror("cannot specify route handling "
				    "on anchors");
				YYERROR;
			}

			if (yyvsp[-1].v.filter_opts.match_tag)
				if (strlcpy(r.match_tagname, yyvsp[-1].v.filter_opts.match_tag,
				    PF_TAG_NAME_SIZE) >= PF_TAG_NAME_SIZE) {
					yyerror("tag too long, max %u chars",
					    PF_TAG_NAME_SIZE - 1);
					YYERROR;
				}
			r.match_tag_not = yyvsp[-1].v.filter_opts.match_tag_not;

			decide_address_family(yyvsp[-2].v.fromto.src.host, &r.af);
			decide_address_family(yyvsp[-2].v.fromto.dst.host, &r.af);

			expand_rule(&r, 0, yyvsp[-5].v.interface, NULL, NULL, NULL, yyvsp[-3].v.proto, yyvsp[-2].v.fromto.src_os,
			    yyvsp[-2].v.fromto.src.host, yyvsp[-2].v.fromto.src.port, yyvsp[-2].v.fromto.dst.host, yyvsp[-2].v.fromto.dst.port,
			    yyvsp[-1].v.filter_opts.uid, yyvsp[-1].v.filter_opts.gid, yyvsp[-1].v.filter_opts.rcv, yyvsp[-1].v.filter_opts.icmpspec,
			    pf->astack[pf->asd + 1] ? pf->alast->name : yyvsp[-8].v.string);
			free(yyvsp[-8].v.string);
			pf->astack[pf->asd + 1] = NULL;
		}
break;
case 59:
#line 931 "parse.y"
{
			struct loadanchors	*loadanchor;

			if (strlen(pf->anchor->name) + 1 +
			    strlen(yyvsp[-2].v.string) >= MAXPATHLEN) {
				yyerror("anchorname %s too long, max %u\n",
				    yyvsp[-2].v.string, MAXPATHLEN - 1);
				free(yyvsp[-2].v.string);
				YYERROR;
			}
			loadanchor = calloc(1, sizeof(struct loadanchors));
			if (loadanchor == NULL)
				err(1, "loadrule: calloc");
			if ((loadanchor->anchorname = malloc(MAXPATHLEN)) ==
			    NULL)
				err(1, "loadrule: malloc");
			if (pf->anchor->name[0])
				snprintf(loadanchor->anchorname, MAXPATHLEN,
				    "%s/%s", pf->anchor->name, yyvsp[-2].v.string);
			else
				strlcpy(loadanchor->anchorname, yyvsp[-2].v.string, MAXPATHLEN);
			if ((loadanchor->filename = strdup(yyvsp[0].v.string)) == NULL)
				err(1, "loadrule: strdup");

			TAILQ_INSERT_TAIL(&loadanchorshead, loadanchor,
			    entries);

			free(yyvsp[-2].v.string);
			free(yyvsp[0].v.string);
		}
break;
case 60:
#line 962 "parse.y"
{
				bzero(&scrub_opts, sizeof scrub_opts);
			}
break;
case 61:
#line 966 "parse.y"
{ yyval.v.scrub_opts = scrub_opts; }
break;
case 64:
#line 973 "parse.y"
{
			if (scrub_opts.nodf) {
				yyerror("no-df cannot be respecified");
				YYERROR;
			}
			scrub_opts.nodf = 1;
		}
break;
case 65:
#line 980 "parse.y"
{
			if (scrub_opts.marker & FOM_MINTTL) {
				yyerror("min-ttl cannot be respecified");
				YYERROR;
			}
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > 255) {
				yyerror("illegal min-ttl value %d", yyvsp[0].v.number);
				YYERROR;
			}
			scrub_opts.marker |= FOM_MINTTL;
			scrub_opts.minttl = yyvsp[0].v.number;
		}
break;
case 66:
#line 992 "parse.y"
{
			if (scrub_opts.marker & FOM_MAXMSS) {
				yyerror("max-mss cannot be respecified");
				YYERROR;
			}
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > 65535) {
				yyerror("illegal max-mss value %d", yyvsp[0].v.number);
				YYERROR;
			}
			scrub_opts.marker |= FOM_MAXMSS;
			scrub_opts.maxmss = yyvsp[0].v.number;
		}
break;
case 67:
#line 1004 "parse.y"
{
			if (scrub_opts.marker & FOM_SETTOS) {
				yyerror("set-tos cannot be respecified");
				YYERROR;
			}
			scrub_opts.marker |= FOM_SETTOS;
			scrub_opts.settos = yyvsp[0].v.number;
		}
break;
case 68:
#line 1012 "parse.y"
{
			if (strcasecmp(yyvsp[0].v.string, "tcp") != 0) {
				yyerror("scrub reassemble supports only tcp, "
				    "not '%s'", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
			if (scrub_opts.reassemble_tcp) {
				yyerror("reassemble tcp cannot be respecified");
				YYERROR;
			}
			scrub_opts.reassemble_tcp = 1;
		}
break;
case 69:
#line 1026 "parse.y"
{
			if (scrub_opts.randomid) {
				yyerror("random-id cannot be respecified");
				YYERROR;
			}
			scrub_opts.randomid = 1;
		}
break;
case 70:
#line 1035 "parse.y"
{
			struct pf_rule		 r;
			struct node_host	*h = NULL, *hh;
			struct node_if		*i, *j;

			if (check_rulestate(PFCTL_STATE_FILTER))
				YYERROR;

			for (i = yyvsp[-2].v.interface; i; i = i->next) {
				bzero(&r, sizeof(r));

				r.action = PF_DROP;
				r.direction = PF_IN;
				r.log = yyvsp[-3].v.logquick.log;
				r.logif = yyvsp[-3].v.logquick.logif;
				r.quick = yyvsp[-3].v.logquick.quick;
				r.af = yyvsp[-1].v.i;
				if (rule_label(&r, yyvsp[0].v.antispoof_opts.label))
					YYERROR;
				r.rtableid = yyvsp[0].v.antispoof_opts.rtableid;
				j = calloc(1, sizeof(struct node_if));
				if (j == NULL)
					err(1, "antispoof: calloc");
				if (strlcpy(j->ifname, i->ifname,
				    sizeof(j->ifname)) >= sizeof(j->ifname)) {
					free(j);
					yyerror("interface name too long");
					YYERROR;
				}
				j->not = 1;
				if (i->dynamic) {
					h = calloc(1, sizeof(*h));
					if (h == NULL)
						err(1, "address: calloc");
					h->addr.type = PF_ADDR_DYNIFTL;
					set_ipmask(h, 128);
					if (strlcpy(h->addr.v.ifname, i->ifname,
					    sizeof(h->addr.v.ifname)) >=
					    sizeof(h->addr.v.ifname)) {
						free(h);
						yyerror(
						    "interface name too long");
						YYERROR;
					}
					hh = malloc(sizeof(*hh));
					if (hh == NULL)
						 err(1, "address: malloc");
					bcopy(h, hh, sizeof(*hh));
					h->addr.iflags = PFI_AFLAG_NETWORK;
				} else {
					h = ifa_lookup(j->ifname,
					    PFI_AFLAG_NETWORK);
					hh = NULL;
				}

				if (h != NULL)
					expand_rule(&r, 0, j, NULL, NULL, NULL,
					    NULL, NULL, h, NULL, NULL, NULL,
					    NULL, NULL, NULL, NULL, "");

				if ((i->ifa_flags & IFF_LOOPBACK) == 0) {
					bzero(&r, sizeof(r));

					r.action = PF_DROP;
					r.direction = PF_IN;
					r.log = yyvsp[-3].v.logquick.log;
					r.logif = yyvsp[-3].v.logquick.logif;
					r.quick = yyvsp[-3].v.logquick.quick;
					r.af = yyvsp[-1].v.i;
					if (rule_label(&r, yyvsp[0].v.antispoof_opts.label))
						YYERROR;
					r.rtableid = yyvsp[0].v.antispoof_opts.rtableid;
					if (hh != NULL)
						h = hh;
					else
						h = ifa_lookup(i->ifname, 0);
					if (h != NULL)
						expand_rule(&r, 0, NULL, NULL,
						    NULL, NULL, NULL, NULL, h,
						    NULL, NULL, NULL, NULL,
						    NULL, NULL, NULL, "");
				} else
					free(hh);
			}
			free(yyvsp[0].v.antispoof_opts.label);
		}
break;
case 71:
#line 1123 "parse.y"
{ yyval.v.interface = yyvsp[0].v.interface; }
break;
case 72:
#line 1124 "parse.y"
{ yyval.v.interface = yyvsp[-1].v.interface; }
break;
case 73:
#line 1127 "parse.y"
{ yyval.v.interface = yyvsp[-1].v.interface; }
break;
case 74:
#line 1128 "parse.y"
{
			yyvsp[-3].v.interface->tail->next = yyvsp[-1].v.interface;
			yyvsp[-3].v.interface->tail = yyvsp[-1].v.interface;
			yyval.v.interface = yyvsp[-3].v.interface;
		}
break;
case 75:
#line 1135 "parse.y"
{ yyval.v.interface = yyvsp[0].v.interface; }
break;
case 76:
#line 1136 "parse.y"
{
			yyvsp[-1].v.interface->dynamic = 1;
			yyval.v.interface = yyvsp[-1].v.interface;
		}
break;
case 77:
#line 1142 "parse.y"
{
				bzero(&antispoof_opts, sizeof antispoof_opts);
				antispoof_opts.rtableid = -1;
			}
break;
case 78:
#line 1147 "parse.y"
{ yyval.v.antispoof_opts = antispoof_opts; }
break;
case 79:
#line 1148 "parse.y"
{
			bzero(&antispoof_opts, sizeof antispoof_opts);
			antispoof_opts.rtableid = -1;
			yyval.v.antispoof_opts = antispoof_opts;
		}
break;
case 82:
#line 1159 "parse.y"
{
			if (antispoof_opts.label) {
				yyerror("label cannot be redefined");
				YYERROR;
			}
			antispoof_opts.label = yyvsp[0].v.string;
		}
break;
case 83:
#line 1166 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > RT_TABLEID_MAX) {
				yyerror("invalid rtable id");
				YYERROR;
			}
			antispoof_opts.rtableid = yyvsp[0].v.number;
		}
break;
case 84:
#line 1175 "parse.y"
{ yyval.v.number = 1; }
break;
case 85:
#line 1176 "parse.y"
{ yyval.v.number = 0; }
break;
case 86:
#line 1179 "parse.y"
{
			struct node_host	 *h, *nh;
			struct node_tinit	 *ti, *nti;

			if (strlen(yyvsp[-2].v.string) >= PF_TABLE_NAME_SIZE) {
				yyerror("table name too long, max %d chars",
				    PF_TABLE_NAME_SIZE - 1);
				free(yyvsp[-2].v.string);
				YYERROR;
			}
			if (process_tabledef(yyvsp[-2].v.string, &yyvsp[0].v.table_opts)) {
				free(yyvsp[-2].v.string);
				YYERROR;
			}
			free(yyvsp[-2].v.string);
			for (ti = SIMPLEQ_FIRST(&yyvsp[0].v.table_opts.init_nodes);
			    ti != SIMPLEQ_END(&yyvsp[0].v.table_opts.init_nodes); ti = nti) {
				if (ti->file)
					free(ti->file);
				for (h = ti->host; h != NULL; h = nh) {
					nh = h->next;
					free(h);
				}
				nti = SIMPLEQ_NEXT(ti, entries);
				free(ti);
			}
		}
break;
case 87:
#line 1208 "parse.y"
{
			bzero(&table_opts, sizeof table_opts);
			SIMPLEQ_INIT(&table_opts.init_nodes);
		}
break;
case 88:
#line 1213 "parse.y"
{ yyval.v.table_opts = table_opts; }
break;
case 89:
#line 1215 "parse.y"
{
			bzero(&table_opts, sizeof table_opts);
			SIMPLEQ_INIT(&table_opts.init_nodes);
			yyval.v.table_opts = table_opts;
		}
break;
case 92:
#line 1226 "parse.y"
{
			if (!strcmp(yyvsp[0].v.string, "const"))
				table_opts.flags |= PFR_TFLAG_CONST;
			else if (!strcmp(yyvsp[0].v.string, "persist"))
				table_opts.flags |= PFR_TFLAG_PERSIST;
			else if (!strcmp(yyvsp[0].v.string, "counters"))
				table_opts.flags |= PFR_TFLAG_COUNTERS;
			else {
				yyerror("invalid table option '%s'", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 93:
#line 1240 "parse.y"
{ table_opts.init_addr = 1; }
break;
case 94:
#line 1241 "parse.y"
{
			struct node_host	*n;
			struct node_tinit	*ti;

			for (n = yyvsp[-1].v.host; n != NULL; n = n->next) {
				switch (n->addr.type) {
				case PF_ADDR_ADDRMASK:
					continue; /* ok */
				case PF_ADDR_RANGE:
					yyerror("address ranges are not "
					    "permitted inside tables");
					break;
				case PF_ADDR_DYNIFTL:
					yyerror("dynamic addresses are not "
					    "permitted inside tables");
					break;
				case PF_ADDR_TABLE:
					yyerror("tables cannot contain tables");
					break;
				case PF_ADDR_NOROUTE:
					yyerror("\"no-route\" is not permitted "
					    "inside tables");
					break;
				case PF_ADDR_URPFFAILED:
					yyerror("\"urpf-failed\" is not "
					    "permitted inside tables");
					break;
				default:
					yyerror("unknown address type %d",
					    n->addr.type);
				}
				YYERROR;
			}
			if (!(ti = calloc(1, sizeof(*ti))))
				err(1, "table_opt: calloc");
			ti->host = yyvsp[-1].v.host;
			SIMPLEQ_INSERT_TAIL(&table_opts.init_nodes, ti,
			    entries);
			table_opts.init_addr = 1;
		}
break;
case 95:
#line 1281 "parse.y"
{
			struct node_tinit	*ti;

			if (!(ti = calloc(1, sizeof(*ti))))
				err(1, "table_opt: calloc");
			ti->file = yyvsp[0].v.string;
			SIMPLEQ_INSERT_TAIL(&table_opts.init_nodes, ti,
			    entries);
			table_opts.init_addr = 1;
		}
break;
case 96:
#line 1293 "parse.y"
{
			struct pf_altq	a;

			if (check_rulestate(PFCTL_STATE_QUEUE))
				YYERROR;

			memset(&a, 0, sizeof(a));
			if (yyvsp[-2].v.queue_opts.scheduler.qtype == ALTQT_NONE) {
				yyerror("no scheduler specified!");
				YYERROR;
			}
			a.scheduler = yyvsp[-2].v.queue_opts.scheduler.qtype;
			a.qlimit = yyvsp[-2].v.queue_opts.qlimit;
			a.tbrsize = yyvsp[-2].v.queue_opts.tbrsize;
			if (yyvsp[0].v.queue == NULL) {
				yyerror("no child queues specified");
				YYERROR;
			}
			if (expand_altq(&a, yyvsp[-3].v.interface, yyvsp[0].v.queue, yyvsp[-2].v.queue_opts.queue_bwspec,
			    &yyvsp[-2].v.queue_opts.scheduler))
				YYERROR;
		}
break;
case 97:
#line 1317 "parse.y"
{
			struct pf_altq	a;

			if (check_rulestate(PFCTL_STATE_QUEUE)) {
				free(yyvsp[-3].v.string);
				YYERROR;
			}

			memset(&a, 0, sizeof(a));

			if (strlcpy(a.qname, yyvsp[-3].v.string, sizeof(a.qname)) >=
			    sizeof(a.qname)) {
				yyerror("queue name too long (max "
				    "%d chars)", PF_QNAME_SIZE-1);
				free(yyvsp[-3].v.string);
				YYERROR;
			}
			free(yyvsp[-3].v.string);
			if (yyvsp[-1].v.queue_opts.tbrsize) {
				yyerror("cannot specify tbrsize for queue");
				YYERROR;
			}
			if (yyvsp[-1].v.queue_opts.priority > 255) {
				yyerror("priority out of range: max 255");
				YYERROR;
			}
			a.priority = yyvsp[-1].v.queue_opts.priority;
			a.qlimit = yyvsp[-1].v.queue_opts.qlimit;
			a.scheduler = yyvsp[-1].v.queue_opts.scheduler.qtype;
			if (expand_queue(&a, yyvsp[-2].v.interface, yyvsp[0].v.queue, yyvsp[-1].v.queue_opts.queue_bwspec,
			    &yyvsp[-1].v.queue_opts.scheduler)) {
				yyerror("errors in queue definition");
				YYERROR;
			}
		}
break;
case 98:
#line 1354 "parse.y"
{
			bzero(&queue_opts, sizeof queue_opts);
			queue_opts.priority = DEFAULT_PRIORITY;
			queue_opts.qlimit = DEFAULT_QLIMIT;
			queue_opts.scheduler.qtype = ALTQT_NONE;
			queue_opts.queue_bwspec.bw_percent = 100;
		}
break;
case 99:
#line 1362 "parse.y"
{ yyval.v.queue_opts = queue_opts; }
break;
case 100:
#line 1363 "parse.y"
{
			bzero(&queue_opts, sizeof queue_opts);
			queue_opts.priority = DEFAULT_PRIORITY;
			queue_opts.qlimit = DEFAULT_QLIMIT;
			queue_opts.scheduler.qtype = ALTQT_NONE;
			queue_opts.queue_bwspec.bw_percent = 100;
			yyval.v.queue_opts = queue_opts;
		}
break;
case 103:
#line 1377 "parse.y"
{
			if (queue_opts.marker & QOM_BWSPEC) {
				yyerror("bandwidth cannot be respecified");
				YYERROR;
			}
			queue_opts.marker |= QOM_BWSPEC;
			queue_opts.queue_bwspec = yyvsp[0].v.queue_bwspec;
		}
break;
case 104:
#line 1385 "parse.y"
{
			if (queue_opts.marker & QOM_PRIORITY) {
				yyerror("priority cannot be respecified");
				YYERROR;
			}
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > 255) {
				yyerror("priority out of range: max 255");
				YYERROR;
			}
			queue_opts.marker |= QOM_PRIORITY;
			queue_opts.priority = yyvsp[0].v.number;
		}
break;
case 105:
#line 1397 "parse.y"
{
			if (queue_opts.marker & QOM_QLIMIT) {
				yyerror("qlimit cannot be respecified");
				YYERROR;
			}
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > 65535) {
				yyerror("qlimit out of range: max 65535");
				YYERROR;
			}
			queue_opts.marker |= QOM_QLIMIT;
			queue_opts.qlimit = yyvsp[0].v.number;
		}
break;
case 106:
#line 1409 "parse.y"
{
			if (queue_opts.marker & QOM_SCHEDULER) {
				yyerror("scheduler cannot be respecified");
				YYERROR;
			}
			queue_opts.marker |= QOM_SCHEDULER;
			queue_opts.scheduler = yyvsp[0].v.queue_options;
		}
break;
case 107:
#line 1417 "parse.y"
{
			if (queue_opts.marker & QOM_TBRSIZE) {
				yyerror("tbrsize cannot be respecified");
				YYERROR;
			}
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > 65535) {
				yyerror("tbrsize too big: max 65535");
				YYERROR;
			}
			queue_opts.marker |= QOM_TBRSIZE;
			queue_opts.tbrsize = yyvsp[0].v.number;
		}
break;
case 108:
#line 1431 "parse.y"
{
			double	 bps;
			char	*cp;

			yyval.v.queue_bwspec.bw_percent = 0;

			bps = strtod(yyvsp[0].v.string, &cp);
			if (cp != NULL) {
				if (!strcmp(cp, "b"))
					; /* nothing */
				else if (!strcmp(cp, "Kb"))
					bps *= 1000;
				else if (!strcmp(cp, "Mb"))
					bps *= 1000 * 1000;
				else if (!strcmp(cp, "Gb"))
					bps *= 1000 * 1000 * 1000;
				else if (!strcmp(cp, "%")) {
					if (bps < 0 || bps > 100) {
						yyerror("bandwidth spec "
						    "out of range");
						free(yyvsp[0].v.string);
						YYERROR;
					}
					yyval.v.queue_bwspec.bw_percent = bps;
					bps = 0;
				} else {
					yyerror("unknown unit %s", cp);
					free(yyvsp[0].v.string);
					YYERROR;
				}
			}
			free(yyvsp[0].v.string);
			yyval.v.queue_bwspec.bw_absolute = (u_int32_t)bps;
		}
break;
case 109:
#line 1465 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > UINT_MAX) {
				yyerror("bandwidth number too big");
				YYERROR;
			}
			yyval.v.queue_bwspec.bw_percent = 0;
			yyval.v.queue_bwspec.bw_absolute = yyvsp[0].v.number;
		}
break;
case 110:
#line 1475 "parse.y"
{
			yyval.v.queue_options.qtype = ALTQT_CBQ;
			yyval.v.queue_options.data.cbq_opts.flags = 0;
		}
break;
case 111:
#line 1479 "parse.y"
{
			yyval.v.queue_options.qtype = ALTQT_CBQ;
			yyval.v.queue_options.data.cbq_opts.flags = yyvsp[-1].v.number;
		}
break;
case 112:
#line 1483 "parse.y"
{
			yyval.v.queue_options.qtype = ALTQT_PRIQ;
			yyval.v.queue_options.data.priq_opts.flags = 0;
		}
break;
case 113:
#line 1487 "parse.y"
{
			yyval.v.queue_options.qtype = ALTQT_PRIQ;
			yyval.v.queue_options.data.priq_opts.flags = yyvsp[-1].v.number;
		}
break;
case 114:
#line 1491 "parse.y"
{
			yyval.v.queue_options.qtype = ALTQT_HFSC;
			bzero(&yyval.v.queue_options.data.hfsc_opts,
			    sizeof(struct node_hfsc_opts));
		}
break;
case 115:
#line 1496 "parse.y"
{
			yyval.v.queue_options.qtype = ALTQT_HFSC;
			yyval.v.queue_options.data.hfsc_opts = yyvsp[-1].v.hfsc_opts;
		}
break;
case 116:
#line 1502 "parse.y"
{ yyval.v.number |= yyvsp[0].v.number; }
break;
case 117:
#line 1503 "parse.y"
{ yyval.v.number |= yyvsp[0].v.number; }
break;
case 118:
#line 1506 "parse.y"
{
			if (!strcmp(yyvsp[0].v.string, "default"))
				yyval.v.number = CBQCLF_DEFCLASS;
			else if (!strcmp(yyvsp[0].v.string, "borrow"))
				yyval.v.number = CBQCLF_BORROW;
			else if (!strcmp(yyvsp[0].v.string, "red"))
				yyval.v.number = CBQCLF_RED;
			else if (!strcmp(yyvsp[0].v.string, "ecn"))
				yyval.v.number = CBQCLF_RED|CBQCLF_ECN;
			else if (!strcmp(yyvsp[0].v.string, "rio"))
				yyval.v.number = CBQCLF_RIO;
			else {
				yyerror("unknown cbq flag \"%s\"", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 119:
#line 1526 "parse.y"
{ yyval.v.number |= yyvsp[0].v.number; }
break;
case 120:
#line 1527 "parse.y"
{ yyval.v.number |= yyvsp[0].v.number; }
break;
case 121:
#line 1530 "parse.y"
{
			if (!strcmp(yyvsp[0].v.string, "default"))
				yyval.v.number = PRCF_DEFAULTCLASS;
			else if (!strcmp(yyvsp[0].v.string, "red"))
				yyval.v.number = PRCF_RED;
			else if (!strcmp(yyvsp[0].v.string, "ecn"))
				yyval.v.number = PRCF_RED|PRCF_ECN;
			else if (!strcmp(yyvsp[0].v.string, "rio"))
				yyval.v.number = PRCF_RIO;
			else {
				yyerror("unknown priq flag \"%s\"", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 122:
#line 1548 "parse.y"
{
				bzero(&hfsc_opts,
				    sizeof(struct node_hfsc_opts));
			}
break;
case 123:
#line 1552 "parse.y"
{
			yyval.v.hfsc_opts = hfsc_opts;
		}
break;
case 126:
#line 1561 "parse.y"
{
			if (hfsc_opts.linkshare.used) {
				yyerror("linkshare already specified");
				YYERROR;
			}
			hfsc_opts.linkshare.m2 = yyvsp[0].v.queue_bwspec;
			hfsc_opts.linkshare.used = 1;
		}
break;
case 127:
#line 1570 "parse.y"
{
			if (yyvsp[-3].v.number < 0 || yyvsp[-3].v.number > INT_MAX) {
				yyerror("timing in curve out of range");
				YYERROR;
			}
			if (hfsc_opts.linkshare.used) {
				yyerror("linkshare already specified");
				YYERROR;
			}
			hfsc_opts.linkshare.m1 = yyvsp[-5].v.queue_bwspec;
			hfsc_opts.linkshare.d = yyvsp[-3].v.number;
			hfsc_opts.linkshare.m2 = yyvsp[-1].v.queue_bwspec;
			hfsc_opts.linkshare.used = 1;
		}
break;
case 128:
#line 1584 "parse.y"
{
			if (hfsc_opts.realtime.used) {
				yyerror("realtime already specified");
				YYERROR;
			}
			hfsc_opts.realtime.m2 = yyvsp[0].v.queue_bwspec;
			hfsc_opts.realtime.used = 1;
		}
break;
case 129:
#line 1593 "parse.y"
{
			if (yyvsp[-3].v.number < 0 || yyvsp[-3].v.number > INT_MAX) {
				yyerror("timing in curve out of range");
				YYERROR;
			}
			if (hfsc_opts.realtime.used) {
				yyerror("realtime already specified");
				YYERROR;
			}
			hfsc_opts.realtime.m1 = yyvsp[-5].v.queue_bwspec;
			hfsc_opts.realtime.d = yyvsp[-3].v.number;
			hfsc_opts.realtime.m2 = yyvsp[-1].v.queue_bwspec;
			hfsc_opts.realtime.used = 1;
		}
break;
case 130:
#line 1607 "parse.y"
{
			if (hfsc_opts.upperlimit.used) {
				yyerror("upperlimit already specified");
				YYERROR;
			}
			hfsc_opts.upperlimit.m2 = yyvsp[0].v.queue_bwspec;
			hfsc_opts.upperlimit.used = 1;
		}
break;
case 131:
#line 1616 "parse.y"
{
			if (yyvsp[-3].v.number < 0 || yyvsp[-3].v.number > INT_MAX) {
				yyerror("timing in curve out of range");
				YYERROR;
			}
			if (hfsc_opts.upperlimit.used) {
				yyerror("upperlimit already specified");
				YYERROR;
			}
			hfsc_opts.upperlimit.m1 = yyvsp[-5].v.queue_bwspec;
			hfsc_opts.upperlimit.d = yyvsp[-3].v.number;
			hfsc_opts.upperlimit.m2 = yyvsp[-1].v.queue_bwspec;
			hfsc_opts.upperlimit.used = 1;
		}
break;
case 132:
#line 1630 "parse.y"
{
			if (!strcmp(yyvsp[0].v.string, "default"))
				hfsc_opts.flags |= HFCF_DEFAULTCLASS;
			else if (!strcmp(yyvsp[0].v.string, "red"))
				hfsc_opts.flags |= HFCF_RED;
			else if (!strcmp(yyvsp[0].v.string, "ecn"))
				hfsc_opts.flags |= HFCF_RED|HFCF_ECN;
			else if (!strcmp(yyvsp[0].v.string, "rio"))
				hfsc_opts.flags |= HFCF_RIO;
			else {
				yyerror("unknown hfsc flag \"%s\"", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 133:
#line 1648 "parse.y"
{ yyval.v.queue = NULL; }
break;
case 134:
#line 1649 "parse.y"
{ yyval.v.queue = yyvsp[0].v.queue; }
break;
case 135:
#line 1650 "parse.y"
{ yyval.v.queue = yyvsp[-1].v.queue; }
break;
case 136:
#line 1653 "parse.y"
{ yyval.v.queue = yyvsp[-1].v.queue; }
break;
case 137:
#line 1654 "parse.y"
{
			yyvsp[-3].v.queue->tail->next = yyvsp[-1].v.queue;
			yyvsp[-3].v.queue->tail = yyvsp[-1].v.queue;
			yyval.v.queue = yyvsp[-3].v.queue;
		}
break;
case 138:
#line 1661 "parse.y"
{
			yyval.v.queue = calloc(1, sizeof(struct node_queue));
			if (yyval.v.queue == NULL)
				err(1, "qassign_item: calloc");
			if (strlcpy(yyval.v.queue->queue, yyvsp[0].v.string, sizeof(yyval.v.queue->queue)) >=
			    sizeof(yyval.v.queue->queue)) {
				yyerror("queue name '%s' too long (max "
				    "%d chars)", yyvsp[0].v.string, sizeof(yyval.v.queue->queue)-1);
				free(yyvsp[0].v.string);
				free(yyval.v.queue);
				YYERROR;
			}
			free(yyvsp[0].v.string);
			yyval.v.queue->next = NULL;
			yyval.v.queue->tail = yyval.v.queue;
		}
break;
case 139:
#line 1681 "parse.y"
{
			struct pf_rule		 r;
			struct node_state_opt	*o;
			struct node_proto	*proto;
			int			 srctrack = 0;
			int			 statelock = 0;
			int			 adaptive = 0;
			int			 defaults = 0;

			if (check_rulestate(PFCTL_STATE_FILTER))
				YYERROR;

			memset(&r, 0, sizeof(r));

			r.action = yyvsp[-7].v.b.b1;
			switch (yyvsp[-7].v.b.b2) {
			case PFRULE_RETURNRST:
				r.rule_flag |= PFRULE_RETURNRST;
				r.return_ttl = yyvsp[-7].v.b.w;
				break;
			case PFRULE_RETURNICMP:
				r.rule_flag |= PFRULE_RETURNICMP;
				r.return_icmp = yyvsp[-7].v.b.w;
				r.return_icmp6 = yyvsp[-7].v.b.w2;
				break;
			case PFRULE_RETURN:
				r.rule_flag |= PFRULE_RETURN;
				r.return_icmp = yyvsp[-7].v.b.w;
				r.return_icmp6 = yyvsp[-7].v.b.w2;
				break;
			}
			r.direction = yyvsp[-6].v.i;
			r.log = yyvsp[-5].v.logquick.log;
			r.logif = yyvsp[-5].v.logquick.logif;
			r.quick = yyvsp[-5].v.logquick.quick;
			r.prob = yyvsp[0].v.filter_opts.prob;
			r.rtableid = yyvsp[0].v.filter_opts.rtableid;

			if (yyvsp[0].v.filter_opts.nodf)
				r.scrub_flags |= PFSTATE_NODF;
			if (yyvsp[0].v.filter_opts.randomid)
				r.scrub_flags |= PFSTATE_RANDOMID;
			if (yyvsp[0].v.filter_opts.minttl)
				r.min_ttl = yyvsp[0].v.filter_opts.minttl;
			if (yyvsp[0].v.filter_opts.max_mss)
				r.max_mss = yyvsp[0].v.filter_opts.max_mss;
			if (yyvsp[0].v.filter_opts.marker & FOM_SETTOS) {
				r.scrub_flags |= PFSTATE_SETTOS;
				r.set_tos = yyvsp[0].v.filter_opts.settos;
			}
			if (yyvsp[0].v.filter_opts.marker & FOM_SCRUB_TCP)
				r.scrub_flags |= PFSTATE_SCRUB_TCP;

			r.af = yyvsp[-3].v.i;
			if (yyvsp[0].v.filter_opts.tag)
				if (strlcpy(r.tagname, yyvsp[0].v.filter_opts.tag,
				    PF_TAG_NAME_SIZE) >= PF_TAG_NAME_SIZE) {
					yyerror("tag too long, max %u chars",
					    PF_TAG_NAME_SIZE - 1);
					YYERROR;
				}
			if (yyvsp[0].v.filter_opts.match_tag)
				if (strlcpy(r.match_tagname, yyvsp[0].v.filter_opts.match_tag,
				    PF_TAG_NAME_SIZE) >= PF_TAG_NAME_SIZE) {
					yyerror("tag too long, max %u chars",
					    PF_TAG_NAME_SIZE - 1);
					YYERROR;
				}
			r.match_tag_not = yyvsp[0].v.filter_opts.match_tag_not;
			if (rule_label(&r, yyvsp[0].v.filter_opts.label))
				YYERROR;
			free(yyvsp[0].v.filter_opts.label);
			r.flags = yyvsp[0].v.filter_opts.flags.b1;
			r.flagset = yyvsp[0].v.filter_opts.flags.b2;
			if ((yyvsp[0].v.filter_opts.flags.b1 & yyvsp[0].v.filter_opts.flags.b2) != yyvsp[0].v.filter_opts.flags.b1) {
				yyerror("flags always false");
				YYERROR;
			}
			if (yyvsp[0].v.filter_opts.flags.b1 || yyvsp[0].v.filter_opts.flags.b2 || yyvsp[-1].v.fromto.src_os) {
				for (proto = yyvsp[-2].v.proto; proto != NULL &&
				    proto->proto != IPPROTO_TCP;
				    proto = proto->next)
					;	/* nothing */
				if (proto == NULL && yyvsp[-2].v.proto != NULL) {
					if (yyvsp[0].v.filter_opts.flags.b1 || yyvsp[0].v.filter_opts.flags.b2)
						yyerror(
						    "flags only apply to tcp");
					if (yyvsp[-1].v.fromto.src_os)
						yyerror(
						    "OS fingerprinting only "
						    "apply to tcp");
					YYERROR;
				}
#if 0
				if ((yyvsp[0].v.filter_opts.flags.b1 & parse_flags("S")) == 0 &&
				    yyvsp[-1].v.fromto.src_os) {
					yyerror("OS fingerprinting requires "
					    "the SYN TCP flag (flags S/SA)");
					YYERROR;
				}
#endif
			}

			r.tos = yyvsp[0].v.filter_opts.tos;
			r.keep_state = yyvsp[0].v.filter_opts.keep.action;
			o = yyvsp[0].v.filter_opts.keep.options;

			/* 'keep state' by default on pass rules. */
			if (!r.keep_state && !r.action &&
			    !(yyvsp[0].v.filter_opts.marker & FOM_KEEP)) {
				r.keep_state = PF_STATE_NORMAL;
				o = keep_state_defaults;
				defaults = 1;
			}

			while (o) {
				struct node_state_opt	*p = o;

				switch (o->type) {
				case PF_STATE_OPT_MAX:
					if (r.max_states) {
						yyerror("state option 'max' "
						    "multiple definitions");
						YYERROR;
					}
					r.max_states = o->data.max_states;
					break;
				case PF_STATE_OPT_NOSYNC:
					if (r.rule_flag & PFRULE_NOSYNC) {
						yyerror("state option 'sync' "
						    "multiple definitions");
						YYERROR;
					}
					r.rule_flag |= PFRULE_NOSYNC;
					break;
				case PF_STATE_OPT_SRCTRACK:
					if (srctrack) {
						yyerror("state option "
						    "'source-track' "
						    "multiple definitions");
						YYERROR;
					}
					srctrack =  o->data.src_track;
					r.rule_flag |= PFRULE_SRCTRACK;
					break;
				case PF_STATE_OPT_MAX_SRC_STATES:
					if (r.max_src_states) {
						yyerror("state option "
						    "'max-src-states' "
						    "multiple definitions");
						YYERROR;
					}
					if (o->data.max_src_states == 0) {
						yyerror("'max-src-states' must "
						    "be > 0");
						YYERROR;
					}
					r.max_src_states =
					    o->data.max_src_states;
					r.rule_flag |= PFRULE_SRCTRACK;
					break;
				case PF_STATE_OPT_OVERLOAD:
					if (r.overload_tblname[0]) {
						yyerror("multiple 'overload' "
						    "table definitions");
						YYERROR;
					}
					if (strlcpy(r.overload_tblname,
					    o->data.overload.tblname,
					    PF_TABLE_NAME_SIZE) >=
					    PF_TABLE_NAME_SIZE) {
						yyerror("state option: "
						    "strlcpy");
						YYERROR;
					}
					r.flush = o->data.overload.flush;
					break;
				case PF_STATE_OPT_MAX_SRC_CONN:
					if (r.max_src_conn) {
						yyerror("state option "
						    "'max-src-conn' "
						    "multiple definitions");
						YYERROR;
					}
					if (o->data.max_src_conn == 0) {
						yyerror("'max-src-conn' "
						    "must be > 0");
						YYERROR;
					}
					r.max_src_conn =
					    o->data.max_src_conn;
					r.rule_flag |= PFRULE_SRCTRACK |
					    PFRULE_RULESRCTRACK;
					break;
				case PF_STATE_OPT_MAX_SRC_CONN_RATE:
					if (r.max_src_conn_rate.limit) {
						yyerror("state option "
						    "'max-src-conn-rate' "
						    "multiple definitions");
						YYERROR;
					}
					if (!o->data.max_src_conn_rate.limit ||
					    !o->data.max_src_conn_rate.seconds) {
						yyerror("'max-src-conn-rate' "
						    "values must be > 0");
						YYERROR;
					}
					if (o->data.max_src_conn_rate.limit >
					    PF_THRESHOLD_MAX) {
						yyerror("'max-src-conn-rate' "
						    "maximum rate must be < %u",
						    PF_THRESHOLD_MAX);
						YYERROR;
					}
					r.max_src_conn_rate.limit =
					    o->data.max_src_conn_rate.limit;
					r.max_src_conn_rate.seconds =
					    o->data.max_src_conn_rate.seconds;
					r.rule_flag |= PFRULE_SRCTRACK |
					    PFRULE_RULESRCTRACK;
					break;
				case PF_STATE_OPT_MAX_SRC_NODES:
					if (r.max_src_nodes) {
						yyerror("state option "
						    "'max-src-nodes' "
						    "multiple definitions");
						YYERROR;
					}
					if (o->data.max_src_nodes == 0) {
						yyerror("'max-src-nodes' must "
						    "be > 0");
						YYERROR;
					}
					r.max_src_nodes =
					    o->data.max_src_nodes;
					r.rule_flag |= PFRULE_SRCTRACK |
					    PFRULE_RULESRCTRACK;
					break;
				case PF_STATE_OPT_STATELOCK:
					if (statelock) {
						yyerror("state locking option: "
						    "multiple definitions");
						YYERROR;
					}
					statelock = 1;
					r.rule_flag |= o->data.statelock;
					break;
				case PF_STATE_OPT_SLOPPY:
					if (r.rule_flag & PFRULE_STATESLOPPY) {
						yyerror("state sloppy option: "
						    "multiple definitions");
						YYERROR;
					}
					r.rule_flag |= PFRULE_STATESLOPPY;
					break;
				case PF_STATE_OPT_PFLOW:
					if (r.rule_flag & PFRULE_PFLOW) {
						yyerror("state pflow "
						    "option: multiple "
						    "definitions");
						YYERROR;
					}
					r.rule_flag |= PFRULE_PFLOW;
					break;
				case PF_STATE_OPT_TIMEOUT:
					if (o->data.timeout.number ==
					    PFTM_ADAPTIVE_START ||
					    o->data.timeout.number ==
					    PFTM_ADAPTIVE_END)
						adaptive = 1;
					if (r.timeout[o->data.timeout.number]) {
						yyerror("state timeout %s "
						    "multiple definitions",
						    pf_timeouts[o->data.
						    timeout.number].name);
						YYERROR;
					}
					r.timeout[o->data.timeout.number] =
					    o->data.timeout.seconds;
				}
				o = o->next;
				if (!defaults)
					free(p);
			}

			/* 'flags S/SA' by default on stateful rules */
			if (!r.action && !r.flags && !r.flagset &&
			    !yyvsp[0].v.filter_opts.fragment && !(yyvsp[0].v.filter_opts.marker & FOM_FLAGS) &&
			    r.keep_state) {
				r.flags = parse_flags("S");
				r.flagset =  parse_flags("SA");
			}
			if (!adaptive && r.max_states) {
				r.timeout[PFTM_ADAPTIVE_START] =
				    (r.max_states / 10) * 6;
				r.timeout[PFTM_ADAPTIVE_END] =
				    (r.max_states / 10) * 12;
			}
			if (r.rule_flag & PFRULE_SRCTRACK) {
				if (srctrack == PF_SRCTRACK_GLOBAL &&
				    r.max_src_nodes) {
					yyerror("'max-src-nodes' is "
					    "incompatible with "
					    "'source-track global'");
					YYERROR;
				}
				if (srctrack == PF_SRCTRACK_GLOBAL &&
				    r.max_src_conn) {
					yyerror("'max-src-conn' is "
					    "incompatible with "
					    "'source-track global'");
					YYERROR;
				}
				if (srctrack == PF_SRCTRACK_GLOBAL &&
				    r.max_src_conn_rate.seconds) {
					yyerror("'max-src-conn-rate' is "
					    "incompatible with "
					    "'source-track global'");
					YYERROR;
				}
				if (r.timeout[PFTM_SRC_NODE] <
				    r.max_src_conn_rate.seconds)
					r.timeout[PFTM_SRC_NODE] =
					    r.max_src_conn_rate.seconds;
				r.rule_flag |= PFRULE_SRCTRACK;
				if (srctrack == PF_SRCTRACK_RULE)
					r.rule_flag |= PFRULE_RULESRCTRACK;
			}
			if (r.keep_state && !statelock)
				r.rule_flag |= default_statelock;

			if (yyvsp[0].v.filter_opts.fragment)
				r.rule_flag |= PFRULE_FRAGMENT;
			r.allow_opts = yyvsp[0].v.filter_opts.allowopts;

			decide_address_family(yyvsp[-1].v.fromto.src.host, &r.af);
			decide_address_family(yyvsp[-1].v.fromto.dst.host, &r.af);

			if (yyvsp[0].v.filter_opts.route.rt) {
				if (!r.direction) {
					yyerror("direction must be explicit "
					    "with rules that specify routing");
					YYERROR;
				}
				r.rt = yyvsp[0].v.filter_opts.route.rt;
				r.route.opts = yyvsp[0].v.filter_opts.route.pool_opts;
				if (yyvsp[0].v.filter_opts.route.key != NULL)
					memcpy(&r.route.key, yyvsp[0].v.filter_opts.route.key,
					    sizeof(struct pf_poolhashkey));
			}
			if (r.rt && r.rt != PF_FASTROUTE) {
				decide_address_family(yyvsp[0].v.filter_opts.route.host, &r.af);
				if ((r.route.opts & PF_POOL_TYPEMASK) ==
				    PF_POOL_NONE && (yyvsp[0].v.filter_opts.route.host->next != NULL ||
				    yyvsp[0].v.filter_opts.route.host->addr.type == PF_ADDR_TABLE ||
				    DYNIF_MULTIADDR(yyvsp[0].v.filter_opts.route.host->addr)))
					r.route.opts |= PF_POOL_ROUNDROBIN;
				if ((r.route.opts & PF_POOL_TYPEMASK) !=
				    PF_POOL_ROUNDROBIN &&
				    disallow_table(yyvsp[0].v.filter_opts.route.host,
				    "tables are only "
				    "supported in round-robin routing pools"))
					YYERROR;
				if ((r.route.opts & PF_POOL_TYPEMASK) !=
				    PF_POOL_ROUNDROBIN &&
				    disallow_alias(yyvsp[0].v.filter_opts.route.host,
				    "interface (%s) "
				    "is only supported in round-robin "
				    "routing pools"))
					YYERROR;
				if (yyvsp[0].v.filter_opts.route.host->next != NULL) {
					if ((r.route.opts & PF_POOL_TYPEMASK) !=
					    PF_POOL_ROUNDROBIN) {
						yyerror("r.route.opts must "
						    "be PF_POOL_ROUNDROBIN");
						YYERROR;
					}
				}
				/* fake redirspec */
				if ((yyvsp[0].v.filter_opts.rroute.rdr = calloc(1,
				    sizeof(*yyvsp[0].v.filter_opts.rroute.rdr))) == NULL)
					err(1, "$8.rroute.rdr");
				yyvsp[0].v.filter_opts.rroute.rdr->host = yyvsp[0].v.filter_opts.route.host;
			}
			if (yyvsp[0].v.filter_opts.queues.qname != NULL) {
				if (strlcpy(r.qname, yyvsp[0].v.filter_opts.queues.qname,
				    sizeof(r.qname)) >= sizeof(r.qname)) {
					yyerror("rule qname too long (max "
					    "%d chars)", sizeof(r.qname)-1);
					YYERROR;
				}
				free(yyvsp[0].v.filter_opts.queues.qname);
			}
			if (yyvsp[0].v.filter_opts.queues.pqname != NULL) {
				if (strlcpy(r.pqname, yyvsp[0].v.filter_opts.queues.pqname,
				    sizeof(r.pqname)) >= sizeof(r.pqname)) {
					yyerror("rule pqname too long (max "
					    "%d chars)", sizeof(r.pqname)-1);
					YYERROR;
				}
				free(yyvsp[0].v.filter_opts.queues.pqname);
			}
			if ((r.divert.port = yyvsp[0].v.filter_opts.divert.port)) {
				if (r.direction == PF_OUT) {
					if (yyvsp[0].v.filter_opts.divert.addr) {
						yyerror("address specified "
						    "for outgoing divert");
						YYERROR;
					}
					bzero(&r.divert.addr,
					    sizeof(r.divert.addr));
				} else {
					if (!yyvsp[0].v.filter_opts.divert.addr) {
						yyerror("no address specified "
						    "for incoming divert");
						YYERROR;
					}
					if (yyvsp[0].v.filter_opts.divert.addr->af != r.af) {
						yyerror("address family "
						    "mismatch for divert");
						YYERROR;
					}
					r.divert.addr =
					    yyvsp[0].v.filter_opts.divert.addr->addr.v.a.addr;
				}
			}
			r.divert_packet.port = yyvsp[0].v.filter_opts.divert_packet.port;

			expand_rule(&r, 0, yyvsp[-4].v.interface, &yyvsp[0].v.filter_opts.nat, &yyvsp[0].v.filter_opts.rdr, &yyvsp[0].v.filter_opts.rroute, yyvsp[-2].v.proto,
			    yyvsp[-1].v.fromto.src_os,
			    yyvsp[-1].v.fromto.src.host, yyvsp[-1].v.fromto.src.port, yyvsp[-1].v.fromto.dst.host, yyvsp[-1].v.fromto.dst.port,
			    yyvsp[0].v.filter_opts.uid, yyvsp[0].v.filter_opts.gid, yyvsp[0].v.filter_opts.rcv, yyvsp[0].v.filter_opts.icmpspec, "");
		}
break;
case 140:
#line 2116 "parse.y"
{
				bzero(&filter_opts, sizeof filter_opts);
				filter_opts.rtableid = -1;
			}
break;
case 141:
#line 2121 "parse.y"
{ yyval.v.filter_opts = filter_opts; }
break;
case 142:
#line 2122 "parse.y"
{
			bzero(&filter_opts, sizeof filter_opts);
			filter_opts.rtableid = -1;
			yyval.v.filter_opts = filter_opts;
		}
break;
case 145:
#line 2133 "parse.y"
{
			if (filter_opts.uid)
				yyvsp[0].v.uid->tail->next = filter_opts.uid;
			filter_opts.uid = yyvsp[0].v.uid;
		}
break;
case 146:
#line 2138 "parse.y"
{
			if (filter_opts.gid)
				yyvsp[0].v.gid->tail->next = filter_opts.gid;
			filter_opts.gid = yyvsp[0].v.gid;
		}
break;
case 147:
#line 2143 "parse.y"
{
			if (filter_opts.marker & FOM_FLAGS) {
				yyerror("flags cannot be redefined");
				YYERROR;
			}
			filter_opts.marker |= FOM_FLAGS;
			filter_opts.flags.b1 |= yyvsp[0].v.b.b1;
			filter_opts.flags.b2 |= yyvsp[0].v.b.b2;
			filter_opts.flags.w |= yyvsp[0].v.b.w;
			filter_opts.flags.w2 |= yyvsp[0].v.b.w2;
		}
break;
case 148:
#line 2154 "parse.y"
{
			if (filter_opts.marker & FOM_ICMP) {
				yyerror("icmp-type cannot be redefined");
				YYERROR;
			}
			filter_opts.marker |= FOM_ICMP;
			filter_opts.icmpspec = yyvsp[0].v.icmp;
		}
break;
case 149:
#line 2162 "parse.y"
{
			if (filter_opts.marker & FOM_TOS) {
				yyerror("tos cannot be redefined");
				YYERROR;
			}
			filter_opts.marker |= FOM_TOS;
			filter_opts.tos = yyvsp[0].v.number;
		}
break;
case 150:
#line 2170 "parse.y"
{
			if (filter_opts.marker & FOM_KEEP) {
				yyerror("modulate or keep cannot be redefined");
				YYERROR;
			}
			filter_opts.marker |= FOM_KEEP;
			filter_opts.keep.action = yyvsp[0].v.keep_state.action;
			filter_opts.keep.options = yyvsp[0].v.keep_state.options;
		}
break;
case 151:
#line 2179 "parse.y"
{
			filter_opts.fragment = 1;
		}
break;
case 152:
#line 2182 "parse.y"
{
			filter_opts.allowopts = 1;
		}
break;
case 153:
#line 2185 "parse.y"
{
			if (filter_opts.label) {
				yyerror("label cannot be redefined");
				YYERROR;
			}
			filter_opts.label = yyvsp[0].v.string;
		}
break;
case 154:
#line 2192 "parse.y"
{
			if (filter_opts.queues.qname) {
				yyerror("queue cannot be redefined");
				YYERROR;
			}
			filter_opts.queues = yyvsp[0].v.qassign;
		}
break;
case 155:
#line 2199 "parse.y"
{
			filter_opts.tag = yyvsp[0].v.string;
		}
break;
case 156:
#line 2202 "parse.y"
{
			filter_opts.match_tag = yyvsp[0].v.string;
			filter_opts.match_tag_not = yyvsp[-2].v.number;
		}
break;
case 157:
#line 2206 "parse.y"
{
			double	p;

			p = floor(yyvsp[0].v.probability * UINT_MAX + 0.5);
			if (p < 0.0 || p > UINT_MAX) {
				yyerror("invalid probability: %g%%", yyvsp[0].v.probability * 100);
				YYERROR;
			}
			filter_opts.prob = (u_int32_t)p;
			if (filter_opts.prob == 0)
				filter_opts.prob = 1;
		}
break;
case 158:
#line 2218 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > RT_TABLEID_MAX) {
				yyerror("invalid rtable id");
				YYERROR;
			}
			filter_opts.rtableid = yyvsp[0].v.number;
		}
break;
case 159:
#line 2225 "parse.y"
{
			if ((filter_opts.divert.addr = host(yyvsp[-2].v.string)) == NULL) {
				yyerror("could not parse divert address: %s",
				    yyvsp[-2].v.string);
				free(yyvsp[-2].v.string);
				YYERROR;
			}
			free(yyvsp[-2].v.string);
			filter_opts.divert.port = yyvsp[0].v.range.a;
			if (!filter_opts.divert.port) {
				yyerror("invalid divert port: %u", ntohs(yyvsp[0].v.range.a));
				YYERROR;
			}
		}
break;
case 160:
#line 2239 "parse.y"
{
			filter_opts.divert.port = 1;	/* some random value */
		}
break;
case 161:
#line 2242 "parse.y"
{
			/*
			 * If IP reassembly was not turned off, also
			 * forcibly enable TCP reassembly by default.
			 */
			if (pf->reassemble & PF_REASS_ENABLED)
				filter_opts.marker |= FOM_SCRUB_TCP;

			if (yyvsp[0].v.number < 1 || yyvsp[0].v.number > 65535) {
				yyerror("invalid divert port");
				YYERROR;
			}

			filter_opts.divert_packet.port = htons(yyvsp[0].v.number);
		}
break;
case 162:
#line 2257 "parse.y"
{
			filter_opts.nodf = yyvsp[-1].v.scrub_opts.nodf;
			filter_opts.minttl = yyvsp[-1].v.scrub_opts.minttl;
			filter_opts.settos = yyvsp[-1].v.scrub_opts.settos;
			filter_opts.randomid = yyvsp[-1].v.scrub_opts.randomid;
			filter_opts.max_mss = yyvsp[-1].v.scrub_opts.maxmss;
			if (yyvsp[-1].v.scrub_opts.reassemble_tcp)
				filter_opts.marker |= FOM_SCRUB_TCP;
			filter_opts.marker |= yyvsp[-1].v.scrub_opts.marker;
		}
break;
case 163:
#line 2267 "parse.y"
{
			if (filter_opts.nat.rdr) {
				yyerror("cannot respecify nat-to/binat-to");
				YYERROR;
			}
			filter_opts.nat.rdr = yyvsp[-1].v.redirection;
			memcpy(&filter_opts.nat.pool_opts, &yyvsp[0].v.pool_opts,
			    sizeof(filter_opts.nat.pool_opts));
		}
break;
case 164:
#line 2276 "parse.y"
{
			if (filter_opts.rdr.rdr) {
				yyerror("cannot respecify rdr-to");
				YYERROR;
			}
			filter_opts.rdr.rdr = yyvsp[-1].v.redirection;
			memcpy(&filter_opts.rdr.pool_opts, &yyvsp[0].v.pool_opts,
			    sizeof(filter_opts.rdr.pool_opts));
		}
break;
case 165:
#line 2285 "parse.y"
{
			if (filter_opts.nat.rdr) {
				yyerror("cannot respecify nat-to/binat-to");
				YYERROR;
			}
			filter_opts.nat.rdr = yyvsp[-1].v.redirection;
			filter_opts.nat.binat = 1;
			memcpy(&filter_opts.nat.pool_opts, &yyvsp[0].v.pool_opts,
			    sizeof(filter_opts.nat.pool_opts));
			filter_opts.nat.pool_opts.staticport = 1;
		}
break;
case 166:
#line 2296 "parse.y"
{
			filter_opts.route.host = NULL;
			filter_opts.route.rt = PF_FASTROUTE;
			filter_opts.route.pool_opts = 0;
		}
break;
case 167:
#line 2301 "parse.y"
{
			filter_opts.route.host = yyvsp[-1].v.host;
			filter_opts.route.rt = PF_ROUTETO;
			filter_opts.route.pool_opts = yyvsp[0].v.pool_opts.type | yyvsp[0].v.pool_opts.opts;
			if (yyvsp[0].v.pool_opts.key != NULL)
				filter_opts.route.key = yyvsp[0].v.pool_opts.key;
		}
break;
case 168:
#line 2308 "parse.y"
{
			filter_opts.route.host = yyvsp[-1].v.host;
			filter_opts.route.rt = PF_REPLYTO;
			filter_opts.route.pool_opts = yyvsp[0].v.pool_opts.type | yyvsp[0].v.pool_opts.opts;
			if (yyvsp[0].v.pool_opts.key != NULL)
				filter_opts.route.key = yyvsp[0].v.pool_opts.key;
		}
break;
case 169:
#line 2315 "parse.y"
{
			filter_opts.route.host = yyvsp[-1].v.host;
			filter_opts.route.rt = PF_DUPTO;
			filter_opts.route.pool_opts = yyvsp[0].v.pool_opts.type | yyvsp[0].v.pool_opts.opts;
			if (yyvsp[0].v.pool_opts.key != NULL)
				filter_opts.route.key = yyvsp[0].v.pool_opts.key;
		}
break;
case 170:
#line 2322 "parse.y"
{
			if (filter_opts.rcv) {
				yyerror("cannot respecify received-on");
				YYERROR;
			}
			filter_opts.rcv = yyvsp[0].v.interface;
		}
break;
case 171:
#line 2331 "parse.y"
{
			char	*e;
			double	 p = strtod(yyvsp[0].v.string, &e);

			if (*e == '%') {
				p *= 0.01;
				e++;
			}
			if (*e) {
				yyerror("invalid probability: %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
			yyval.v.probability = p;
		}
break;
case 172:
#line 2347 "parse.y"
{
			yyval.v.probability = (double)yyvsp[0].v.number;
		}
break;
case 173:
#line 2353 "parse.y"
{ yyval.v.b.b1 = PF_PASS; yyval.v.b.b2 = yyval.v.b.w = 0; }
break;
case 174:
#line 2354 "parse.y"
{ yyval.v.b.b1 = PF_MATCH; yyval.v.b.b2 = yyval.v.b.w = 0; }
break;
case 175:
#line 2355 "parse.y"
{ yyval.v.b = yyvsp[0].v.b; yyval.v.b.b1 = PF_DROP; }
break;
case 176:
#line 2358 "parse.y"
{
			yyval.v.b.b2 = blockpolicy;
			yyval.v.b.w = returnicmpdefault;
			yyval.v.b.w2 = returnicmp6default;
		}
break;
case 177:
#line 2363 "parse.y"
{
			yyval.v.b.b2 = PFRULE_DROP;
			yyval.v.b.w = 0;
			yyval.v.b.w2 = 0;
		}
break;
case 178:
#line 2368 "parse.y"
{
			yyval.v.b.b2 = PFRULE_RETURNRST;
			yyval.v.b.w = 0;
			yyval.v.b.w2 = 0;
		}
break;
case 179:
#line 2373 "parse.y"
{
			if (yyvsp[-1].v.number < 0 || yyvsp[-1].v.number > 255) {
				yyerror("illegal ttl value %d", yyvsp[-1].v.number);
				YYERROR;
			}
			yyval.v.b.b2 = PFRULE_RETURNRST;
			yyval.v.b.w = yyvsp[-1].v.number;
			yyval.v.b.w2 = 0;
		}
break;
case 180:
#line 2382 "parse.y"
{
			yyval.v.b.b2 = PFRULE_RETURNICMP;
			yyval.v.b.w = returnicmpdefault;
			yyval.v.b.w2 = returnicmp6default;
		}
break;
case 181:
#line 2387 "parse.y"
{
			yyval.v.b.b2 = PFRULE_RETURNICMP;
			yyval.v.b.w = returnicmpdefault;
			yyval.v.b.w2 = returnicmp6default;
		}
break;
case 182:
#line 2392 "parse.y"
{
			yyval.v.b.b2 = PFRULE_RETURNICMP;
			yyval.v.b.w = yyvsp[-1].v.number;
			yyval.v.b.w2 = returnicmpdefault;
		}
break;
case 183:
#line 2397 "parse.y"
{
			yyval.v.b.b2 = PFRULE_RETURNICMP;
			yyval.v.b.w = returnicmpdefault;
			yyval.v.b.w2 = yyvsp[-1].v.number;
		}
break;
case 184:
#line 2402 "parse.y"
{
			yyval.v.b.b2 = PFRULE_RETURNICMP;
			yyval.v.b.w = yyvsp[-3].v.number;
			yyval.v.b.w2 = yyvsp[-1].v.number;
		}
break;
case 185:
#line 2407 "parse.y"
{
			yyval.v.b.b2 = PFRULE_RETURN;
			yyval.v.b.w = returnicmpdefault;
			yyval.v.b.w2 = returnicmp6default;
		}
break;
case 186:
#line 2414 "parse.y"
{
			if (!(yyval.v.number = parseicmpspec(yyvsp[0].v.string, AF_INET))) {
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 187:
#line 2421 "parse.y"
{
			u_int8_t		icmptype;

			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > 255) {
				yyerror("invalid icmp code %lu", yyvsp[0].v.number);
				YYERROR;
			}
			icmptype = returnicmpdefault >> 8;
			yyval.v.number = (icmptype << 8 | yyvsp[0].v.number);
		}
break;
case 188:
#line 2433 "parse.y"
{
			if (!(yyval.v.number = parseicmpspec(yyvsp[0].v.string, AF_INET6))) {
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 189:
#line 2440 "parse.y"
{
			u_int8_t		icmptype;

			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > 255) {
				yyerror("invalid icmp code %lu", yyvsp[0].v.number);
				YYERROR;
			}
			icmptype = returnicmp6default >> 8;
			yyval.v.number = (icmptype << 8 | yyvsp[0].v.number);
		}
break;
case 190:
#line 2452 "parse.y"
{ yyval.v.i = PF_INOUT; }
break;
case 191:
#line 2453 "parse.y"
{ yyval.v.i = PF_IN; }
break;
case 192:
#line 2454 "parse.y"
{ yyval.v.i = PF_OUT; }
break;
case 193:
#line 2457 "parse.y"
{ yyval.v.logquick.quick = 0; }
break;
case 194:
#line 2458 "parse.y"
{ yyval.v.logquick.quick = 1; }
break;
case 195:
#line 2461 "parse.y"
{ yyval.v.logquick.log = 0; yyval.v.logquick.quick = 0; yyval.v.logquick.logif = 0; }
break;
case 196:
#line 2462 "parse.y"
{ yyval.v.logquick = yyvsp[0].v.logquick; yyval.v.logquick.quick = 0; }
break;
case 197:
#line 2463 "parse.y"
{ yyval.v.logquick.quick = 1; yyval.v.logquick.log = 0; yyval.v.logquick.logif = 0; }
break;
case 198:
#line 2464 "parse.y"
{ yyval.v.logquick = yyvsp[-1].v.logquick; yyval.v.logquick.quick = 1; }
break;
case 199:
#line 2465 "parse.y"
{ yyval.v.logquick = yyvsp[0].v.logquick; yyval.v.logquick.quick = 1; }
break;
case 200:
#line 2468 "parse.y"
{ yyval.v.logquick.log = PF_LOG; yyval.v.logquick.logif = 0; }
break;
case 201:
#line 2469 "parse.y"
{
			yyval.v.logquick.log = PF_LOG | yyvsp[-1].v.logquick.log;
			yyval.v.logquick.logif = yyvsp[-1].v.logquick.logif;
		}
break;
case 202:
#line 2475 "parse.y"
{ yyval.v.logquick = yyvsp[0].v.logquick; }
break;
case 203:
#line 2476 "parse.y"
{
			yyval.v.logquick.log = yyvsp[-2].v.logquick.log | yyvsp[0].v.logquick.log;
			yyval.v.logquick.logif = yyvsp[0].v.logquick.logif;
			if (yyval.v.logquick.logif == 0)
				yyval.v.logquick.logif = yyvsp[-2].v.logquick.logif;
		}
break;
case 204:
#line 2484 "parse.y"
{ yyval.v.logquick.log = PF_LOG_ALL; yyval.v.logquick.logif = 0; }
break;
case 205:
#line 2485 "parse.y"
{ yyval.v.logquick.log = PF_LOG_MATCHES; yyval.v.logquick.logif = 0; }
break;
case 206:
#line 2486 "parse.y"
{ yyval.v.logquick.log = PF_LOG_SOCKET_LOOKUP; yyval.v.logquick.logif = 0; }
break;
case 207:
#line 2487 "parse.y"
{ yyval.v.logquick.log = PF_LOG_SOCKET_LOOKUP; yyval.v.logquick.logif = 0; }
break;
case 208:
#line 2488 "parse.y"
{
			const char	*errstr;
			u_int		 i;

			yyval.v.logquick.log = 0;
			if (strncmp(yyvsp[0].v.string, "pflog", 5)) {
				yyerror("%s: should be a pflog interface", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			i = strtonum(yyvsp[0].v.string + 5, 0, 255, &errstr);
			if (errstr) {
				yyerror("%s: %s", yyvsp[0].v.string, errstr);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
			yyval.v.logquick.logif = i;
		}
break;
case 209:
#line 2509 "parse.y"
{ yyval.v.interface = NULL; }
break;
case 210:
#line 2510 "parse.y"
{ yyval.v.interface = yyvsp[0].v.interface; }
break;
case 211:
#line 2511 "parse.y"
{ yyval.v.interface = yyvsp[-1].v.interface; }
break;
case 212:
#line 2514 "parse.y"
{ yyval.v.interface = yyvsp[-1].v.interface; }
break;
case 213:
#line 2515 "parse.y"
{
			yyvsp[-3].v.interface->tail->next = yyvsp[-1].v.interface;
			yyvsp[-3].v.interface->tail = yyvsp[-1].v.interface;
			yyval.v.interface = yyvsp[-3].v.interface;
		}
break;
case 214:
#line 2522 "parse.y"
{ yyval.v.interface = yyvsp[0].v.interface; yyval.v.interface->not = yyvsp[-1].v.number; }
break;
case 215:
#line 2525 "parse.y"
{
			struct node_host	*n;

			yyval.v.interface = calloc(1, sizeof(struct node_if));
			if (yyval.v.interface == NULL)
				err(1, "if_item: calloc");
			if (strlcpy(yyval.v.interface->ifname, yyvsp[0].v.string, sizeof(yyval.v.interface->ifname)) >=
			    sizeof(yyval.v.interface->ifname)) {
				free(yyvsp[0].v.string);
				free(yyval.v.interface);
				yyerror("interface name too long");
				YYERROR;
			}

			if ((n = ifa_exists(yyvsp[0].v.string)) != NULL)
				yyval.v.interface->ifa_flags = n->ifa_flags;

			free(yyvsp[0].v.string);
			yyval.v.interface->not = 0;
			yyval.v.interface->next = NULL;
			yyval.v.interface->tail = yyval.v.interface;
		}
break;
case 216:
#line 2549 "parse.y"
{ yyval.v.i = 0; }
break;
case 217:
#line 2550 "parse.y"
{ yyval.v.i = AF_INET; }
break;
case 218:
#line 2551 "parse.y"
{ yyval.v.i = AF_INET6; }
break;
case 219:
#line 2554 "parse.y"
{ yyval.v.proto = NULL; }
break;
case 220:
#line 2555 "parse.y"
{ yyval.v.proto = yyvsp[0].v.proto; }
break;
case 221:
#line 2556 "parse.y"
{ yyval.v.proto = yyvsp[-1].v.proto; }
break;
case 222:
#line 2559 "parse.y"
{ yyval.v.proto = yyvsp[-1].v.proto; }
break;
case 223:
#line 2560 "parse.y"
{
			yyvsp[-3].v.proto->tail->next = yyvsp[-1].v.proto;
			yyvsp[-3].v.proto->tail = yyvsp[-1].v.proto;
			yyval.v.proto = yyvsp[-3].v.proto;
		}
break;
case 224:
#line 2567 "parse.y"
{
			u_int8_t	pr;

			pr = (u_int8_t)yyvsp[0].v.number;
			if (pr == 0) {
				yyerror("proto 0 cannot be used");
				YYERROR;
			}
			yyval.v.proto = calloc(1, sizeof(struct node_proto));
			if (yyval.v.proto == NULL)
				err(1, "proto_item: calloc");
			yyval.v.proto->proto = pr;
			yyval.v.proto->next = NULL;
			yyval.v.proto->tail = yyval.v.proto;
		}
break;
case 225:
#line 2584 "parse.y"
{
			struct protoent	*p;

			p = getprotobyname(yyvsp[0].v.string);
			if (p == NULL) {
				yyerror("unknown protocol %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			yyval.v.number = p->p_proto;
			free(yyvsp[0].v.string);
		}
break;
case 226:
#line 2596 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > 255) {
				yyerror("protocol outside range");
				YYERROR;
			}
		}
break;
case 227:
#line 2604 "parse.y"
{
			yyval.v.fromto.src.host = NULL;
			yyval.v.fromto.src.port = NULL;
			yyval.v.fromto.dst.host = NULL;
			yyval.v.fromto.dst.port = NULL;
			yyval.v.fromto.src_os = NULL;
		}
break;
case 228:
#line 2611 "parse.y"
{
			yyval.v.fromto.src = yyvsp[-2].v.peer;
			yyval.v.fromto.src_os = yyvsp[-1].v.os;
			yyval.v.fromto.dst = yyvsp[0].v.peer;
		}
break;
case 229:
#line 2618 "parse.y"
{ yyval.v.os = NULL; }
break;
case 230:
#line 2619 "parse.y"
{ yyval.v.os = yyvsp[0].v.os; }
break;
case 231:
#line 2620 "parse.y"
{ yyval.v.os = yyvsp[-1].v.os; }
break;
case 232:
#line 2623 "parse.y"
{
			yyval.v.os = calloc(1, sizeof(struct node_os));
			if (yyval.v.os == NULL)
				err(1, "os: calloc");
			yyval.v.os->os = yyvsp[0].v.string;
			yyval.v.os->tail = yyval.v.os;
		}
break;
case 233:
#line 2632 "parse.y"
{ yyval.v.os = yyvsp[-1].v.os; }
break;
case 234:
#line 2633 "parse.y"
{
			yyvsp[-3].v.os->tail->next = yyvsp[-1].v.os;
			yyvsp[-3].v.os->tail = yyvsp[-1].v.os;
			yyval.v.os = yyvsp[-3].v.os;
		}
break;
case 235:
#line 2640 "parse.y"
{
			yyval.v.peer.host = NULL;
			yyval.v.peer.port = NULL;
		}
break;
case 236:
#line 2644 "parse.y"
{
			yyval.v.peer = yyvsp[0].v.peer;
		}
break;
case 237:
#line 2649 "parse.y"
{
			yyval.v.peer.host = NULL;
			yyval.v.peer.port = NULL;
		}
break;
case 238:
#line 2653 "parse.y"
{
			if (disallow_urpf_failed(yyvsp[0].v.peer.host, "\"urpf-failed\" is "
			    "not permitted in a destination address"))
				YYERROR;
			yyval.v.peer = yyvsp[0].v.peer;
		}
break;
case 239:
#line 2661 "parse.y"
{
			yyval.v.peer.host = yyvsp[0].v.host;
			yyval.v.peer.port = NULL;
		}
break;
case 240:
#line 2665 "parse.y"
{
			yyval.v.peer.host = yyvsp[-2].v.host;
			yyval.v.peer.port = yyvsp[0].v.port;
		}
break;
case 241:
#line 2669 "parse.y"
{
			yyval.v.peer.host = NULL;
			yyval.v.peer.port = yyvsp[0].v.port;
		}
break;
case 244:
#line 2679 "parse.y"
{ yyval.v.host = NULL; }
break;
case 245:
#line 2680 "parse.y"
{ yyval.v.host = yyvsp[0].v.host; }
break;
case 246:
#line 2681 "parse.y"
{ yyval.v.host = yyvsp[-1].v.host; }
break;
case 247:
#line 2684 "parse.y"
{ yyval.v.host = yyvsp[-1].v.host; }
break;
case 248:
#line 2685 "parse.y"
{
			if (yyvsp[-3].v.host == NULL) {
				freehostlist(yyvsp[-1].v.host);
				yyval.v.host = yyvsp[-3].v.host;
			} else if (yyvsp[-1].v.host == NULL) {
				freehostlist(yyvsp[-3].v.host);
				yyval.v.host = yyvsp[-1].v.host;
			} else {
				yyvsp[-3].v.host->tail->next = yyvsp[-1].v.host;
				yyvsp[-3].v.host->tail = yyvsp[-1].v.host->tail;
				yyval.v.host = yyvsp[-3].v.host;
			}
		}
break;
case 249:
#line 2700 "parse.y"
{
			struct node_host	*n;

			for (n = yyvsp[0].v.host; n != NULL; n = n->next)
				n->not = yyvsp[-1].v.number;
			yyval.v.host = yyvsp[0].v.host;
		}
break;
case 250:
#line 2707 "parse.y"
{
			yyval.v.host = calloc(1, sizeof(struct node_host));
			if (yyval.v.host == NULL)
				err(1, "xhost: calloc");
			yyval.v.host->addr.type = PF_ADDR_NOROUTE;
			yyval.v.host->next = NULL;
			yyval.v.host->not = yyvsp[-1].v.number;
			yyval.v.host->tail = yyval.v.host;
		}
break;
case 251:
#line 2716 "parse.y"
{
			yyval.v.host = calloc(1, sizeof(struct node_host));
			if (yyval.v.host == NULL)
				err(1, "xhost: calloc");
			yyval.v.host->addr.type = PF_ADDR_URPFFAILED;
			yyval.v.host->next = NULL;
			yyval.v.host->not = yyvsp[-1].v.number;
			yyval.v.host->tail = yyval.v.host;
		}
break;
case 252:
#line 2727 "parse.y"
{
			if ((yyval.v.host = host(yyvsp[0].v.string)) == NULL)	{
				/* error. "any" is handled elsewhere */
				free(yyvsp[0].v.string);
				yyerror("could not parse host specification");
				YYERROR;
			}
			free(yyvsp[0].v.string);

		}
break;
case 253:
#line 2737 "parse.y"
{
			struct node_host *b, *e;

			if ((b = host(yyvsp[-2].v.string)) == NULL || (e = host(yyvsp[0].v.string)) == NULL) {
				free(yyvsp[-2].v.string);
				free(yyvsp[0].v.string);
				yyerror("could not parse host specification");
				YYERROR;
			}
			if (b->af != e->af ||
			    b->addr.type != PF_ADDR_ADDRMASK ||
			    e->addr.type != PF_ADDR_ADDRMASK ||
			    unmask(&b->addr.v.a.mask, b->af) !=
			    (b->af == AF_INET ? 32 : 128) ||
			    unmask(&e->addr.v.a.mask, e->af) !=
			    (e->af == AF_INET ? 32 : 128) ||
			    b->next != NULL || b->not ||
			    e->next != NULL || e->not) {
				free(b);
				free(e);
				free(yyvsp[-2].v.string);
				free(yyvsp[0].v.string);
				yyerror("invalid address range");
				YYERROR;
			}
			memcpy(&b->addr.v.a.mask, &e->addr.v.a.addr,
			    sizeof(b->addr.v.a.mask));
			b->addr.type = PF_ADDR_RANGE;
			yyval.v.host = b;
			free(e);
			free(yyvsp[-2].v.string);
			free(yyvsp[0].v.string);
		}
break;
case 254:
#line 2770 "parse.y"
{
			char	*buf;

			if (asprintf(&buf, "%s/%lld", yyvsp[-2].v.string, yyvsp[0].v.number) == -1)
				err(1, "host: asprintf");
			free(yyvsp[-2].v.string);
			if ((yyval.v.host = host(buf)) == NULL)	{
				/* error. "any" is handled elsewhere */
				free(buf);
				yyerror("could not parse host specification");
				YYERROR;
			}
			free(buf);
		}
break;
case 255:
#line 2784 "parse.y"
{
			char	*buf;

			/* ie. for 10/8 parsing */
			if (asprintf(&buf, "%lld/%lld", yyvsp[-2].v.number, yyvsp[0].v.number) == -1)
				err(1, "host: asprintf");
			if ((yyval.v.host = host(buf)) == NULL)	{
				/* error. "any" is handled elsewhere */
				free(buf);
				yyerror("could not parse host specification");
				YYERROR;
			}
			free(buf);
		}
break;
case 257:
#line 2799 "parse.y"
{
			struct node_host	*n;

			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > 128) {
				yyerror("bit number too big");
				YYERROR;
			}
			yyval.v.host = yyvsp[-2].v.host;
			for (n = yyvsp[-2].v.host; n != NULL; n = n->next)
				set_ipmask(n, yyvsp[0].v.number);
		}
break;
case 258:
#line 2810 "parse.y"
{
			if (strlen(yyvsp[-1].v.string) >= PF_TABLE_NAME_SIZE) {
				yyerror("table name '%s' too long", yyvsp[-1].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			yyval.v.host = calloc(1, sizeof(struct node_host));
			if (yyval.v.host == NULL)
				err(1, "host: calloc");
			yyval.v.host->addr.type = PF_ADDR_TABLE;
			if (strlcpy(yyval.v.host->addr.v.tblname, yyvsp[-1].v.string,
			    sizeof(yyval.v.host->addr.v.tblname)) >=
			    sizeof(yyval.v.host->addr.v.tblname))
				errx(1, "host: strlcpy");
			free(yyvsp[-1].v.string);
			yyval.v.host->next = NULL;
			yyval.v.host->tail = yyval.v.host;
		}
break;
case 259:
#line 2828 "parse.y"
{
			yyval.v.host = calloc(1, sizeof(struct node_host));
			if (yyval.v.host == NULL) {
				free(yyvsp[0].v.string);
				err(1, "host: calloc");
			}
			yyval.v.host->addr.type = PF_ADDR_RTLABEL;
			if (strlcpy(yyval.v.host->addr.v.rtlabelname, yyvsp[0].v.string,
			    sizeof(yyval.v.host->addr.v.rtlabelname)) >=
			    sizeof(yyval.v.host->addr.v.rtlabelname)) {
				yyerror("route label too long, max %u chars",
				    sizeof(yyval.v.host->addr.v.rtlabelname) - 1);
				free(yyvsp[0].v.string);
				free(yyval.v.host);
				YYERROR;
			}
			yyval.v.host->next = NULL;
			yyval.v.host->tail = yyval.v.host;
			free(yyvsp[0].v.string);
		}
break;
case 261:
#line 2851 "parse.y"
{
			u_long	ulval;

			if (atoul(yyvsp[0].v.string, &ulval) == -1) {
				yyerror("%s is not a number", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			} else
				yyval.v.number = ulval;
			free(yyvsp[0].v.string);
		}
break;
case 262:
#line 2864 "parse.y"
{
			int	 flags = 0;
			char	*p, *op;

			op = yyvsp[-1].v.string;
			if (!isalpha(op[0])) {
				yyerror("invalid interface name '%s'", op);
				free(op);
				YYERROR;
			}
			while ((p = strrchr(yyvsp[-1].v.string, ':')) != NULL) {
				if (!strcmp(p+1, "network"))
					flags |= PFI_AFLAG_NETWORK;
				else if (!strcmp(p+1, "broadcast"))
					flags |= PFI_AFLAG_BROADCAST;
				else if (!strcmp(p+1, "peer"))
					flags |= PFI_AFLAG_PEER;
				else if (!strcmp(p+1, "0"))
					flags |= PFI_AFLAG_NOALIAS;
				else {
					yyerror("interface %s has bad modifier",
					    yyvsp[-1].v.string);
					free(op);
					YYERROR;
				}
				*p = '\0';
			}
			if (flags & (flags - 1) & PFI_AFLAG_MODEMASK) {
				free(op);
				yyerror("illegal combination of "
				    "interface modifiers");
				YYERROR;
			}
			yyval.v.host = calloc(1, sizeof(struct node_host));
			if (yyval.v.host == NULL)
				err(1, "address: calloc");
			yyval.v.host->af = 0;
			set_ipmask(yyval.v.host, 128);
			yyval.v.host->addr.type = PF_ADDR_DYNIFTL;
			yyval.v.host->addr.iflags = flags;
			if (strlcpy(yyval.v.host->addr.v.ifname, yyvsp[-1].v.string,
			    sizeof(yyval.v.host->addr.v.ifname)) >=
			    sizeof(yyval.v.host->addr.v.ifname)) {
				free(op);
				free(yyval.v.host);
				yyerror("interface name too long");
				YYERROR;
			}
			free(op);
			yyval.v.host->next = NULL;
			yyval.v.host->tail = yyval.v.host;
		}
break;
case 263:
#line 2918 "parse.y"
{ yyval.v.port = yyvsp[0].v.port; }
break;
case 264:
#line 2919 "parse.y"
{ yyval.v.port = yyvsp[-1].v.port; }
break;
case 265:
#line 2922 "parse.y"
{ yyval.v.port = yyvsp[-1].v.port; }
break;
case 266:
#line 2923 "parse.y"
{
			yyvsp[-3].v.port->tail->next = yyvsp[-1].v.port;
			yyvsp[-3].v.port->tail = yyvsp[-1].v.port;
			yyval.v.port = yyvsp[-3].v.port;
		}
break;
case 267:
#line 2930 "parse.y"
{
			yyval.v.port = calloc(1, sizeof(struct node_port));
			if (yyval.v.port == NULL)
				err(1, "port_item: calloc");
			yyval.v.port->port[0] = yyvsp[0].v.range.a;
			yyval.v.port->port[1] = yyvsp[0].v.range.b;
			if (yyvsp[0].v.range.t)
				yyval.v.port->op = PF_OP_RRG;
			else
				yyval.v.port->op = PF_OP_EQ;
			yyval.v.port->next = NULL;
			yyval.v.port->tail = yyval.v.port;
		}
break;
case 268:
#line 2943 "parse.y"
{
			if (yyvsp[0].v.range.t) {
				yyerror("':' cannot be used with an other "
				    "port operator");
				YYERROR;
			}
			yyval.v.port = calloc(1, sizeof(struct node_port));
			if (yyval.v.port == NULL)
				err(1, "port_item: calloc");
			yyval.v.port->port[0] = yyvsp[0].v.range.a;
			yyval.v.port->port[1] = yyvsp[0].v.range.b;
			yyval.v.port->op = yyvsp[-1].v.i;
			yyval.v.port->next = NULL;
			yyval.v.port->tail = yyval.v.port;
		}
break;
case 269:
#line 2958 "parse.y"
{
			if (yyvsp[-2].v.range.t || yyvsp[0].v.range.t) {
				yyerror("':' cannot be used with an other "
				    "port operator");
				YYERROR;
			}
			yyval.v.port = calloc(1, sizeof(struct node_port));
			if (yyval.v.port == NULL)
				err(1, "port_item: calloc");
			yyval.v.port->port[0] = yyvsp[-2].v.range.a;
			yyval.v.port->port[1] = yyvsp[0].v.range.a;
			yyval.v.port->op = yyvsp[-1].v.i;
			yyval.v.port->next = NULL;
			yyval.v.port->tail = yyval.v.port;
		}
break;
case 270:
#line 2975 "parse.y"
{
			if (parseport(yyvsp[0].v.string, &yyval.v.range, 0) == -1) {
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 271:
#line 2984 "parse.y"
{
			if (parseport(yyvsp[0].v.string, &yyval.v.range, PPORT_RANGE) == -1) {
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 272:
#line 2993 "parse.y"
{ yyval.v.uid = yyvsp[0].v.uid; }
break;
case 273:
#line 2994 "parse.y"
{ yyval.v.uid = yyvsp[-1].v.uid; }
break;
case 274:
#line 2997 "parse.y"
{ yyval.v.uid = yyvsp[-1].v.uid; }
break;
case 275:
#line 2998 "parse.y"
{
			yyvsp[-3].v.uid->tail->next = yyvsp[-1].v.uid;
			yyvsp[-3].v.uid->tail = yyvsp[-1].v.uid;
			yyval.v.uid = yyvsp[-3].v.uid;
		}
break;
case 276:
#line 3005 "parse.y"
{
			yyval.v.uid = calloc(1, sizeof(struct node_uid));
			if (yyval.v.uid == NULL)
				err(1, "uid_item: calloc");
			yyval.v.uid->uid[0] = yyvsp[0].v.number;
			yyval.v.uid->uid[1] = yyvsp[0].v.number;
			yyval.v.uid->op = PF_OP_EQ;
			yyval.v.uid->next = NULL;
			yyval.v.uid->tail = yyval.v.uid;
		}
break;
case 277:
#line 3015 "parse.y"
{
			if (yyvsp[0].v.number == UID_MAX && yyvsp[-1].v.i != PF_OP_EQ && yyvsp[-1].v.i != PF_OP_NE) {
				yyerror("user unknown requires operator = or "
				    "!=");
				YYERROR;
			}
			yyval.v.uid = calloc(1, sizeof(struct node_uid));
			if (yyval.v.uid == NULL)
				err(1, "uid_item: calloc");
			yyval.v.uid->uid[0] = yyvsp[0].v.number;
			yyval.v.uid->uid[1] = yyvsp[0].v.number;
			yyval.v.uid->op = yyvsp[-1].v.i;
			yyval.v.uid->next = NULL;
			yyval.v.uid->tail = yyval.v.uid;
		}
break;
case 278:
#line 3030 "parse.y"
{
			if (yyvsp[-2].v.number == UID_MAX || yyvsp[0].v.number == UID_MAX) {
				yyerror("user unknown requires operator = or "
				    "!=");
				YYERROR;
			}
			yyval.v.uid = calloc(1, sizeof(struct node_uid));
			if (yyval.v.uid == NULL)
				err(1, "uid_item: calloc");
			yyval.v.uid->uid[0] = yyvsp[-2].v.number;
			yyval.v.uid->uid[1] = yyvsp[0].v.number;
			yyval.v.uid->op = yyvsp[-1].v.i;
			yyval.v.uid->next = NULL;
			yyval.v.uid->tail = yyval.v.uid;
		}
break;
case 279:
#line 3047 "parse.y"
{
			if (!strcmp(yyvsp[0].v.string, "unknown"))
				yyval.v.number = UID_MAX;
			else {
				struct passwd	*pw;

				if ((pw = getpwnam(yyvsp[0].v.string)) == NULL) {
					yyerror("unknown user %s", yyvsp[0].v.string);
					free(yyvsp[0].v.string);
					YYERROR;
				}
				yyval.v.number = pw->pw_uid;
			}
			free(yyvsp[0].v.string);
		}
break;
case 280:
#line 3062 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number >= UID_MAX) {
				yyerror("illegal uid value %lu", yyvsp[0].v.number);
				YYERROR;
			}
			yyval.v.number = yyvsp[0].v.number;
		}
break;
case 281:
#line 3071 "parse.y"
{ yyval.v.gid = yyvsp[0].v.gid; }
break;
case 282:
#line 3072 "parse.y"
{ yyval.v.gid = yyvsp[-1].v.gid; }
break;
case 283:
#line 3075 "parse.y"
{ yyval.v.gid = yyvsp[-1].v.gid; }
break;
case 284:
#line 3076 "parse.y"
{
			yyvsp[-3].v.gid->tail->next = yyvsp[-1].v.gid;
			yyvsp[-3].v.gid->tail = yyvsp[-1].v.gid;
			yyval.v.gid = yyvsp[-3].v.gid;
		}
break;
case 285:
#line 3083 "parse.y"
{
			yyval.v.gid = calloc(1, sizeof(struct node_gid));
			if (yyval.v.gid == NULL)
				err(1, "gid_item: calloc");
			yyval.v.gid->gid[0] = yyvsp[0].v.number;
			yyval.v.gid->gid[1] = yyvsp[0].v.number;
			yyval.v.gid->op = PF_OP_EQ;
			yyval.v.gid->next = NULL;
			yyval.v.gid->tail = yyval.v.gid;
		}
break;
case 286:
#line 3093 "parse.y"
{
			if (yyvsp[0].v.number == GID_MAX && yyvsp[-1].v.i != PF_OP_EQ && yyvsp[-1].v.i != PF_OP_NE) {
				yyerror("group unknown requires operator = or "
				    "!=");
				YYERROR;
			}
			yyval.v.gid = calloc(1, sizeof(struct node_gid));
			if (yyval.v.gid == NULL)
				err(1, "gid_item: calloc");
			yyval.v.gid->gid[0] = yyvsp[0].v.number;
			yyval.v.gid->gid[1] = yyvsp[0].v.number;
			yyval.v.gid->op = yyvsp[-1].v.i;
			yyval.v.gid->next = NULL;
			yyval.v.gid->tail = yyval.v.gid;
		}
break;
case 287:
#line 3108 "parse.y"
{
			if (yyvsp[-2].v.number == GID_MAX || yyvsp[0].v.number == GID_MAX) {
				yyerror("group unknown requires operator = or "
				    "!=");
				YYERROR;
			}
			yyval.v.gid = calloc(1, sizeof(struct node_gid));
			if (yyval.v.gid == NULL)
				err(1, "gid_item: calloc");
			yyval.v.gid->gid[0] = yyvsp[-2].v.number;
			yyval.v.gid->gid[1] = yyvsp[0].v.number;
			yyval.v.gid->op = yyvsp[-1].v.i;
			yyval.v.gid->next = NULL;
			yyval.v.gid->tail = yyval.v.gid;
		}
break;
case 288:
#line 3125 "parse.y"
{
			if (!strcmp(yyvsp[0].v.string, "unknown"))
				yyval.v.number = GID_MAX;
			else {
				struct group	*grp;

				if ((grp = getgrnam(yyvsp[0].v.string)) == NULL) {
					yyerror("unknown group %s", yyvsp[0].v.string);
					free(yyvsp[0].v.string);
					YYERROR;
				}
				yyval.v.number = grp->gr_gid;
			}
			free(yyvsp[0].v.string);
		}
break;
case 289:
#line 3140 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number >= GID_MAX) {
				yyerror("illegal gid value %lu", yyvsp[0].v.number);
				YYERROR;
			}
			yyval.v.number = yyvsp[0].v.number;
		}
break;
case 290:
#line 3149 "parse.y"
{
			int	f;

			if ((f = parse_flags(yyvsp[0].v.string)) < 0) {
				yyerror("bad flags %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
			yyval.v.b.b1 = f;
		}
break;
case 291:
#line 3162 "parse.y"
{ yyval.v.b.b1 = yyvsp[-2].v.b.b1; yyval.v.b.b2 = yyvsp[0].v.b.b1; }
break;
case 292:
#line 3163 "parse.y"
{ yyval.v.b.b1 = 0; yyval.v.b.b2 = yyvsp[0].v.b.b1; }
break;
case 293:
#line 3164 "parse.y"
{ yyval.v.b.b1 = 0; yyval.v.b.b2 = 0; }
break;
case 294:
#line 3167 "parse.y"
{ yyval.v.icmp = yyvsp[0].v.icmp; }
break;
case 295:
#line 3168 "parse.y"
{ yyval.v.icmp = yyvsp[-1].v.icmp; }
break;
case 296:
#line 3169 "parse.y"
{ yyval.v.icmp = yyvsp[0].v.icmp; }
break;
case 297:
#line 3170 "parse.y"
{ yyval.v.icmp = yyvsp[-1].v.icmp; }
break;
case 298:
#line 3173 "parse.y"
{ yyval.v.icmp = yyvsp[-1].v.icmp; }
break;
case 299:
#line 3174 "parse.y"
{
			yyvsp[-3].v.icmp->tail->next = yyvsp[-1].v.icmp;
			yyvsp[-3].v.icmp->tail = yyvsp[-1].v.icmp;
			yyval.v.icmp = yyvsp[-3].v.icmp;
		}
break;
case 300:
#line 3181 "parse.y"
{ yyval.v.icmp = yyvsp[-1].v.icmp; }
break;
case 301:
#line 3182 "parse.y"
{
			yyvsp[-3].v.icmp->tail->next = yyvsp[-1].v.icmp;
			yyvsp[-3].v.icmp->tail = yyvsp[-1].v.icmp;
			yyval.v.icmp = yyvsp[-3].v.icmp;
		}
break;
case 302:
#line 3189 "parse.y"
{
			yyval.v.icmp = calloc(1, sizeof(struct node_icmp));
			if (yyval.v.icmp == NULL)
				err(1, "icmp_item: calloc");
			yyval.v.icmp->type = yyvsp[0].v.number;
			yyval.v.icmp->code = 0;
			yyval.v.icmp->proto = IPPROTO_ICMP;
			yyval.v.icmp->next = NULL;
			yyval.v.icmp->tail = yyval.v.icmp;
		}
break;
case 303:
#line 3199 "parse.y"
{
			const struct icmpcodeent	*p;

			if ((p = geticmpcodebyname(yyvsp[-2].v.number-1, yyvsp[0].v.string, AF_INET)) == NULL) {
				yyerror("unknown icmp-code %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}

			free(yyvsp[0].v.string);
			yyval.v.icmp = calloc(1, sizeof(struct node_icmp));
			if (yyval.v.icmp == NULL)
				err(1, "icmp_item: calloc");
			yyval.v.icmp->type = yyvsp[-2].v.number;
			yyval.v.icmp->code = p->code + 1;
			yyval.v.icmp->proto = IPPROTO_ICMP;
			yyval.v.icmp->next = NULL;
			yyval.v.icmp->tail = yyval.v.icmp;
		}
break;
case 304:
#line 3218 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > 255) {
				yyerror("illegal icmp-code %lu", yyvsp[0].v.number);
				YYERROR;
			}
			yyval.v.icmp = calloc(1, sizeof(struct node_icmp));
			if (yyval.v.icmp == NULL)
				err(1, "icmp_item: calloc");
			yyval.v.icmp->type = yyvsp[-2].v.number;
			yyval.v.icmp->code = yyvsp[0].v.number + 1;
			yyval.v.icmp->proto = IPPROTO_ICMP;
			yyval.v.icmp->next = NULL;
			yyval.v.icmp->tail = yyval.v.icmp;
		}
break;
case 305:
#line 3234 "parse.y"
{
			yyval.v.icmp = calloc(1, sizeof(struct node_icmp));
			if (yyval.v.icmp == NULL)
				err(1, "icmp_item: calloc");
			yyval.v.icmp->type = yyvsp[0].v.number;
			yyval.v.icmp->code = 0;
			yyval.v.icmp->proto = IPPROTO_ICMPV6;
			yyval.v.icmp->next = NULL;
			yyval.v.icmp->tail = yyval.v.icmp;
		}
break;
case 306:
#line 3244 "parse.y"
{
			const struct icmpcodeent	*p;

			if ((p = geticmpcodebyname(yyvsp[-2].v.number-1, yyvsp[0].v.string, AF_INET6)) == NULL) {
				yyerror("unknown icmp6-code %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);

			yyval.v.icmp = calloc(1, sizeof(struct node_icmp));
			if (yyval.v.icmp == NULL)
				err(1, "icmp_item: calloc");
			yyval.v.icmp->type = yyvsp[-2].v.number;
			yyval.v.icmp->code = p->code + 1;
			yyval.v.icmp->proto = IPPROTO_ICMPV6;
			yyval.v.icmp->next = NULL;
			yyval.v.icmp->tail = yyval.v.icmp;
		}
break;
case 307:
#line 3263 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > 255) {
				yyerror("illegal icmp-code %lu", yyvsp[0].v.number);
				YYERROR;
			}
			yyval.v.icmp = calloc(1, sizeof(struct node_icmp));
			if (yyval.v.icmp == NULL)
				err(1, "icmp_item: calloc");
			yyval.v.icmp->type = yyvsp[-2].v.number;
			yyval.v.icmp->code = yyvsp[0].v.number + 1;
			yyval.v.icmp->proto = IPPROTO_ICMPV6;
			yyval.v.icmp->next = NULL;
			yyval.v.icmp->tail = yyval.v.icmp;
		}
break;
case 308:
#line 3279 "parse.y"
{
			const struct icmptypeent	*p;

			if ((p = geticmptypebyname(yyvsp[0].v.string, AF_INET)) == NULL) {
				yyerror("unknown icmp-type %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			yyval.v.number = p->type + 1;
			free(yyvsp[0].v.string);
		}
break;
case 309:
#line 3290 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > 255) {
				yyerror("illegal icmp-type %lu", yyvsp[0].v.number);
				YYERROR;
			}
			yyval.v.number = yyvsp[0].v.number + 1;
		}
break;
case 310:
#line 3299 "parse.y"
{
			const struct icmptypeent	*p;

			if ((p = geticmptypebyname(yyvsp[0].v.string, AF_INET6)) ==
			    NULL) {
				yyerror("unknown icmp6-type %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			yyval.v.number = p->type + 1;
			free(yyvsp[0].v.string);
		}
break;
case 311:
#line 3311 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > 255) {
				yyerror("illegal icmp6-type %lu", yyvsp[0].v.number);
				YYERROR;
			}
			yyval.v.number = yyvsp[0].v.number + 1;
		}
break;
case 312:
#line 3320 "parse.y"
{
			int val;
			if (map_tos(yyvsp[0].v.string, &val))
				yyval.v.number = val;
			else if (yyvsp[0].v.string[0] == '0' && yyvsp[0].v.string[1] == 'x')
				yyval.v.number = strtoul(yyvsp[0].v.string, NULL, 16);
			else
				yyval.v.number = 256;		/* flag bad argument */
			if (yyval.v.number > 255) {
				yyerror("illegal tos value %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 313:
#line 3335 "parse.y"
{
			yyval.v.number = yyvsp[0].v.number;
			if (yyval.v.number > 255) {
				yyerror("illegal tos value %s", yyvsp[0].v.number);
				YYERROR;
			}
		}
break;
case 314:
#line 3344 "parse.y"
{ yyval.v.i = PF_SRCTRACK; }
break;
case 315:
#line 3345 "parse.y"
{ yyval.v.i = PF_SRCTRACK_GLOBAL; }
break;
case 316:
#line 3346 "parse.y"
{ yyval.v.i = PF_SRCTRACK_RULE; }
break;
case 317:
#line 3349 "parse.y"
{
			yyval.v.i = PFRULE_IFBOUND;
		}
break;
case 318:
#line 3352 "parse.y"
{
			yyval.v.i = 0;
		}
break;
case 319:
#line 3357 "parse.y"
{
			yyval.v.keep_state.action = 0;
			yyval.v.keep_state.options = NULL;
		}
break;
case 320:
#line 3361 "parse.y"
{
			yyval.v.keep_state.action = PF_STATE_NORMAL;
			yyval.v.keep_state.options = yyvsp[0].v.state_opt;
		}
break;
case 321:
#line 3365 "parse.y"
{
			yyval.v.keep_state.action = PF_STATE_MODULATE;
			yyval.v.keep_state.options = yyvsp[0].v.state_opt;
		}
break;
case 322:
#line 3369 "parse.y"
{
			yyval.v.keep_state.action = PF_STATE_SYNPROXY;
			yyval.v.keep_state.options = yyvsp[0].v.state_opt;
		}
break;
case 323:
#line 3375 "parse.y"
{ yyval.v.i = 0; }
break;
case 324:
#line 3376 "parse.y"
{ yyval.v.i = PF_FLUSH; }
break;
case 325:
#line 3377 "parse.y"
{
			yyval.v.i = PF_FLUSH | PF_FLUSH_GLOBAL;
		}
break;
case 326:
#line 3382 "parse.y"
{ yyval.v.state_opt = yyvsp[-1].v.state_opt; }
break;
case 327:
#line 3383 "parse.y"
{ yyval.v.state_opt = NULL; }
break;
case 328:
#line 3386 "parse.y"
{ yyval.v.state_opt = yyvsp[0].v.state_opt; }
break;
case 329:
#line 3387 "parse.y"
{
			yyvsp[-2].v.state_opt->tail->next = yyvsp[0].v.state_opt;
			yyvsp[-2].v.state_opt->tail = yyvsp[0].v.state_opt;
			yyval.v.state_opt = yyvsp[-2].v.state_opt;
		}
break;
case 330:
#line 3394 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > UINT_MAX) {
				yyerror("only positive values permitted");
				YYERROR;
			}
			yyval.v.state_opt = calloc(1, sizeof(struct node_state_opt));
			if (yyval.v.state_opt == NULL)
				err(1, "state_opt_item: calloc");
			yyval.v.state_opt->type = PF_STATE_OPT_MAX;
			yyval.v.state_opt->data.max_states = yyvsp[0].v.number;
			yyval.v.state_opt->next = NULL;
			yyval.v.state_opt->tail = yyval.v.state_opt;
		}
break;
case 331:
#line 3407 "parse.y"
{
			yyval.v.state_opt = calloc(1, sizeof(struct node_state_opt));
			if (yyval.v.state_opt == NULL)
				err(1, "state_opt_item: calloc");
			yyval.v.state_opt->type = PF_STATE_OPT_NOSYNC;
			yyval.v.state_opt->next = NULL;
			yyval.v.state_opt->tail = yyval.v.state_opt;
		}
break;
case 332:
#line 3415 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > UINT_MAX) {
				yyerror("only positive values permitted");
				YYERROR;
			}
			yyval.v.state_opt = calloc(1, sizeof(struct node_state_opt));
			if (yyval.v.state_opt == NULL)
				err(1, "state_opt_item: calloc");
			yyval.v.state_opt->type = PF_STATE_OPT_MAX_SRC_STATES;
			yyval.v.state_opt->data.max_src_states = yyvsp[0].v.number;
			yyval.v.state_opt->next = NULL;
			yyval.v.state_opt->tail = yyval.v.state_opt;
		}
break;
case 333:
#line 3428 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > UINT_MAX) {
				yyerror("only positive values permitted");
				YYERROR;
			}
			yyval.v.state_opt = calloc(1, sizeof(struct node_state_opt));
			if (yyval.v.state_opt == NULL)
				err(1, "state_opt_item: calloc");
			yyval.v.state_opt->type = PF_STATE_OPT_MAX_SRC_CONN;
			yyval.v.state_opt->data.max_src_conn = yyvsp[0].v.number;
			yyval.v.state_opt->next = NULL;
			yyval.v.state_opt->tail = yyval.v.state_opt;
		}
break;
case 334:
#line 3441 "parse.y"
{
			if (yyvsp[-2].v.number < 0 || yyvsp[-2].v.number > UINT_MAX ||
			    yyvsp[0].v.number < 0 || yyvsp[0].v.number > UINT_MAX) {
				yyerror("only positive values permitted");
				YYERROR;
			}
			yyval.v.state_opt = calloc(1, sizeof(struct node_state_opt));
			if (yyval.v.state_opt == NULL)
				err(1, "state_opt_item: calloc");
			yyval.v.state_opt->type = PF_STATE_OPT_MAX_SRC_CONN_RATE;
			yyval.v.state_opt->data.max_src_conn_rate.limit = yyvsp[-2].v.number;
			yyval.v.state_opt->data.max_src_conn_rate.seconds = yyvsp[0].v.number;
			yyval.v.state_opt->next = NULL;
			yyval.v.state_opt->tail = yyval.v.state_opt;
		}
break;
case 335:
#line 3456 "parse.y"
{
			if (strlen(yyvsp[-2].v.string) >= PF_TABLE_NAME_SIZE) {
				yyerror("table name '%s' too long", yyvsp[-2].v.string);
				free(yyvsp[-2].v.string);
				YYERROR;
			}
			yyval.v.state_opt = calloc(1, sizeof(struct node_state_opt));
			if (yyval.v.state_opt == NULL)
				err(1, "state_opt_item: calloc");
			if (strlcpy(yyval.v.state_opt->data.overload.tblname, yyvsp[-2].v.string,
			    PF_TABLE_NAME_SIZE) >= PF_TABLE_NAME_SIZE)
				errx(1, "state_opt_item: strlcpy");
			free(yyvsp[-2].v.string);
			yyval.v.state_opt->type = PF_STATE_OPT_OVERLOAD;
			yyval.v.state_opt->data.overload.flush = yyvsp[0].v.i;
			yyval.v.state_opt->next = NULL;
			yyval.v.state_opt->tail = yyval.v.state_opt;
		}
break;
case 336:
#line 3474 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > UINT_MAX) {
				yyerror("only positive values permitted");
				YYERROR;
			}
			yyval.v.state_opt = calloc(1, sizeof(struct node_state_opt));
			if (yyval.v.state_opt == NULL)
				err(1, "state_opt_item: calloc");
			yyval.v.state_opt->type = PF_STATE_OPT_MAX_SRC_NODES;
			yyval.v.state_opt->data.max_src_nodes = yyvsp[0].v.number;
			yyval.v.state_opt->next = NULL;
			yyval.v.state_opt->tail = yyval.v.state_opt;
		}
break;
case 337:
#line 3487 "parse.y"
{
			yyval.v.state_opt = calloc(1, sizeof(struct node_state_opt));
			if (yyval.v.state_opt == NULL)
				err(1, "state_opt_item: calloc");
			yyval.v.state_opt->type = PF_STATE_OPT_SRCTRACK;
			yyval.v.state_opt->data.src_track = yyvsp[0].v.i;
			yyval.v.state_opt->next = NULL;
			yyval.v.state_opt->tail = yyval.v.state_opt;
		}
break;
case 338:
#line 3496 "parse.y"
{
			yyval.v.state_opt = calloc(1, sizeof(struct node_state_opt));
			if (yyval.v.state_opt == NULL)
				err(1, "state_opt_item: calloc");
			yyval.v.state_opt->type = PF_STATE_OPT_STATELOCK;
			yyval.v.state_opt->data.statelock = yyvsp[0].v.i;
			yyval.v.state_opt->next = NULL;
			yyval.v.state_opt->tail = yyval.v.state_opt;
		}
break;
case 339:
#line 3505 "parse.y"
{
			yyval.v.state_opt = calloc(1, sizeof(struct node_state_opt));
			if (yyval.v.state_opt == NULL)
				err(1, "state_opt_item: calloc");
			yyval.v.state_opt->type = PF_STATE_OPT_SLOPPY;
			yyval.v.state_opt->next = NULL;
			yyval.v.state_opt->tail = yyval.v.state_opt;
		}
break;
case 340:
#line 3513 "parse.y"
{
			yyval.v.state_opt = calloc(1, sizeof(struct node_state_opt));
			if (yyval.v.state_opt == NULL)
				err(1, "state_opt_item: calloc");
			yyval.v.state_opt->type = PF_STATE_OPT_PFLOW;
			yyval.v.state_opt->next = NULL;
			yyval.v.state_opt->tail = yyval.v.state_opt;
		}
break;
case 341:
#line 3521 "parse.y"
{
			int	i;

			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > UINT_MAX) {
				yyerror("only positive values permitted");
				YYERROR;
			}
			for (i = 0; pf_timeouts[i].name &&
			    strcmp(pf_timeouts[i].name, yyvsp[-1].v.string); ++i)
				;	/* nothing */
			if (!pf_timeouts[i].name) {
				yyerror("illegal timeout name %s", yyvsp[-1].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			if (strchr(pf_timeouts[i].name, '.') == NULL) {
				yyerror("illegal state timeout %s", yyvsp[-1].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			free(yyvsp[-1].v.string);
			yyval.v.state_opt = calloc(1, sizeof(struct node_state_opt));
			if (yyval.v.state_opt == NULL)
				err(1, "state_opt_item: calloc");
			yyval.v.state_opt->type = PF_STATE_OPT_TIMEOUT;
			yyval.v.state_opt->data.timeout.number = pf_timeouts[i].timeout;
			yyval.v.state_opt->data.timeout.seconds = yyvsp[0].v.number;
			yyval.v.state_opt->next = NULL;
			yyval.v.state_opt->tail = yyval.v.state_opt;
		}
break;
case 342:
#line 3553 "parse.y"
{
			yyval.v.string = yyvsp[0].v.string;
		}
break;
case 343:
#line 3558 "parse.y"
{
			yyval.v.qassign.qname = yyvsp[0].v.string;
			yyval.v.qassign.pqname = NULL;
		}
break;
case 344:
#line 3562 "parse.y"
{
			yyval.v.qassign.qname = yyvsp[-1].v.string;
			yyval.v.qassign.pqname = NULL;
		}
break;
case 345:
#line 3566 "parse.y"
{
			yyval.v.qassign.qname = yyvsp[-3].v.string;
			yyval.v.qassign.pqname = yyvsp[-1].v.string;
		}
break;
case 346:
#line 3572 "parse.y"
{
			if (parseport(yyvsp[0].v.string, &yyval.v.range, PPORT_RANGE|PPORT_STAR) == -1) {
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 347:
#line 3581 "parse.y"
{ yyval.v.host = yyvsp[0].v.host; }
break;
case 348:
#line 3582 "parse.y"
{ yyval.v.host = yyvsp[-1].v.host; }
break;
case 349:
#line 3585 "parse.y"
{
			if (yyvsp[-1].v.host->addr.type != PF_ADDR_ADDRMASK) {
				free(yyvsp[-1].v.host);
				yyerror("only addresses can be listed for"
				    "redirection pools ");
				YYERROR;
			}
			yyval.v.host = yyvsp[-1].v.host;
		}
break;
case 350:
#line 3594 "parse.y"
{
			yyvsp[-3].v.host->tail->next = yyvsp[-1].v.host;
			yyvsp[-3].v.host->tail = yyvsp[-1].v.host->tail;
			yyval.v.host = yyvsp[-3].v.host;
		}
break;
case 351:
#line 3601 "parse.y"
{
			yyval.v.redirection = calloc(1, sizeof(struct redirection));
			if (yyval.v.redirection == NULL)
				err(1, "redirection: calloc");
			yyval.v.redirection->host = yyvsp[0].v.host;
			yyval.v.redirection->rport.a = yyval.v.redirection->rport.b = yyval.v.redirection->rport.t = 0;
		}
break;
case 352:
#line 3608 "parse.y"
{
			yyval.v.redirection = calloc(1, sizeof(struct redirection));
			if (yyval.v.redirection == NULL)
				err(1, "redirection: calloc");
			yyval.v.redirection->host = yyvsp[-2].v.host;
			yyval.v.redirection->rport = yyvsp[0].v.range;
		}
break;
case 353:
#line 3618 "parse.y"
{
			yyval.v.hashkey = calloc(1, sizeof(struct pf_poolhashkey));
			if (yyval.v.hashkey == NULL)
				err(1, "hashkey: calloc");
			yyval.v.hashkey->key32[0] = arc4random();
			yyval.v.hashkey->key32[1] = arc4random();
			yyval.v.hashkey->key32[2] = arc4random();
			yyval.v.hashkey->key32[3] = arc4random();
		}
break;
case 354:
#line 3628 "parse.y"
{
			if (!strncmp(yyvsp[0].v.string, "0x", 2)) {
				if (strlen(yyvsp[0].v.string) != 34) {
					free(yyvsp[0].v.string);
					yyerror("hex key must be 128 bits "
						"(32 hex digits) long");
					YYERROR;
				}
				yyval.v.hashkey = calloc(1, sizeof(struct pf_poolhashkey));
				if (yyval.v.hashkey == NULL)
					err(1, "hashkey: calloc");

				if (sscanf(yyvsp[0].v.string, "0x%8x%8x%8x%8x",
				    &yyval.v.hashkey->key32[0], &yyval.v.hashkey->key32[1],
				    &yyval.v.hashkey->key32[2], &yyval.v.hashkey->key32[3]) != 4) {
					free(yyval.v.hashkey);
					free(yyvsp[0].v.string);
					yyerror("invalid hex key");
					YYERROR;
				}
			} else {
				MD5_CTX	context;

				yyval.v.hashkey = calloc(1, sizeof(struct pf_poolhashkey));
				if (yyval.v.hashkey == NULL)
					err(1, "hashkey: calloc");
				MD5Init(&context);
				MD5Update(&context, (unsigned char *)yyvsp[0].v.string,
				    strlen(yyvsp[0].v.string));
				MD5Final((unsigned char *)yyval.v.hashkey, &context);
				HTONL(yyval.v.hashkey->key32[0]);
				HTONL(yyval.v.hashkey->key32[1]);
				HTONL(yyval.v.hashkey->key32[2]);
				HTONL(yyval.v.hashkey->key32[3]);
			}
			free(yyvsp[0].v.string);
		}
break;
case 355:
#line 3667 "parse.y"
{ bzero(&pool_opts, sizeof pool_opts); }
break;
case 356:
#line 3669 "parse.y"
{ yyval.v.pool_opts = pool_opts; }
break;
case 357:
#line 3670 "parse.y"
{
			bzero(&pool_opts, sizeof pool_opts);
			yyval.v.pool_opts = pool_opts;
		}
break;
case 360:
#line 3680 "parse.y"
{
			if (pool_opts.type) {
				yyerror("pool type cannot be redefined");
				YYERROR;
			}
			pool_opts.type =  PF_POOL_BITMASK;
		}
break;
case 361:
#line 3687 "parse.y"
{
			if (pool_opts.type) {
				yyerror("pool type cannot be redefined");
				YYERROR;
			}
			pool_opts.type = PF_POOL_RANDOM;
		}
break;
case 362:
#line 3694 "parse.y"
{
			if (pool_opts.type) {
				yyerror("pool type cannot be redefined");
				YYERROR;
			}
			pool_opts.type = PF_POOL_SRCHASH;
			pool_opts.key = yyvsp[0].v.hashkey;
		}
break;
case 363:
#line 3702 "parse.y"
{
			if (pool_opts.type) {
				yyerror("pool type cannot be redefined");
				YYERROR;
			}
			pool_opts.type = PF_POOL_ROUNDROBIN;
		}
break;
case 364:
#line 3709 "parse.y"
{
			if (pool_opts.staticport) {
				yyerror("static-port cannot be redefined");
				YYERROR;
			}
			pool_opts.staticport = 1;
		}
break;
case 365:
#line 3716 "parse.y"
{
			if (filter_opts.marker & POM_STICKYADDRESS) {
				yyerror("sticky-address cannot be redefined");
				YYERROR;
			}
			pool_opts.marker |= POM_STICKYADDRESS;
			pool_opts.opts |= PF_POOL_STICKYADDR;
		}
break;
case 366:
#line 3726 "parse.y"
{
			/* try to find @if0 address specs */
			if (strrchr(yyvsp[0].v.string, '@') != NULL) {
				if ((yyval.v.host = host(yyvsp[0].v.string)) == NULL)	{
					yyerror("invalid host for route spec");
					YYERROR;
				}
				free(yyvsp[0].v.string);
			} else {
				yyval.v.host = calloc(1, sizeof(struct node_host));
				if (yyval.v.host == NULL)
					err(1, "route_host: calloc");
				yyval.v.host->ifname = yyvsp[0].v.string;
				yyval.v.host->addr.type = PF_ADDR_NONE;
				set_ipmask(yyval.v.host, 128);
				yyval.v.host->next = NULL;
				yyval.v.host->tail = yyval.v.host;
			}
		}
break;
case 367:
#line 3745 "parse.y"
{
			char	*buf;

			if (asprintf(&buf, "%s/%s", yyvsp[-2].v.string, yyvsp[0].v.string) == -1)
				err(1, "host: asprintf");
			free(yyvsp[-2].v.string);
			if ((yyval.v.host = host(buf)) == NULL)	{
				/* error. "any" is handled elsewhere */
				free(buf);
				yyerror("could not parse host specification");
				YYERROR;
			}
			free(buf);
		}
break;
case 368:
#line 3759 "parse.y"
{
			if (strlen(yyvsp[-1].v.string) >= PF_TABLE_NAME_SIZE) {
				yyerror("table name '%s' too long", yyvsp[-1].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			yyval.v.host = calloc(1, sizeof(struct node_host));
			if (yyval.v.host == NULL)
				err(1, "host: calloc");
			yyval.v.host->addr.type = PF_ADDR_TABLE;
			if (strlcpy(yyval.v.host->addr.v.tblname, yyvsp[-1].v.string,
			    sizeof(yyval.v.host->addr.v.tblname)) >=
			    sizeof(yyval.v.host->addr.v.tblname))
				errx(1, "host: strlcpy");
			free(yyvsp[-1].v.string);
			yyval.v.host->next = NULL;
			yyval.v.host->tail = yyval.v.host;
		}
break;
case 369:
#line 3777 "parse.y"
{
			struct node_host	*n;

			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > 128) {
				yyerror("bit number too big");
				YYERROR;
			}
			yyval.v.host = yyvsp[-2].v.host;
			for (n = yyvsp[-2].v.host; n != NULL; n = n->next)
				set_ipmask(n, yyvsp[0].v.number);
		}
break;
case 370:
#line 3788 "parse.y"
{
			struct node_host	*n;

			yyval.v.host = yyvsp[-1].v.host;
			/* XXX check masks, only full mask should be allowed */
			for (n = yyvsp[-1].v.host; n != NULL; n = n->next) {
				if (yyval.v.host->ifname) {
					yyerror("cannot specify interface twice "
					    "in route spec");
					YYERROR;
				}
				if ((yyval.v.host->ifname = strdup(yyvsp[-2].v.string)) == NULL)
					errx(1, "host: strdup");
			}
			free(yyvsp[-2].v.string);
		}
break;
case 371:
#line 3806 "parse.y"
{ yyval.v.host = yyvsp[-1].v.host; }
break;
case 372:
#line 3807 "parse.y"
{
			if (yyvsp[-3].v.host->af == 0)
				yyvsp[-3].v.host->af = yyvsp[-1].v.host->af;
			if (yyvsp[-3].v.host->af != yyvsp[-1].v.host->af) {
				yyerror("all pool addresses must be in the "
				    "same address family");
				YYERROR;
			}
			yyvsp[-3].v.host->tail->next = yyvsp[-1].v.host;
			yyvsp[-3].v.host->tail = yyvsp[-1].v.host->tail;
			yyval.v.host = yyvsp[-3].v.host;
		}
break;
case 373:
#line 3821 "parse.y"
{ yyval.v.host = yyvsp[0].v.host; }
break;
case 374:
#line 3822 "parse.y"
{ yyval.v.host = yyvsp[-1].v.host; }
break;
case 375:
#line 3826 "parse.y"
{
			if (check_rulestate(PFCTL_STATE_OPTION)) {
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > UINT_MAX) {
				yyerror("only positive values permitted");
				YYERROR;
			}
			if (pfctl_set_timeout(pf, yyvsp[-1].v.string, yyvsp[0].v.number, 0) != 0) {
				yyerror("unknown timeout %s", yyvsp[-1].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			free(yyvsp[-1].v.string);
		}
break;
case 378:
#line 3849 "parse.y"
{
			if (check_rulestate(PFCTL_STATE_OPTION)) {
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > UINT_MAX) {
				yyerror("only positive values permitted");
				YYERROR;
			}
			if (pfctl_set_limit(pf, yyvsp[-1].v.string, yyvsp[0].v.number) != 0) {
				yyerror("unable to set limit %s %u", yyvsp[-1].v.string, yyvsp[0].v.number);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			free(yyvsp[-1].v.string);
		}
break;
case 383:
#line 3875 "parse.y"
{ yyval.v.number = 0; }
break;
case 384:
#line 3876 "parse.y"
{
			if (!strcmp(yyvsp[0].v.string, "yes"))
				yyval.v.number = 1;
			else {
				yyerror("invalid value '%s', expected 'yes' "
				    "or 'no'", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 385:
#line 3889 "parse.y"
{ yyval.v.i = PF_OP_EQ; }
break;
case 386:
#line 3890 "parse.y"
{ yyval.v.i = PF_OP_NE; }
break;
case 387:
#line 3891 "parse.y"
{ yyval.v.i = PF_OP_LE; }
break;
case 388:
#line 3892 "parse.y"
{ yyval.v.i = PF_OP_LT; }
break;
case 389:
#line 3893 "parse.y"
{ yyval.v.i = PF_OP_GE; }
break;
case 390:
#line 3894 "parse.y"
{ yyval.v.i = PF_OP_GT; }
break;
#line 8592 "y.tab.c"
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
