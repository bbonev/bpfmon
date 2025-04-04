// $Id: bpfmon.c,v 2.54 2025/03/24 22:19:03 bbonev Exp $ {{{
// Copyright © 2015-2024 Boian Bonev (bbonev@ipacct.com)
//
// SPDX-License-Identifer: GPL-2.0-or-later
//
// This file is part of bpfmon - traffic monitor for BPF and iptables
//
// bpfmon is free software, released under the terms of GNU General Public License v2.0 or later
//
// }}}

// {{{ includes
#define _GNU_SOURCE

#include <pcap.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <wchar.h>
#include <locale.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <langinfo.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <yascreen.h>
// }}}

// {{{ definitions
#define SAMPLES 500
#define TSIZE (8+1+3+1+8+1+3)
#define LSIZE (8)
#define TSIZEH (8+1+8)
#define HELPX 41
#define HELPY 14
#define HSELX 41
#define HSELY 8

// default attributes
//#define DA (YAS_FGXCOLOR(228)|YAS_BGXCOLOR(17))
//#define DA (YAS_FGCOLOR(YAS_WHITE)|YAS_BGCOLOR(YAS_BLACK))
//#define DA (YAS_FGCOLOR(YAS_BLACK)|YAS_BGXCOLOR(21))
#define DA 0

#define mymax(a,b) (((a)>(b))?(a):(b))
#define mymin(a,b) (((a)<(b))?(a):(b))

typedef enum {
	PCAP,
	IPT4,
	IPT6,
	CUST,
} e_source;

typedef struct _s_grf {
	int size;
	int count;
	uint64_t *data;
	int sx,sy;
	char *bf;
} s_grf;

typedef struct _s_bpf {
	s_grf bts;
	s_grf pks;
	int sx,sy;
	char **bf;
	char *bfh;
} s_bpf;

typedef struct _s_ipt {
	struct _s_ipt *next;
	char *table;
	char *chain;
	char *rtext;
	int rulenum;
} s_ipt;

typedef struct _s_cst {
	struct _s_cst *next;
	char *id;
	char *descr;
} s_cst;

static const char *sp_chars_utf8[]={
	"─","…",
	"(",")",
	"•",
};

static const char *sp_chars_asci[]={
	"_",">",
	"(",")",
	"*",
};

typedef enum {
	D_M,D_ELL,
	D_BO,D_BC,
	D_EMPTY,
} e_drc;

static const char *levels_h_utfp[]={" "," "," ","▌","▌","▌","█","█","█"}; // (H) partial utf support on linux console
static const char *levels_h_utff[]={" ","▏","▎","▍","▌","▋","▊","▉","█"}; // (H) full utf support
static const char *levels_h_asci[]={" "," ",".",".","-","-","=","=","="}; // (H) ASCII mode
static const char *levels_v_utfp[]={" "," "," ","▄","▄","▄","█","█","█"}; // (V) partial utf support on linux console
static const char *levels_v_utff[]={" ","▁","▂","▃","▄","▅","▆","▇","█"}; // (V) full utf support
static const char *levels_v_asci[]={" "," ",".",".",":",":","|","|","|"}; // (V) ASCII mode

/* braile graph up/down
⠀⢀⢠⢰⢸
⡀⣀⣠⣰⣸
⡄⣄⣤⣴⣼
⡆⣆⣦⣶⣾
⡇⣇⣧⣷⣿
⠀⠈⠘⠸⢸
⠁⠉⠙⠹⢹
⠃⠋⠛⠻⢻
⠇⠏⠟⠿⢿
⡇⡏⡟⡿⣿
*/

// }}}

// {{{ globals
static yascreen *s;
static const char **drchars=sp_chars_utf8; // frame draw characters
static const char **levels_v_utf8=levels_v_utff; // (V) full utf8 support, this will be changed on linux term
static const char **levels_h_utf8=levels_h_utff; // (H) full utf8 support, this will be changed on linux term
static const char **drlevels_v=levels_v_utff; // (V) graph draw characters
static const char **drlevels_h=levels_h_utff; // (H) graph draw characters

static int heartbeat=0;
static char *sbps=" bytes per second ";
static char *spps=" packets per second ";
static char ver[]="$Revision: 2.54 $";
static int simplest=0; // use simplest console mode
static int legend=1; // show legend in classic mode
static int history=0; // show history in classic mode
static int shhelp=0; // show help window with active keys
static enum {CLASSIC,HORIZ} mode=CLASSIC; // drawing mode
static e_source source=PCAP; // counter source
static e_source iptselectt=PCAP; // select dialog IPTx

static s_bpf dta={{0},{0},0,0,NULL,NULL}; // data with history

static int winch=1; // signal for window size change event or other redraw request
static int redraw=0; // signal to perform full redraw
static int update=0; // signal for timeout that require data refresh
static int toexit=0; // signal for quit request

static char *dev=NULL; // device to dump
static char *flt=NULL; // pcap filter code
static char *chain=NULL; // iptables chain
static char *table="filter"; // iptables default table
static int canfreetablechain=0; // mark if table and chain are ok to be freed
static int rulenum=0; // iptables rule number to monitor
static int iptselect=0; // flag if iptables selection is active
static int noutf8=0; // flag if the underlying os cannot support utf8
static int inverse=0; // XORed with YAS_INVERSE

static s_ipt *rules=NULL; // list of iptables rules for selection
static unsigned tablelen; // max len of table names
static unsigned chainlen; // max len of chain names
static int iptselbeg; // start position of rule list
static int iptselsel; // selected position of rule list
static int iptselcnt; // count of rules

static char *custombin=""; // custom binary to get counters
static char *customparam=""; // custom binary current parameter
static int canfreeparam=0; // mark if customparam is ok to be freed
static int cstselect=0; // flag if custom binary selection is active
static s_cst *binpa=NULL; // list of custom binary parameters
static unsigned idlen; // max len of parameter id
static unsigned dslen; // max len of parameter description
static int cstselbeg; // start position of rule list
static int cstselsel; // selected position of rule list
static int cstselcnt; // count of possible parameters

// libpcap stuff
static struct pcap *pc; // libpcap structure
static struct bpf_program fp; // compiled filter program
static uint64_t bcntr=0; // byte counter
static uint64_t pcntr=0; // pkt counter
static uint64_t bcnto=0; // previous byte counter
static uint64_t pcnto=0; // previous pkt counter
// }}}

static inline int64_t mytime() { // {{{
	struct timespec ts;
	int64_t res;

	clock_gettime(CLOCK_MONOTONIC,&ts);
	res=ts.tv_sec*1000;
	res+=ts.tv_nsec/1000000;
	return res;
} // }}}

static inline void sprintsi(char *s,size_t l,uint64_t v) { // {{{
	const char *u=" KMGTPEZY";
	unsigned int unit=1024;
	uint64_t r=0,rr;
	unsigned pos=0;

	while (v>=10000) {
		r=v%unit;
		v/=unit,pos++;
	}
	if (pos>=strlen(u)) { // number is too big
		strncpy(s," ERROR! ",l); // keep exactly 8 chars of output
		return;
	}

	snprintf(s,l,"%"PRIu64,v); // 4 or less digits
	rr=(r*100)/unit;
	snprintf(s+strlen(s),l-strlen(s),".%02"PRIu64,rr); // exactly 3 chars
	snprintf(s+strlen(s),l-strlen(s),"%c",u[pos]); // exactly 1 char; total = 8 chars
} // }}}

static inline void display(void) { // {{{
	uint64_t db=bcntr-bcnto;
	uint64_t dp=pcntr-pcnto;
	char bs[20],ps[20];

	bcnto=bcntr;
	pcnto=pcntr;

	if (simplest) {
		sprintsi(bs,sizeof bs,db);
		sprintsi(ps,sizeof ps,dp);
		printf("%8s bps %8s pps\n",bs,ps);
		return;
	}

	if (!dta.bts.data||!dta.pks.data) // alloc error
		return;

	if (dta.bts.count<dta.bts.size)
		dta.bts.data[dta.bts.count++]=db;
	else {
		memmove(dta.bts.data+0,dta.bts.data+1,(dta.bts.size-1)*sizeof *dta.bts.data);
		dta.bts.data[dta.bts.size-1]=db;
	}
	if (dta.pks.count<dta.pks.size)
		dta.pks.data[dta.pks.count++]=dp;
	else {
		memmove(dta.pks.data+0,dta.pks.data+1,(dta.pks.size-1)*sizeof *dta.pks.data);
		dta.pks.data[dta.pks.size-1]=dp;
	}
} // }}}

static void sigwinch(int sign __attribute__((unused))) { // {{{
	winch++;
} // }}}

static void sigcont(int sign __attribute__((unused))) { // {{{
	yascreen_term_set(s,YAS_NOBUFF|YAS_NOSIGN|YAS_NOECHO);
	yascreen_altbuf(s,1);
	yascreen_cursor(s,0);
	redraw=1;
	winch++;
} // }}}

static inline void sigchld(int sign __attribute__((unused))) { // {{{
	int status,sverr;

	sverr=errno;
	while ((waitpid(-1,&status,WNOHANG))>0) {
	}
	errno=sverr;
} // }}}

static inline void swin(char *cap,int x,int y,int sx,int sy) { // {{{
	int i,j;

	if (sy>=1) {
		int capcnt=0;

		if (sx>=1)
			yascreen_putsxy(s,x-1,y-1,DA|inverse,drchars[D_M]);
		if (sx>4&&cap[0]) {
			wchar_t *ws=calloc(strlen(cap)+1,sizeof *ws),tws[2];
			int wl,nc=0,cl=0,prsp=1;
			char ts[20];
			int myx=x+1;

			if (ws) {
				if (-1!=(wl=mbstowcs(ws,cap,strlen(cap)))) {
					yascreen_putsxy(s,x,y-1,DA|(YAS_INVERSE^inverse)," ");
					tws[1]=0;
					for (i=0;i<wl;i++) {
						cl+=wcwidth(ws[i]);
						if (cl>=sx-3) {
							prsp=0;
							break;
						}
						nc=cl;
						tws[0]=ws[i];
						wcstombs(ts,tws,20);
						yascreen_putsxy(s,myx++,y-1,DA|(YAS_INVERSE^inverse),ts);
					}
					yascreen_putsxy(s,myx,y-1,DA|(YAS_INVERSE^inverse),prsp?" ":drchars[D_ELL]);
				}
				free(ws);
			}
			capcnt=nc+2; // 2 spaces or space+ellipsis
		}
		for (i=capcnt;i<sx-1;i++)
			yascreen_putsxy(s,x-1+i+1,y-1,DA|inverse,drchars[D_M]);
	}
	for (j=1;j<sy-1;j++) {
		for (i=0;i<sx;i++)
			yascreen_putsxy(s,x-1+i,y+j-1,DA|inverse," ");
	}
	if (sy>=2) {
		for (i=0;i<sx;i++)
			yascreen_putsxy(s,x-1+i,y+sy-1-1,DA|inverse,drchars[D_M]);
	}
} // }}}

static inline void draw(s_grf *g,int x,int y,int sx,int sy) { // {{{
	uint64_t ma,mi;
	int i,j;

	if (!g||!g->count) // nothing to do
		return;

	ma=mi=g->data[g->count-1];
	for (i=1;i<sx;i++) {
		if (g->count-i-1<0)
			break;
		if (mi>g->data[g->count-i-1])
			mi=g->data[g->count-i-1];
		if (ma<g->data[g->count-i-1])
			ma=g->data[g->count-i-1];
	}

	for (j=0;j<sy;j++) {
		if (legend) {
			char ts[20];

			sprintsi(ts,sizeof ts,mi+(sy-j)*(ma-mi)/sy);
			yascreen_printxy(s,x-1-LSIZE-1,y-1+j,DA|inverse,"%8s",ts);
		}
		for (i=0;i<sx;i++) {
			if (i>=g->count)
				yascreen_putsxy(s,x+i-1,y+j-1,DA|inverse," ");
			else {
				int64_t vhr=((g->data[g->count-i-1]-mi)*sy*8)/((!ma)?1:ma);
				const char *prch;
				int64_t v=vhr/8;
				uint8_t r=vhr%8;

				if (v>(sy-j-1)&&v>(sy-j))
					prch=drlevels_v[8];
				else {
					if (v>(sy-j-1))
						prch=drlevels_v[r];
					else
						prch=drlevels_v[0];
				}
				yascreen_putsxy(s,x+i-1,y+j-1,DA|inverse,prch);
			}
		}
	}

} // }}}

static inline void drawt(s_bpf *d,int x,int y,int sx,int sy) { // {{{
	int j,cnt,off;
	char ts[sx+30];

	if (!d||!d->bts.count||!d->pks.count) // nothing to do
		return;

	cnt=mymin(d->bts.count,d->pks.count);
	off=0;
	if (sy<cnt)
		off=cnt-sy;

	for (j=0;j<sy;j++) {
		if (j>=cnt)
			snprintf(ts,sizeof ts,"%*s",sx,"");
		else {
			char bs[20],ps[20];

			sprintsi(bs,sizeof bs,d->bts.data[off+j]);
			sprintsi(ps,sizeof ps,d->pks.data[off+j]);
			snprintf(ts,sizeof ts,"%8s bps %8s pps%*s",bs,ps,sx-TSIZE,"");
		}
		yascreen_putsxy(s,x-1,y+j-1,DA|inverse,ts);
	}
} // }}}

static inline void drawh(s_bpf *g,int x,int y,int sx,int sy) { // {{{
	uint64_t bma,bmi,pma,pmi; // bytes min/max packets min/max
	int grs=(sx-2-TSIZEH)/2; // graph part size
	int tpos=grs,g1pos=0,g2pos=tpos+TSIZEH+2; // text position; graph part positions
	int cnt,i,j;
	int off=0;

	if (sx<TSIZEH+2) // do not draw if there is not enough space
		return;
	if (!g||!g->bts.count||!g->pks.count) // nothing to do
		return;

	cnt=mymin(g->bts.count,g->pks.count);
	if (sy<cnt)
		off=cnt-sy;

	bma=bmi=g->bts.data[g->bts.count-1];
	pma=pmi=g->pks.data[g->pks.count-1];
	for (i=1;i<sy;i++) {
		if (g->bts.count-i-1<0)
			break;
		if (g->pks.count-i-1<0)
			break;
		if (bmi>g->bts.data[g->bts.count-i-1])
			bmi=g->bts.data[g->bts.count-i-1];
		if (bma<g->bts.data[g->bts.count-i-1])
			bma=g->bts.data[g->bts.count-i-1];
		if (pmi>g->pks.data[g->pks.count-i-1])
			pmi=g->pks.data[g->pks.count-i-1];
		if (pma<g->pks.data[g->pks.count-i-1])
			pma=g->pks.data[g->pks.count-i-1];
	}

	for (j=0;j<sy;j++) {
		if (j>=cnt)
			yascreen_printxy(s,x-1,y+j-1,DA|inverse,"%*s",sx,"");
		else {
			int64_t vbr=((g->bts.data[off+j]-bmi)*grs*8)/((!bma)?1:bma);
			int64_t vpr=((g->pks.data[off+j]-pmi)*grs*8)/((!pma)?1:pma);
			char bs[20],ps[20];
			const char *prchb;
			const char *prchp;
			int64_t vb=vbr/8;
			int64_t vp=vpr/8;
			uint8_t rb=vbr%8;
			uint8_t rp=vpr%8;
			uint32_t inv;

			sprintsi(bs,sizeof bs,g->bts.data[off+j]);
			sprintsi(ps,sizeof ps,g->pks.data[off+j]);
			yascreen_printxy(s,x-1+tpos,y+j-1,DA|inverse," %8s %8s ",bs,ps);
			for (i=0;i<grs;i++) {
				inv=0;
				if (vb<(grs-i-1))
					prchb=drlevels_h[0];
				else {
					if (vb>(grs-i-1))
						prchb=drlevels_h[8];
					else {
						prchb=drlevels_h[rb];
						if (vbr>0&&drchars==sp_chars_utf8)
							inv=YAS_INVERSE;
					}
				}
				if (vp<i)
					prchp=drlevels_h[0];
				else {
					if (vp>i)
						prchp=drlevels_h[8];
					else
						prchp=drlevels_h[rp];
				}
				yascreen_putsxy(s,x-1+i+g1pos,y-1+j,(DA|inverse)^inv,prchb);
				yascreen_putsxy(s,x-1+i+g2pos,y-1+j,DA|inverse,prchp);
			}
		}
	}
} // }}}

static void pc_cb(unsigned char *user __attribute__((unused)),const struct pcap_pkthdr *h,const u_char *bytes __attribute__((unused))) { // {{{
	pcntr++;
	bcntr+=h->len;
} // }}}

static inline void ipt_rule_free(void) { // {{{
	s_ipt *p;

	while (rules) {
		p=rules->next;
		if (rules->table)
			free(rules->table);
		if (rules->chain)
			free(rules->chain);
		if (rules->rtext)
			free(rules->rtext);
		free(rules);
		rules=p;
	}
} // }}}

static inline void ipt_rule_get(void) { // {{{
	char *ctable=NULL,*cchain=NULL;
	char rl[4096];
	int rnum=0;
	FILE *f;

	if (rules)
		ipt_rule_free();

	if ((f=popen(iptselectt==IPT4?"iptables-save 2>/dev/null":"ip6tables-save 2>/dev/null","r"))) {
		chainlen=0;
		tablelen=0;
		while (fgets(rl,sizeof rl,f)) {
			if (strlen(rl)>0) // nuke end of line
				rl[strlen(rl)-1]=0;
			if (rl[0]=='#'||rl[0]==':') // ignore comments and table creates
				continue;
			if (rl[0]=='C') // ignore COMMIT by loose matching
				continue;

			//printf("got rule: %s\n",rl);
			if (rl[0]=='*') {
				if (ctable)
					free(ctable);
				ctable=strdup(rl+1);
				if (!ctable) {
					fprintf(stderr,"cannot allocate memory for table\n");
					exit(1);
				}
				continue;
			}
			if (strlen(rl)>4&&rl[0]=='-'&&rl[1]=='A'&&rl[2]==' ') {
				char *p=rl+3;
				s_ipt *r;

				if (!ctable) // silently ignore garbage
					continue;

				while (*p&&*p!=' ')
					p++;
				if (*p) {
					*p=0;
					p++;
				}

				r=calloc(1,sizeof *r);
				if (!r) {
					fprintf(stderr,"cannot allocate memory for rule\n");
					exit(1);
				}

				if (!cchain||strcmp(cchain,rl+3)) { // first or different chain
					rnum=1;
					if (cchain)
						free(cchain);
					cchain=strdup(rl+3);
					if (!cchain) {
						fprintf(stderr,"cannot allocate memory for chain\n");
						exit(1);
					}
				} else
					rnum++;

				r->rulenum=rnum;
				r->rtext=strdup(p);
				r->chain=strdup(cchain);
				r->table=strdup(ctable);

				if (!r->rtext||!r->chain||!r->table) {
					fprintf(stderr,"cannot allocate memory for strings\n");
					exit(1);
				}

				r->next=rules;
				rules=r;
				chainlen=mymax(chainlen,strlen(r->chain));
				tablelen=mymax(tablelen,strlen(r->table));
			}
		}
		pclose(f);
	}
	if (cchain)
		free(cchain);
	if (ctable)
		free(ctable);

	// reverse the list
	iptselcnt=0;
	s_ipt *pr=rules,*t=NULL;
	while (pr) {
		s_ipt *tt=pr;

		//printf("got rule: %-*s %-*s %s\n",tablelen,pr->table,chainlen,pr->chain,pr->rtext);
		pr=pr->next;
		tt->next=t;
		t=tt;
		iptselcnt++;
	}
	rules=t;
	iptselbeg=0;
	iptselsel=0;
} // }}}

static inline void cst_param_free(void) { // {{{
	s_cst *p;

	while (binpa) {
		p=binpa->next;
		if (binpa->id)
			free(binpa->id);
		if (binpa->descr)
			free(binpa->descr);
		free(binpa);
		binpa=p;
	}
} // }}}

static inline void cst_param_get(void) { // {{{
	char buf[strlen(custombin)+strlen(" bpfmon-list 2>/dev/null")+1];
	s_cst *pr,*t=NULL;
	char rl[4096];
	int first=1;
	FILE *f;

	if (binpa)
		cst_param_free();

	snprintf(buf,sizeof buf,"%s bpfmon-list 2>/dev/null",custombin);
	//printf("running %s\n",buf);
	if ((f=popen(buf,"r"))) {
		idlen=0;
		dslen=0;
		while (fgets(rl,sizeof rl,f)) {
			char *id,*descr;
			s_cst *n;

			if (strlen(rl)>0) // nuke end of line
				rl[strlen(rl)-1]=0;
			// trim the line
			for (id=rl;*id==' '||*id=='\t';id++) {
			}
			if (id!=rl)
				memmove(rl,id,sizeof rl-(id-rl));
			while (strlen(rl)&&(rl[strlen(rl)-1]==' '||rl[strlen(rl)-1]=='\t'))
				rl[strlen(rl)-1]=0;

			if (first) {
				if (strcmp(rl,"#bpfmon-counters")) { // invalid format, ignore
					//printf("script does not support parameters\n");
					break;
				}
				first=0;
			}

			if (rl[0]=='#') // ignore comments
				continue;

			id=rl;
			while (*id!=' '||*id=='\t')
				id++;
			if (!*id) // no description
				continue;
			*id=0;
			descr=id+1;
			while (*descr==' '||*descr=='\t')
				descr++;
			if (!*descr) // no description
				continue;
			id=rl;

			//printf("got id: %s descr: %s\n",id,descr);

			n=calloc(1,sizeof *n);
			if (!n) {
				fprintf(stderr,"cannot allocate memory for parameter\n");
				exit(1);
			}
			n->id=strdup(id);
			n->descr=strdup(descr);
			if (!n->id||!n->descr) {
				if (n->id)
					free(n->id);
				if (n->descr)
					free(n->descr);
				free(n);
				fprintf(stderr,"cannot allocate memory for parameter\n");
				exit(1);
			}
			n->next=binpa;
			binpa=n;
			idlen=mymax(idlen,strlen(n->id));
			dslen=mymax(dslen,strlen(n->descr));
		}
		pclose(f);
	}

	// reverse the list
	cstselcnt=0;
	pr=binpa;
	while (pr) {
		s_cst *tt=pr;

		pr=pr->next;
		tt->next=t;
		t=tt;
		cstselcnt++;
	}
	binpa=t;
	//printf("binpa: %p\n",binpa);
	cstselbeg=0;
	cstselsel=0;
} // }}}

static inline void ipt_data_fetch(void) { // {{{
	char s[mymax((!(chain&&rulenum))?1:100+strlen(table)+strlen(chain),strlen(custombin)+1+strlen(customparam)+100)];
	uint64_t pc,bc;
	char *cmd;
	FILE *f;

	if (source!=CUST&&!(chain&&rulenum)) // do not collect any data in iptables rule select mode - initially rule may be unknown
		return;

	switch (source) {
		default:
			cmd="true"; // we should not reach here
			break;
		case IPT4:
			cmd="iptables";
			break;
		case IPT6:
			cmd="ip6tables";
			break;
		case CUST:
			cmd=custombin;
			break;
	}
	switch (source) {
		case IPT4:
		case IPT6:
			snprintf(s,sizeof s,"%s -xvnt %s -L %s %d 2>/dev/null",cmd,table,chain,rulenum);
			break;
		default:
		case CUST:
			snprintf(s,sizeof s,"%s%s%s 2>/dev/null",cmd,strlen(customparam)?" ":"",customparam);
			break;
	}
	if ((f=popen(s,"r"))) {
		if (2==fscanf(f,"%"SCNu64" %"SCNu64,&pc,&bc)) {
			pcntr=pc;
			bcntr=bc;
			if (!pcnto&&!bcnto) { // skip initial burst
				pcnto=pcntr;
				bcnto=bcntr;
			}
		} else {
		}
		pclose(f);
	}
} // }}}

int main(int ac,char **av) { // {{{
	unsigned gsx=0,gsy=0,gx=(history?(TSIZE+2):0)+(legend?(LSIZE+2):0)+((!legend&&!history)?1:0),g1y=2,g2y=2;
	char ebuf[PCAP_ERRBUF_SIZE];
	char *term=getenv("TERM");
	int64_t lastroll=0;
	struct timeval to;
	int wssx=0,wssy=0;
	int has_unicode=0;
	time_t lastt=0;
	char ts[100];
	char *p,*q;
	int fdmax;
	int tslen;
	fd_set r;
	int pcfd;
	int i;

	memset(&r,0,sizeof r); // make clang static analyzer happier (llvm bug #8920)
	pcfd=0; // make old cc happy about bogus warning for possibly uninitialized var

	// move numeric ver to the beginning and nul terminate it
	p=q=ver;
	while (*p&&*p!=' ')
		p++;
	p++;
	while (*p&&*p!=' ')
		*q++=*p++;
	*q=0;

	if (ac<2) {
	helpandexit:
		printf(
			"bpfmon %s\n"
			"Usage: %s [-autzvIiLlnNh] <device> '<bpf_filter_code>'\n"
			"       %s [-autzvIiLlnNh] iptables '[<table>] <chain> <rulenum>'\n"
			"       %s [-autzvIiLlnNh] iptables [select]\n"
			"       %s [-autzvIiLlnNh] ip6tables '[<table>] <chain> <rulenum>'\n"
			"       %s [-autzvIiLlnNh] ip6tables [select]\n"
			"       %s [-autzvIiLlnNh] custom <path-to-binary>\n"
			"\t-a  -  use ASCII drawing chars\n"
			"\t-u  -  use UTF-8 drawing chars (default)\n"
			"\t-t  -  use no interface (simple text output)\n"
			"\t-z  -  use horizontal full-screen interface\n"
			"\t-v  -  use vertical full-screen interface (default)\n"
			"\t-I  -  show history in vertical full-screen\n"
			"\t-i  -  hide history in vertical full-screen (default)\n"
			"\t-L  -  show legend in vertical full-screen (default)\n"
			"\t-l  -  hide legend in vertical full-screen\n"
			"\t-n  -  show interface white on black (default)\n"
			"\t-N  -  show interface inverse (black on white)\n"
			"\t-h  -  display this help and exit\n"
			"\n"
			"Keys used in full-screen mode:\n"
			"\th, ?    - toggle help screen\n"
			"\ta       - switch to ASCII drawing chars\n"
			"\tu       - switch to UTF-8 drawing chars\n"
			"\tm       - toggle horizontal/vertical mode\n"
			"\ti       - toggle history in vertical mode\n"
			"\tl       - toggle legend in vertical mode\n"
			"\tr, ^L   - refresh screen\n"
			"\tq, ^C   - quit\n"
			"Examples:\n"
			"\tbpfmon eth0 'arp or ip'      - count arp or ip packets on eth0\n"
			"\tbpfmon any ''                - count all packets on all interfaces\n"
			"\tbpfmon iptables 'FORWARD 1'  - count packets matched by first rule in table filter, chain FORWARD\n"
			"\tbpfmon iptables 'nat chn 3'  - count packets matched by third rule in table nat, chain chn\n"
			"\tbpfmon iptables              - count packets matched by a selected iptables rule\n"
			"\tbpfmon custom /home/me/c.sh  - custom data from script (space separated packets bytes)\n"
			"See tcpdump's manual for full description of BPF filter-code\n"
			"Remember to put the filter code or iptables table/chain/rulenum in quotes.\n"
			"\n"
			,ver,av[0],av[0],av[0],av[0],av[0],av[0]);
		return 0;
	}

	for (i=1;i<ac;i++) {
		if (av[i][0]!='-') {
			if (dev&&flt) {
				fprintf(stderr,"too many command line parameters\n");
				return 1;
			}
			if (!dev)
				dev=av[i];
			else
				if (!flt)
					flt=av[i];
		} else {
			unsigned j;

			for (j=1;j<strlen(av[i]);j++)
				switch (av[i][j]) {
					case 'h':
						goto helpandexit;
						break;
					case 'a':
						drchars=sp_chars_asci;
						drlevels_h=levels_h_asci;
						drlevels_v=levels_v_asci;
						break;
					case 'u': // no need to check for noutf8, because it is set below and will override this
						drchars=sp_chars_utf8;
						drlevels_h=levels_h_utf8;
						drlevels_v=levels_v_utf8;
						break;
					case 't':
						simplest=1;
						break;
					case 'z':
						simplest=0;
						mode=HORIZ;
						break;
					case 'v':
						simplest=0;
						mode=CLASSIC;
						break;
					case 'i':
						history=0;
						break;
					case 'I':
						history=1;
						break;
					case 'l':
						legend=0;
						break;
					case 'L':
						legend=1;
						break;
					case 'n':
						inverse=0;
						break;
					case 'N':
						inverse=YAS_INVERSE;
						break;
					default:
						fprintf(stderr,"unrecognized option '%c'\n",av[i][j]);
						return 1;
				}
		}
	}

	if (!dev) {
		fprintf(stderr,"device is not specified\n");
		return 1;
	}
	if (!flt&&strcmp(dev,"iptables")&&strcmp(dev,"ip6tables")&&strcmp(dev,"custom")) {
		fprintf(stderr,"bpf filter code is not specified\n");
		return 1;
	}

	if (!strcmp(dev,"iptables")||!strcmp(dev,"ip6tables")) {
		char *a1,*a2,*a3=NULL;
		char *t=flt;

		source=strcmp(dev,"iptables")?IPT6:IPT4;
		iptselectt=source;
		if (!flt||!strcmp(flt,"select")) {
			iptselect=1;
			if (simplest) {
				fprintf(stderr,"%s rule selection is not available in simple text output mode\n",source==IPT4?"iptables":"ip6tables");
				return 1;
			}
			ipt_rule_get();
		} else {
			while (*t==' ')
				t++;
			a1=t;
			while (*t&&*t!=' ')
				t++;
			if (!*t) {
				fprintf(stderr,"%s filter code format is \"chain rulenum\"; \"%s\" given\n",source==IPT4?"iptables":"ip6tables",flt);
				return 1;
			}
			*t=0;
			t++;
			while (*t==' ')
				t++;
			a2=t;
			while (*t&&*t!=' ')
				t++;
			if (!*t) { // only 2 args given - a1 is chain a2 is rulenum
				rulenum=atoi(a2);
				if (rulenum<=0) {
					fprintf(stderr,"%s filter code rulenum must be >=0; %d given\n",source==IPT4?"iptables":"ip6tables",rulenum);
					return 1;
				}
				chain=a1;
			} else { // 3+ args - a1 is table, a2 is chain and a3 is rulenum; the rest are ignored
				*t=0;
				t++;
				while (*t==' ')
					t++;
				a3=t;

				rulenum=atoi(a3);
				if (rulenum<=0) {
					fprintf(stderr,"%s filter code rulenum must be >=0; %d given\n",source==IPT4?"iptables":"ip6tables",rulenum);
					return 1;
				}
				chain=a2;
				table=a1;
			}
		}
	}

	if (!strcmp(dev,"custom")) {
		if (!flt) {
			fprintf(stderr,"binary path is not specified\n");
			return 1;
		}
		source=CUST;
		custombin=flt;
	}

	if (source==PCAP) {
		if ((pc=pcap_open_live(dev,8024,1,100,ebuf))==NULL) {
			fprintf(stderr,"open_live error: (%s) %s\n",dev,ebuf);
			return 1;
		}
		if (-1==pcap_setnonblock(pc,1,ebuf)) {
			fprintf(stderr,"setnonblock error: %s\n",ebuf);
			return 1;
		}
		pcfd=pcap_get_selectable_fd(pc);
		if (-1==pcap_compile(pc,&fp,flt,1,0)) {
			fprintf(stderr,"filter compile error: %s\n",flt);
			return 1;
		}
		if (-1==pcap_setfilter(pc,&fp)) {
			fprintf(stderr,"setfilter error\n");
			return 1;
		}
		pcap_freecode(&fp);
	}

	signal(SIGCHLD,sigchld);

	if (!simplest) {
		dta.bts.count=0;
		dta.bts.size=SAMPLES;
		dta.bts.data=calloc(SAMPLES,sizeof(uint64_t));
		dta.pks.count=0;
		dta.pks.size=SAMPLES;
		dta.pks.data=calloc(SAMPLES,sizeof(uint64_t));
		if (!dta.bts.data||!dta.pks.data) {
			fprintf(stderr,"cannot allocate memory\n");
			return 1;
		}

		signal(SIGWINCH,sigwinch);
		signal(SIGCONT,sigcont);

		if (term&&!strcmp(term,"linux")) { // silly check for linux console
			drlevels_h=levels_h_utf8=levels_h_utfp;
			drlevels_v=levels_v_utf8=levels_v_utfp;
		}

		if (setlocale(LC_CTYPE,"C.UTF-8")) // try if unicode is supported
			has_unicode=1;
		else
			if (setlocale(LC_CTYPE,""))
				if (!strcmp("UTF-8",nl_langinfo(CODESET)))
					has_unicode=1;

		if (!has_unicode) { // utf8 is not supported, disable utf mode and force to ascii
			drchars=sp_chars_asci;
			drlevels_h=levels_h_asci;
			drlevels_v=levels_v_asci;
			noutf8=1;
		}

		setbuf(stdout,NULL);
		s=yascreen_init(0,0); // let yascreen get term size
		if (!s) {
			fprintf(stderr,"cannot allocate screen\n");
			return 1;
		}
		yascreen_term_set(s,YAS_NOBUFF|YAS_NOSIGN|YAS_NOECHO);
		wssx=yascreen_sx(s);
		wssy=yascreen_sy(s);

		yascreen_altbuf(s,1);
		yascreen_cursor(s,0);
	}
	snprintf(ts,sizeof ts,"bpfmon %s",ver);
	tslen=strlen(ts);

	if (source==IPT4||source==IPT6||source==CUST) {
		if (source==CUST) {
			cst_param_get();
			if (cstselcnt>1)
				cstselect=1;
			if (cstselcnt==1) {
				if (canfreeparam)
					if (customparam)
						free(customparam);
				canfreeparam=1;
				customparam=strdup(binpa->id);
			}
		}
		ipt_data_fetch();
	}

	for (;;) {
		int64_t now=mytime();

		if (!lastt||lastt+1000<now) { // display results every second
			if (source==IPT4||source==IPT6||source==CUST)
				ipt_data_fetch();
			if (!lastt)
				lastt=now;
			else
				lastt+=1000;
			if ((source!=IPT4&&source!=IPT6)||(chain&&rulenum))
				display();
			update=1; // force redraw
		}

		if (!simplest) {
			if (winch) {
				if (yascreen_resize(s,0,0)) {
					fprintf(stderr,"cannot resize screen\n");
					return 1;
				}
				wssx=yascreen_sx(s);
				wssy=yascreen_sy(s);
				if (redraw) {
					yascreen_redraw(s);
					redraw=0;
				}
				gx=(history?(TSIZE+2):0)+(legend?(LSIZE+2):0)+((!legend&&!history)?1:0);
				gsx=wssx-gx+1;
				gsy=(wssy-3)/2;
				g2y=gsy+3;
				swin((mode==HORIZ||history)?ts:"",1,1,wssx,wssy);
				if (wssx>14) {
					yascreen_putsxy(s,1,wssy-1,DA|inverse,drchars[D_BO]);
					yascreen_putsxy(s,2,wssy-1,DA|((heartbeat*YAS_INVERSE)^inverse),drchars[D_EMPTY]);
					yascreen_putsxy(s,3,wssy-1,DA|inverse,drchars[D_BC]);
					yascreen_putsxy(s,4,wssy-1,DA|inverse," q=quit ");
				}
				if (wssx>14+9+6)
					yascreen_printxy(s,wssx-9-6-1,wssy-1,DA|inverse," size: %dx%d ",wssx,wssy);
				switch (mode) {
					case CLASSIC:
						if (gsy>5&&gsx>5) {
							char t[mymax(strlen(sbps),strlen(spps))+1];
							int i;

							if (legend)
								for (i=0;i<8;i++)
									yascreen_putsxy(s,gx-1-1-8+i,g2y-1-1,DA|inverse,drchars[D_M]);
							strncpy(t,sbps,sizeof t);
							if (gsx<strlen(sbps))
								t[gsx]=0;
							yascreen_printxy(s,gx-1-1,0,DA|(YAS_INVERSE^inverse),"%*s",(unsigned)mymin(gsx,strlen(t)),t);

							strncpy(t,spps,sizeof t);
							if (gsx<strlen(spps))
								t[gsx]=0;
							yascreen_printxy(s,gx-1-1,g2y-1-1,DA|(YAS_INVERSE^inverse),"%*s",(unsigned)mymin(gsx,strlen(t)),t);
							for (i=gx-1+strlen(t);i<=wssx;i++)
								yascreen_putsxy(s,i-1,g2y-1-1,DA|inverse,i==wssx?drchars[D_M]:drchars[D_M]);
						}
						break;
					case HORIZ:
						if (wssx>=TSIZEH) {
							int hp=(wssx-TSIZEH)/2+8-5+1;

							if (tslen+4<hp)
								yascreen_putsxy(s,hp-1,0,DA|(YAS_INVERSE^inverse)," bps ");
							if (tslen+4<hp+9)
								yascreen_putsxy(s,hp+9-1,0,DA|(YAS_INVERSE^inverse)," pps ");
						}
						break;
				}
				if (mode==CLASSIC&&!history) // draw name & version on the right
					yascreen_printxy(s,wssx-strlen(ts)-1-2,0,DA|(YAS_INVERSE^inverse)," %s ",ts);
				winch--;
				update=1;
				dta.sx=dta.sy=dta.bts.sx=dta.bts.sy=dta.pks.sx=dta.pks.sy=0; // force clearing of buffers
			}
			if (update) {
				switch (mode) {
					case CLASSIC:
						if (gsy>5&&gsx>5) {
							draw(&dta.bts,gx,g1y,gsx,gsy);
							draw(&dta.pks,gx,g2y,gsx,gsy);
						}
						if (history&&wssy>2&&wssx>=TSIZE+1)
							drawt(&dta,1,2,TSIZE,wssy-2);
						break;
					case HORIZ:
						if (wssy>2&&wssx>=TSIZEH+2)
							drawh(&dta,1,2,wssx,wssy-2);
				}
				if ((iptselect||cstselect)&&wssx>=8&&wssy>=6) { // iptable rule selection dialog
					int selx=wssx-6;
					int sely=wssy-6;
					int hx=mymax(2,(wssx-selx)/2+1);
					int hy=mymax(2,(wssy-sely)/2+1);
					int sx=mymin((unsigned)wssx-2,(unsigned)selx);
					int sy=mymin((unsigned)wssy-2,(unsigned)sely);
					int cntshow=sely-2;

					if (cstselect)
						swin("select custom script parameter",hx,hy,sx,sy);
					else {
						if (iptselectt==IPT4)
							swin("select iptables rule",hx,hy,sx,sy);
						else
							swin("select ip6tables rule",hx,hy,sx,sy);
					}
					if (iptselect&&iptselcnt&&cntshow>0) { // enough items and space to show
						s_ipt *pr=rules;
						int mybeg;
						int pos=0;

						// ensure selected pos is in bounds
						if (iptselsel>=iptselcnt)
							iptselsel=iptselcnt-1;
						if (iptselsel<0)
							iptselsel=0;
						// adjust begin position
						if (iptselbeg>iptselsel)
							iptselbeg=iptselsel;
						if (iptselsel-iptselbeg>=cntshow)
							iptselbeg=iptselsel-cntshow+1;
						mybeg=iptselbeg;
						if (iptselcnt-mybeg<cntshow)
							mybeg=iptselcnt-cntshow;
						if (mybeg<0)
							mybeg=0;

						while (pr) {
							if (pos>=mybeg) { // show item
								int post=hx;
								int posc=hx+tablelen+1;
								int posr=hx+tablelen+1+chainlen+1;
								int lent=mymin((int)tablelen,sx-2);
								int lenc=mymin(chainlen,sx-2-tablelen-1);
								int lenr=sx-2-tablelen-1-chainlen-1;

								if (pos-mybeg>=cntshow) // end of space
									break;
								if (sx>2) {
									yascreen_printxy(s,post,hy+pos-mybeg,DA|(inverse^(pos==iptselsel?YAS_INVERSE:0)),"%-*.*s",lent,lent,pr->table);
									if ((unsigned)sx>2+tablelen+1) {
										yascreen_printxy(s,posc,hy+pos-mybeg,DA|(inverse^(pos==iptselsel?YAS_INVERSE:0)),"%-*.*s",lenc,lenc,pr->chain);
										if ((unsigned)sx>2+tablelen+1+chainlen+1)
											yascreen_printxy(s,posr,hy+pos-mybeg,DA|(inverse^(pos==iptselsel?YAS_INVERSE:0)),"%-*.*s",lenr,lenr,pr->rtext);
									}
								}
							}
							pr=pr->next;
							pos++;
						}
					}
					if (iptselect&&!rules)
						yascreen_printxy(s,hx,hy+0,DA|inverse,"%.*s",sx-2,sy<=2?"":"No rule to display, use q to quit");
					if (cstselect&&cstselcnt&&cntshow>0) { // enough items and space to show
						s_cst *pr=binpa;
						int mybeg;
						int pos=0;

						// ensure selected pos is in bounds
						if (cstselsel>=cstselcnt)
							cstselsel=cstselcnt-1;
						if (cstselsel<0)
							cstselsel=0;
						// adjust begin position
						if (cstselbeg>cstselsel)
							cstselbeg=cstselsel;
						if (cstselsel-cstselbeg>=cntshow)
							cstselbeg=cstselsel-cntshow+1;
						mybeg=cstselbeg;
						if (cstselcnt-mybeg<cntshow)
							mybeg=cstselcnt-cntshow;
						if (mybeg<0)
							mybeg=0;

						while (pr) {
							if (pos>=mybeg) { // show item
								int post=hx;
								int posc=hx+idlen+1;
								int leni=mymin((int)idlen,sx-2);
								int lend=sx-2-leni-1;

								if (pos-mybeg>=cntshow) // end of space
									break;
								if (sx>2) {
									yascreen_printxy(s,post,hy+pos-mybeg,DA|(inverse^(pos==cstselsel?YAS_INVERSE:0)),"%-*.*s",leni,leni,pr->id);
									if ((unsigned)sx>2+idlen+1)
										yascreen_printxy(s,posc,hy+pos-mybeg,DA|(inverse^(pos==cstselsel?YAS_INVERSE:0)),"%-*.*s",lend,lend,pr->descr);
								}
							}
							pr=pr->next;
							pos++;
						}
					}
					if (cstselect&&!binpa)
						yascreen_printxy(s,hx,hy+0,DA|inverse,"%.*s",sx-2,sy<=2?"":"No script parameters to display, use q to quit");
				}
				if (shhelp&&wssx>=4&&wssy>=4) { // help screens
					if (iptselect||cstselect) {
						int hx=mymax(2,(wssx-HSELX)/2+1);
						int hy=mymax(2,(wssy-HSELY)/2+1);
						int sx=mymin(wssx-2,HSELX);
						int sy=mymin(wssy-2,HSELY);

						if (iptselectt==IPT4)
							swin("help (iptables rule select)",hx,hy,sx,sy);
						else
							swin("help (ip6tables rule select)",hx,hy,sx,sy);
						yascreen_printxy(s,hx,hy+0,DA|inverse,"%.*s",sx-2,sy<=2?"":"UP,DN  - scroll up and down");
						yascreen_printxy(s,hx,hy+1,DA|inverse,"%.*s",sx-2,sy<=3?"":(iptselect?"ENTER  - select rule":"ENTER  - select parameter"));
						yascreen_printxy(s,hx,hy+2,DA|inverse,"%.*s",sx-2,sy<=4?"":"ESC    - cancel selection");
						yascreen_printxy(s,hx,hy+3,DA|inverse,"%.*s",sx-2,sy<=5?"":"s, 6   - change or cancel selection");
						yascreen_printxy(s,hx,hy+4,DA|inverse,"%.*s",sx-2,sy<=6?"":"r, ^L  - refresh screen");
						yascreen_printxy(s,hx,hy+5,DA|inverse,"%.*s",sx-2,sy<=7?"":"q, ^C  - quit");
					} else {
						int hx=mymax(2,(wssx-HELPX)/2+1);
						int hy=mymax(2,(wssy-HELPY)/2+1);
						int sx=mymin(wssx-2,HELPX);
						int sy=mymin(wssy-2,HELPY);

						swin("help",hx,hy,sx,sy);
						yascreen_printxy(s,hx,hy+0,DA|inverse,"%.*s",sx-2,sy<=2?"":"h, ?  - toggle help screen");
						yascreen_printxy(s,hx,hy+1,DA|inverse,"%.*s",sx-2,sy<=3?"":"a     - switch to ASCII drawing chars");
						yascreen_printxy(s,hx,hy+2,DA|inverse,"%.*s",sx-2,sy<=4?"":"u     - switch to UTF-8 drawing chars");
						yascreen_printxy(s,hx,hy+3,DA|inverse,"%.*s",sx-2,sy<=5?"":"m     - toggle horizontal/vertical mode");
						yascreen_printxy(s,hx,hy+4,DA|inverse,"%.*s",sx-2,sy<=6?"":"i     - toggle history in vertical mode");
						yascreen_printxy(s,hx,hy+5,DA|inverse,"%.*s",sx-2,sy<=7?"":"l     - toggle legend in vertical mode");
						yascreen_printxy(s,hx,hy+6,DA|inverse,"%.*s",sx-2,sy<=8?"":"n     - toggle inverse mode");
						yascreen_printxy(s,hx,hy+7,DA|inverse,"%.*s",sx-2,sy<=9?"":"z     - zero history and restart");
						yascreen_printxy(s,hx,hy+8,DA|inverse,"%.*s",sx-2,sy<=10?"":"s     - iptables rule select");
						yascreen_printxy(s,hx,hy+9,DA|inverse,"%.*s",sx-2,sy<=11?"":"6     - ip6tables rule select");
						yascreen_printxy(s,hx,hy+10,DA|inverse,"%.*s",sx-2,sy<=12?"":"c     - custom script parameter select");
						yascreen_printxy(s,hx,hy+11,DA|inverse,"%.*s",sx-2,sy<=13?"":"r, ^L - refresh screen");
						yascreen_printxy(s,hx,hy+12,DA|inverse,"%.*s",sx-2,sy<=14?"":"q, ^C - quit");
					}
				}
				if (yascreen_update(s)<0) {
					fprintf(stderr,"memory allocation failed during screen update\n");
					return 1;
				}
				update=0;
			}
		}

		// use select as timer for refresh in all modes
		FD_ZERO(&r);
		FD_SET(STDIN_FILENO,&r);
		fdmax=STDIN_FILENO;
		if (source==PCAP) {
			if (pcfd>=0) // e.g. on Hurd libpcap does not support events via fd
				FD_SET(pcfd,&r);
			fdmax=mymax(fdmax,pcfd);
		}
		to.tv_sec=0;
		to.tv_usec=500*1000; // at least 2 times per sec
		if (-1!=select(fdmax+1,&r,NULL,NULL,&to)) {
			char c;
			int ch;

			if (!simplest) {
				int64_t now=mytime();

				if (now-lastroll>=500) {
					heartbeat=!heartbeat;
					lastroll=now;
					if (wssx>14) {
						yascreen_putsxy(s,2,wssy-1,DA|((heartbeat*YAS_INVERSE)^inverse),drchars[D_EMPTY]);
						if (yascreen_update(s)<0) {
							fprintf(stderr,"memory allocation failed during screen update\n");
							return 1;
						}
					}
				}
			}

			if (FD_ISSET(STDIN_FILENO,&r)&&sizeof c==read(STDIN_FILENO,&c,sizeof c))
				yascreen_feed(s,c); // pump state machine with bytestream

			while ((ch=yascreen_getch_nowait(s))!=YAS_K_NONE) { // a key can be yielded by the pump above or by timeout (single ESC)
				if (ch=='q'||ch=='Q'||ch==0x03) { // also ^C
					toexit=1;
					break;
				}
				if (ch=='r'||ch=='R'||ch==0x0c) { // also ^L
					winch++;
					redraw=1;
				}
				if (ch==0x1a) { // ^Z
					yascreen_altbuf(s,0);
					yascreen_cursor(s,1);
					yascreen_term_restore(s);
					kill(getpid(),SIGTSTP);
					break;
				}
				if (ch=='n'||ch=='N') {
					redraw=1;
					inverse^=YAS_INVERSE;
					winch++;
				}
				if (ch=='z'||ch=='Z') {
					dta.bts.count=0;
					dta.pks.count=0;
					bcntr=0;
					pcntr=0;
					bcnto=0;
					pcnto=0;
					redraw=1;
					winch++;
				}
				if (ch=='a'||ch=='A') {
					if (drchars!=sp_chars_asci) {
						drchars=sp_chars_asci;
						drlevels_h=levels_h_asci;
						drlevels_v=levels_v_asci;
						winch++;
					}
				}
				if (ch=='u'||ch=='U') {
					if (drchars!=sp_chars_utf8) {
						if (!noutf8) {
							drchars=sp_chars_utf8;
							drlevels_h=levels_h_utf8;
							drlevels_v=levels_v_utf8;
							winch++;
						}
					}
				}
				if (ch=='m'||ch=='M') {
					mode=mode==CLASSIC?HORIZ:CLASSIC;
					winch++;
				}
				if (ch=='l'||ch=='L') {
					legend=!legend;
					winch++;
				}
				if (ch=='i'||ch=='I') {
					history=!history;
					winch++;
				}
				if (ch=='h'||ch=='H'||ch=='?'||ch==YAS_K_F1||ch==YAS_K_ALT('1')) {
					shhelp=!shhelp;
					winch++;
				}
				if (ch=='c'&&strlen(custombin)) { // key valid in other modes only if custombin is there
					if (!cstselect) {
						if (iptselect) {
							iptselect=0;
							ipt_rule_free();
						}
						cstselect=1;
						cst_param_get();
					} else {
						cstselect=0;
						cst_param_free();
					}
					winch++;
				}
				if (ch=='s'||ch=='S'||ch=='6') {
					if (!iptselect) {
						if (cstselect) {
							cstselect=0;
							cst_param_free();
						}
						iptselect=1;
						iptselectt=ch=='6'?IPT6:IPT4;
						ipt_rule_get();
					} else {
						e_source oiptselectt=iptselectt;

						iptselectt=ch=='6'?IPT6:IPT4;
						if (iptselectt==oiptselectt&&(source==PCAP||(chain&&rulenum)||(source==CUST&&strlen(custombin)))) { // we are not changing 4/6
							iptselect=0;
							ipt_rule_free();
						} else // reload rules and continue in iptables select mode
							ipt_rule_get();
					}
					winch++;
				}
				if (iptselect) {
					switch (ch) {
						case YAS_K_UP:
							iptselsel--;
							winch++;
							break;
						case YAS_K_DOWN:
							iptselsel++;
							winch++;
							break;
						case YAS_K_ESC:
							if ((source==CUST||source==PCAP)||(chain&&rulenum)) { // already has valid rule
								iptselect=0;
								ipt_rule_free();
							} else // reload rules and continue in iptables select mode
								ipt_rule_get();
							winch++;
							break;
						case YAS_K_RET: {
							s_ipt *pr=rules;
							int pos=0;

							if (!rules)
								break;

							if (iptselsel<0)
								iptselsel=0;
							if (iptselsel>=iptselcnt)
								iptselsel=iptselcnt-1;
							while (pr) {
								if (pos==iptselsel) {
									// reset state
									dta.bts.count=0;
									dta.pks.count=0;
									bcntr=0;
									pcntr=0;
									bcnto=0;
									pcnto=0;
									redraw=1;

									if (canfreetablechain) {
										if (table)
											free(table);
										if (chain)
											free(chain);
									}
									canfreetablechain=1;
									table=strdup(pr->table);
									chain=strdup(pr->chain);
									rulenum=pr->rulenum;
								}
								pr=pr->next;
								pos++;
							}

							source=iptselectt;
							iptselect=0;
							ipt_rule_free();
							winch++;
							break;
						}
					}
				}
				if (cstselect) {
					switch (ch) {
						case YAS_K_UP:
							cstselsel--;
							winch++;
							break;
						case YAS_K_DOWN:
							cstselsel++;
							winch++;
							break;
						case YAS_K_ESC:
							if ((source==CUST||source==PCAP)||(chain&&rulenum)) { // already has valid rule
								cstselect=0;
								cst_param_free();
							} else // reload rules and continue in custom script parameter select mode
								cst_param_get();
							winch++;
							break;
						case YAS_K_RET: {
							s_cst *pr=binpa;
							int pos=0;

							if (!binpa)
								break;

							if (cstselsel<0)
								cstselsel=0;
							if (cstselsel>=cstselcnt)
								cstselsel=cstselcnt-1;
							while (pr) {
								if (pos==cstselsel) {
									// reset state
									dta.bts.count=0;
									dta.pks.count=0;
									bcntr=0;
									pcntr=0;
									bcnto=0;
									pcnto=0;
									redraw=1;

									if (canfreeparam)
										if (customparam)
											free(customparam);
									canfreeparam=1;
									customparam=strdup(pr->id);
								}
								pr=pr->next;
								pos++;
							}

							source=CUST;
							cstselect=0;
							cst_param_free();
							winch++;
							break;
						}
					}
				}
			}
			if (pcfd<0||(source==PCAP&&FD_ISSET(pcfd,&r)))
				pcap_dispatch(pc,10000,pc_cb,NULL);
		}
		if (toexit)
			break;
	}
	if (!simplest) {
		yascreen_clear(s);
		yascreen_altbuf(s,0);
		yascreen_cursor(s,1);
		yascreen_term_restore(s);
		yascreen_free(s);
	}
	return 0;
} // }}}
