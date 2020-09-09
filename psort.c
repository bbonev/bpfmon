// $Id: psort.c,v 1.15 2020/08/12 19:54:31 bbonev Exp $

// {{{ includes
#define _GNU_SOURCE

#include <pcap.h>
#include <time.h>
#include <ctype.h>
#include <stdio.h>
#include <wchar.h>
#include <locale.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <yascreen.h>
// }}}

// {{{ definitions
#define DATACNT 512
#define PRCNT 30

#define HELPX 41
#define HELPY 9

#define DA 0

#define mymax(a,b) (((a)>(b))?(a):(b))
#define mymin(a,b) (((a)<(b))?(a):(b))

static char *sp_chars_utf8[]={
	"─","┃","…","━","‧",
	"(",")",
	"•",
};
static char *sp_chars_asci[]={
	"_","|",">","=",".",
	"(",")",
	"*",
};
typedef enum {
	D_M,D_I,D_ELL,D_EQ,D_D,
	D_BO,D_BC,
	D_EMPTY,
} e_drc;

typedef struct {
	uint64_t ci;
	uint64_t co;
	uint64_t bi;
	uint64_t bo;
	time_t ts;
} s_da;

typedef union _s_pg {
	union _s_pg *nx[256];
	s_da *da[256];
} s_pg;

typedef struct {
	uint32_t ip;
	uint64_t c;
} s_ip;

typedef struct {
	uint16_t ptype;
	uint16_t arphrd;
	uint16_t llal;
	uint8_t lla[8];
	uint16_t proto;
} s_sll;

typedef struct {
	uint8_t edst[6];
	uint8_t esrc[6];
	uint16_t etype1;
	uint16_t etype2;
	uint16_t etype3;
} s_ehdr;

typedef struct {
	uint8_t vhl;
	uint8_t tos;
	uint16_t hl;
	uint16_t id;
	uint16_t off;
	uint8_t ttl;
	uint8_t proto;
	uint16_t cks;
	uint32_t src;
	uint32_t dst;
} s_ip_hdr;

typedef struct {
	uint16_t sp;
	uint16_t dp;
} s_tu_hdr;

// }}}

// {{{ globals
static yascreen *s;
static char **drchars=sp_chars_utf8; // frame draw characters

static int heartbeat=0;
static char ver[]="$Revision: 1.15 $";
static int winch=1; // signal for window size change event or other redraw request
static int redraw=0; // signal to perform full redraw
static int update=0; // signal for timeout that require data refresh
static int toexit=0; // signal for quit request
static int shhelp=0; // show help window with active keys

static enum {M_TEXT,M_SCR} mode=M_SCR;

static char *dev=NULL; // device to dump
static char *flt=NULL; // pcap filter code
static int noutf8=0; // flag if the undelying os cannot support utf8
static int inverse=0; // XORed with YAS_INVERSE

// libpcap stuff
static struct pcap *pc; // libpcap structure
static struct bpf_program fp; // compiled filter program

static s_pg *map=NULL; // map ip to counters
static uint64_t mem=0; // track used memory
static uint64_t pgs=0; // track used pages
static uint64_t ips=0; // track used ips

// print buffer
static s_ip bypkti[DATACNT];
static s_ip bypkto[DATACNT];
static s_ip bybtsi[DATACNT];
static s_ip bybtso[DATACNT];
static int cntpkti;
static int cntpkto;
static int cntbtsi;
static int cntbtso;
// }}}

static inline void psort_help(const char *ver,const char *me) { // {{{
	printf(
		"psort %s\n"
		"Usage: %s [-autgnNh] -i <device> -f '<bpf_filter_code>'\n"
		"\t-a  -  use ASCII drawing chars\n"
		"\t-u  -  use UTF-8 drawing chars (default)\n"
		"\t-t  -  use no interface (simple text output)\n"
		"\t-g  -  use terminal interface\n"
		"\t-n  -  show interface white on black (default)\n"
		"\t-N  -  show interface inverse (black on white)\n"
		"\t-h  -  display this help and exit\n"
		"\n"
		"Keys used in full-screen mode:\n"
		"\th, ?    - toggle help screen\n"
		"\ta       - switch to ASCII drawing chars\n"
		"\tu       - switch to UTF-8 drawing chars\n"
		"\tr, ^L   - refresh screen\n"
		"\tq, ^C   - quit\n"
		"Examples:\n"
		"\tpsort -i eth0 -f 'arp or ip'      - count arp or ip packets on eth0\n"
		"\tpsort -i any -f ''                - count all packets on all interfaces\n"
		"See tcpdump's manual for full description of BPF filter-code\n"
		"Remember to put the filter code in quotes.\n"
		"\n"
		,ver,me);
} // }}}

static inline int64_t mytime() { // {{{
	struct timespec ts;
	int64_t res;

	clock_gettime(CLOCK_MONOTONIC,&ts);
	res=ts.tv_sec*1000;
	res+=ts.tv_nsec/1000000;
	return res;
} // }}}

static inline void swin(char *cap,int x,int y,int sx,int sy) { // {{{
	int i,j;

	if (sy>=1) {
		int capcnt=0;

		if (sx>=1)
			yascreen_putsxy(s,x-1,y-1,DA|inverse,drchars[D_M]);
		if (sx>4&&cap[0]) {
			wchar_t *ws=calloc(sizeof *ws,strlen(cap)+1),tws[2];
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

static void sigwinch(int sign __attribute__((unused))) { // {{{
	winch++;
} // }}}

static inline void hexdump(const uint8_t *buf,int len) { // {{{
	int i;
	char hexb[16*3+2]="";
	char ascb[16+2]="";

	for (i=0;i<len;i++) {
		if (i%16)
			strcat(hexb," ");
		sprintf(hexb+strlen(hexb),"%02x",buf[i]);
		sprintf(ascb+strlen(ascb),"%c",isprint(buf[i])?buf[i]:'.');
		if ((i%16)==15) {
			printf("%s %s\n",hexb,ascb);
			hexb[0]=ascb[0]=0;
		}
	}
	if (strlen(ascb)) {
		printf("%-47s %s\n",hexb,ascb);
	}
} // }}}

static inline char *ip2s(uint32_t ip) { // {{{
	static char s[50];

	sprintf(s,"%d.%d.%d.%d",(ip>>24)&0xff,(ip>>16)&0xff,(ip>>8)&0xff,ip&0xff);

	return s;
} // }}}

static inline void mypr(const char *fmtstr,...) {  // {{{
	va_list ap;
	char *ns;
	int size;

	if (mode==M_SCR) // disable debug print
		return;

	va_start(ap,fmtstr);
	size=vasprintf(&ns,fmtstr,ap);
	va_end(ap);
	if (size==-1)
		return;
	printf("%s",ns);
	free(ns);
} // }}}

static inline s_da *allocip(uint32_t ip) { // {{{
	uint8_t i,j,k,m;

	if (!map) {
		map=calloc(1,sizeof *map);
		if (!map)
			return NULL;
		mem+=sizeof *map;
		pgs++;
	}
	i=(ip>>24)&0xff;
	if (!map->nx[i]) {
		map->nx[i]=calloc(1,sizeof *map);
		if (!map->nx[i])
			return NULL;
		mem+=sizeof *map;
		pgs++;
	}
	j=(ip>>16)&0xff;
	if (!map->nx[i]->nx[j]) {
		map->nx[i]->nx[j]=calloc(1,sizeof *map);
		if (!map->nx[i]->nx[j])
			return NULL;
		mem+=sizeof *map;
		pgs++;
	}
	k=(ip>>8)&0xff;
	if (!map->nx[i]->nx[j]->nx[k]) {
		map->nx[i]->nx[j]->nx[k]=calloc(1,sizeof *map);
		if (!map->nx[i]->nx[j]->nx[k])
			return NULL;
		mem+=sizeof *map;
		pgs++;
	}
	m=ip&0xff;
	if (!map->nx[i]->nx[j]->nx[k]->da[m]) {
		map->nx[i]->nx[j]->nx[k]->da[m]=calloc(1,sizeof(s_da));
		if (!map->nx[i]->nx[j]->nx[k]->da[m])
			return NULL;
		mem+=sizeof(s_da);
		ips++;
	}
	return map->nx[i]->nx[j]->nx[k]->da[m];
} // }}}

static inline void freemap(void) { // {{{
	int i,j,k,m;

	if (map) {
		for (i=0;i<256;i++)
			if (map->nx[i]) {
				for (j=0;j<256;j++)
					if (map->nx[i]->nx[j]) {
						for (k=0;k<256;k++)
							if (map->nx[i]->nx[j]->nx[k]) {
								for (m=0;m<256;m++)
									if (map->nx[i]->nx[j]->nx[k]->da[m])
										free(map->nx[i]->nx[j]->nx[k]->da[m]);
								free(map->nx[i]->nx[j]->nx[k]);
							}
						free(map->nx[i]->nx[j]);
					}
				free(map->nx[i]);
			}
		free(map);
	}
	map=NULL;
	mem=0;
	pgs=0;
	ips=0;
} // }}}

static inline void handpkt(uint16_t len,uint32_t si,uint16_t sp,uint32_t di,uint16_t dp) { // {{{
	s_da *psd=allocip(si);
	s_da *pdd=allocip(di);

	if (psd) {
		if (!psd->ts)
			psd->ts=time(NULL);
		psd->ci++;
		psd->bi+=len;
	}
	if (pdd) {
		if (!pdd->ts)
			pdd->ts=time(NULL);
		pdd->co++;
		pdd->bo+=len;
	}
	mypr("%08x:%04x %08x:%04x ",si,sp,di,dp);
	mypr("%s",ip2s(si));
	mypr(":%d %s:%d\n",sp,ip2s(di),dp);
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

static inline void drawtxt(int c1,int c2,int c3,int c4,s_ip *i1,s_ip *i2,s_ip *i3,s_ip *i4) { // {{{
	char xps[50];
	int i;

	printf("%15s %8s  ","from ip","pps");
	printf("%15s %8s  ","to ip","pps");
	printf("%15s %8s  ","from ip","bps");
	printf("%15s %8s\n","to ip","bps");
	for (i=0;i<PRCNT;i++) {
		sprintsi(xps,sizeof xps,i1[i].c);
		if (i<c1)
			printf("%2d: %15s %8s  ",i,ip2s(i1[i].ip),xps);
		else
			printf("%2d: %15s %8s  ",i,"","");

		sprintsi(xps,sizeof xps,i2[i].c);
		if (i<c2)
			printf("%15s %8s  ",ip2s(i2[i].ip),xps);
		else
			printf("%15s %8s  ","","");

		sprintsi(xps,sizeof xps,i3[i].c);
		if (i<c3)
			printf("%15s %8s  ",ip2s(i3[i].ip),xps);
		else
			printf("%15s %8s  ","","");

		sprintsi(xps,sizeof xps,i4[i].c);
		if (i<c4)
			printf("%15s %8s\n",ip2s(i4[i].ip),xps);
		else
			printf("%15s %8s\n","","");

		if (i>=c1&&i>=c2&&i>=c3&&i>=c4) // do not print empty lines
			break;
	}
} // }}}

static inline void drawscr(int x,int y,int sx,int sy) { // {{{
	char buf[200]; // enough to handle one line
	char xps[50]; // ip2s uses static buffer...
	int rem=0;
	int i,p;

	if (sy>=1) {
		sprintf(buf,"    %15s %8s  %15s %8s  %15s %8s  %15s %8s","from ip","pps","to ip","pps","from ip","bps","to ip","bps");
		rem=(int)strlen(buf)<sx?(sx-strlen(buf))/2:0;
		yascreen_printxy(s,x+rem,y,DA|(inverse^YAS_INVERSE),"%.*s",sx,buf);
	}

	for (p=y+1;p<y+sy;p++) {
		i=p-y;
		if (i>=DATACNT) // do not go beyond data end
			break;
		sprintsi(xps,sizeof xps,bypkti[i].c);
		if (i<cntpkti)
			sprintf(buf,"%*s%2d: %15s %8s  ",rem,"",i,ip2s(bypkti[i].ip),xps);
		else
			sprintf(buf,"%*s%2d: %15s %8s  ",rem,"",i,"","");

		sprintsi(xps,sizeof xps,bypkto[i].c);
		if (i<cntpkto)
			sprintf(buf+strlen(buf),"%15s %8s  ",ip2s(bypkto[i].ip),xps);
		else
			sprintf(buf+strlen(buf),"%15s %8s  ","","");

		sprintsi(xps,sizeof xps,bybtsi[i].c);
		if (i<cntbtsi)
			sprintf(buf+strlen(buf),"%15s %8s  ",ip2s(bybtsi[i].ip),xps);
		else
			sprintf(buf+strlen(buf),"%15s %8s  ","","");

		sprintsi(xps,sizeof xps,bybtso[i].c);
		if (i<cntbtso)
			sprintf(buf+strlen(buf),"%15s %8s\n",ip2s(bybtso[i].ip),xps);
		else
			sprintf(buf+strlen(buf),"%15s %8s\n","","");
		if (i>=cntpkti&&i>=cntpkto&&i>=cntbtsi&&i>=cntbtso) // do not print empty numbers
			strcpy(buf,"");
		yascreen_printxy(s,x,p,DA|inverse,"%.*s",sx,buf);
	}
} // }}}

static inline void inssorted(int *cnt,s_ip *ips,uint64_t c,uint32_t ip) { // {{{
	int p=-1;
	int i;

	for (i=0;i<*cnt;i++)
		if (c>ips[i].c) {
			p=i;
			break;
		}
	if (*cnt<DATACNT&&p==-1) {
		ips[*cnt].ip=ip;
		ips[*cnt].c=c;
		(*cnt)++;
		return;
	}
	if (p==-1) // all are bigger, ignore
		return;
	if (*cnt<DATACNT)
		(*cnt)++;
	for (i=*cnt-2;i>=p;i--)
		ips[i+1]=ips[i];
	ips[p].ip=ip;
	ips[p].c=c;
} // }}}

static inline void display(void) { // {{{
	time_t now=time(NULL);
	int i,j,k,m;

	memset(bypkti,0,sizeof bypkti);
	memset(bypkto,0,sizeof bypkto);
	memset(bybtsi,0,sizeof bybtsi);
	memset(bybtso,0,sizeof bybtso);
	cntpkti=cntpkto=cntbtsi=cntbtso=0;

	if (map)
		for (i=0;i<256;i++)
			if (map->nx[i])
				for (j=0;j<256;j++)
					if (map->nx[i]->nx[j])
						for (k=0;k<256;k++)
							if (map->nx[i]->nx[j]->nx[k])
								for (m=0;m<256;m++)
									if (map->nx[i]->nx[j]->nx[k]->da[m]) {
										uint32_t ip=(i<<24)+(j<<16)+(k<<8)+m;
										uint64_t cis;
										uint64_t cos;
										uint64_t bis;
										uint64_t bos;

										if (now>map->nx[i]->nx[j]->nx[k]->da[m]->ts) {
											cis=map->nx[i]->nx[j]->nx[k]->da[m]->ci/(now-map->nx[i]->nx[j]->nx[k]->da[m]->ts);
											cos=map->nx[i]->nx[j]->nx[k]->da[m]->co/(now-map->nx[i]->nx[j]->nx[k]->da[m]->ts);
											bis=map->nx[i]->nx[j]->nx[k]->da[m]->bi/(now-map->nx[i]->nx[j]->nx[k]->da[m]->ts);
											bos=map->nx[i]->nx[j]->nx[k]->da[m]->bo/(now-map->nx[i]->nx[j]->nx[k]->da[m]->ts);
										} else {
											cis=0;
											cos=0;
											bis=0;
											bos=0;
										}

										inssorted(&cntpkti,bypkti,cis,ip);
										inssorted(&cntpkto,bypkto,cos,ip);
										inssorted(&cntbtsi,bybtsi,bis,ip);
										inssorted(&cntbtso,bybtso,bos,ip);
									}

	if (mode==M_TEXT)
		drawtxt(cntpkti,cntpkto,cntbtsi,cntbtso,bypkti,bypkto,bybtsi,bybtso);
} // }}}

static void pc_cb(unsigned char *user __attribute__((unused)),const struct pcap_pkthdr *h,const u_char *bytes) { // {{{
	int dl=pcap_datalink(pc);
	int issll=0;

	if (dl==DLT_LINUX_SLL) {
		s_sll *s=(s_sll *)bytes;

		if (ntohs(s->arphrd)==1) {
			s_ehdr *e;

			bytes+=sizeof *s;
			bytes-=6+6+2;
			e=(s_ehdr *)bytes;
			e->etype1=htons(0x800);
			dl=DLT_EN10MB;
			mypr("SLL, ");
			issll=1;
			goto nextproto;
		}
		mypr("ptype: %04x arphrd %04x lall %d proto %04x\n",ntohs(s->ptype),ntohs(s->arphrd),ntohs(s->llal),ntohs(s->proto));
		return;
	}
nextproto:
	if (dl==DLT_EN10MB) {
		s_ehdr *e=(s_ehdr *)bytes;
		s_ip_hdr *i=NULL;
		s_tu_hdr *t=NULL;

		switch (ntohs(e->etype1)) {
			case 0x800: // ip, plain
				mypr("eth-ip, ");
				i=(s_ip_hdr *)(bytes+6+6+2);
				break;
			case 0x8100: // ip, tagged
				if (ntohs(e->etype3)==0x800) {
					mypr("eth-vlan-ip(%d), ",ntohs(e->etype2)&0xfff);
					i=(s_ip_hdr *)(bytes+6+6+4+2);
				}
				break;
			default:
				mypr("unknown eth-type: %04x\n",ntohs(e->etype1));
		}
		if (i) {
			uint16_t sp=0,dp=0;
			char sa[50],da[50];
			uint32_t si,di;
			int ihl;

			si=ntohl(i->src);
			di=ntohl(i->dst);
			strcpy(sa,ip2s(si));
			strcpy(da,ip2s(di));

			mypr("%s to %s, ",sa,da);

			switch (i->proto) {
				case 6: // tcp
				case 17: // udp
					ihl=i->vhl&0xf;
					if (ihl<5) {
						mypr("invalid ip hdr len %d\n",ihl);
						return;
					}
					ihl*=4;
					t=(s_tu_hdr *)(((uint8_t *)i)+ihl);
					mypr("%s %d to %d\n",i->proto==6?"TCP":"UDP",ntohs(t->sp),ntohs(t->dp));
					sp=ntohs(t->sp);
					dp=ntohs(t->dp);
					break;
				default:
					mypr("proto %02x\n",i->proto);
					if (issll&&mode==M_TEXT)
						hexdump(bytes,h->len);
			}
			handpkt(h->len,si,sp,di,dp);
		}
		return;
	}
	mypr("cannot handle packet type %d (expect %d)\n\n",dl,DLT_EN10MB);
} // }}}

int main(int ac,char **av) { // {{{
	//int gsx=0,gsy=0,gx=1,g1y=2,g2y=2;
	char ebuf[PCAP_ERRBUF_SIZE];
	int64_t lastroll=0;
	struct timeval to;
	int wssx=0,wssy=0;
	time_t lastt=0;
	char ts[100];
	char *p,*q;
	int fdmax;
	//int tslen;
	fd_set r;
	int pcfd;
	int i;

	memset(&r,0,sizeof r); // make clang static analyzer happier (llvm bug #8920)

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
		psort_help(ver,av[0]);
		return 0;
	}

	for (i=1;i<ac;i++) {
		if (av[i][0]!='-') {
			fprintf(stderr,"unrecognized parameter: %s\n",av[i]);
			return 1;
		} else {
			unsigned j;

			for (j=1;j<strlen(av[i]);j++)
				switch (av[i][j]) {
					case 'h':
						goto helpandexit;
					case 'a':
						drchars=sp_chars_asci;
						break;
					case 'u': // no need to check for noutf8, because it is set below and will override this
						drchars=sp_chars_utf8;
						break;
					case 't':
						mode=M_TEXT;
						break;
					case 'g':
						mode=M_SCR;
						break;
					case 'n':
						inverse=0;
						break;
					case 'N':
						inverse=YAS_INVERSE;
						break;
					case 'i': // interface
						if (i+1>=ac||j!=strlen(av[i])-1) {
							fprintf(stderr,"option 'i' requires an argument\n");
							return 1;
						}
						dev=av[i+1];
						i++;
						goto nextarg;
					case 'f': // filter code
						if (i+1>=ac||j!=strlen(av[i])-1) {
							fprintf(stderr,"option 'f' requires an argument\n");
							return 1;
						}
						flt=av[i+1];
						i++;
						goto nextarg;
					default:
						fprintf(stderr,"unrecognized option '%c'\n",av[i][j]);
						return 1;
				}
		}
	nextarg:;
	}
	if (!dev) {
		fprintf(stderr,"device is not specified\n");
		return 1;
	}
	if (!flt) {
		fprintf(stderr,"bpf filter code is not specified\n");
		return 1;
	}
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

	if (mode==M_SCR) {
		signal(SIGWINCH,sigwinch);
		if (!setlocale(LC_CTYPE,"C.UTF-8")) { // cannot set utf8 locale, disable utf mode and force to ascii
			drchars=sp_chars_asci;
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

	snprintf(ts,sizeof ts,"psort %s",ver);
	//tslen=strlen(ts);

	for (;;) {
		int64_t now=mytime();

		if (!lastt||lastt+1000<now) { // display results every second
			if (!lastt)
				lastt=now;
			else
				lastt+=1000;
			display();
			update=1; // force redraw
		}
		if (mode==M_SCR) {
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
				//gx=1;
				//gsx=wssx-gx+1;
				//gsy=(wssy-3)/2;
				//g2y=gsy+3;
				swin(ts,1,1,wssx,wssy);
				if (wssx>14) {
					yascreen_putsxy(s,1,wssy-1,DA|inverse,drchars[D_BO]);
					yascreen_putsxy(s,2,wssy-1,DA|((heartbeat*YAS_INVERSE)^inverse),drchars[D_EMPTY]);
					yascreen_putsxy(s,3,wssy-1,DA|inverse,drchars[D_BC]);
					yascreen_putsxy(s,4,wssy-1,DA|inverse," q=quit ");
				}
				if (wssx>14+9+6)
					yascreen_printxy(s,wssx-9-6-1,wssy-1,DA|inverse," size: %dx%d ",wssx,wssy);
				winch--;
				update=1;
			}
			if (update) {
				drawscr(0,1,wssx,wssy-2);
				if (shhelp&&wssx>=4&&wssy>=4) { // help screens
					int hx=mymax(2,(wssx-HELPX)/2+1);
					int hy=mymax(2,(wssy-HELPY)/2+1);
					int sx=mymin(wssx-2,HELPX);
					int sy=mymin(wssy-2,HELPY);

					swin("help",hx,hy,sx,sy);
					yascreen_printxy(s,hx,hy+0,DA|inverse,"%.*s",sx-2,sy<=2?"":"h,?,F1 - toggle help screen");
					yascreen_printxy(s,hx,hy+1,DA|inverse,"%.*s",sx-2,sy<=3?"":"a      - switch to ASCII drawing chars");
					yascreen_printxy(s,hx,hy+2,DA|inverse,"%.*s",sx-2,sy<=4?"":"u      - switch to UTF-8 drawing chars");
					yascreen_printxy(s,hx,hy+3,DA|inverse,"%.*s",sx-2,sy<=5?"":"n      - toggle inverse mode");
					yascreen_printxy(s,hx,hy+4,DA|inverse,"%.*s",sx-2,sy<=6?"":"z      - zero history and restart");
					yascreen_printxy(s,hx,hy+5,DA|inverse,"%.*s",sx-2,sy<=7?"":"r,^L   - refresh screen");
					yascreen_printxy(s,hx,hy+6,DA|inverse,"%.*s",sx-2,sy<=8?"":"q,^C   - quit");
				}
				if (wssx>14+9+6) {
					char mems[50];
					char info[200];

					sprintsi(mems,sizeof mems,mem);
					sprintf(info," ip %"PRIu64" pg %"PRIu64" %8s ",ips,pgs,mems);
					if ((unsigned)wssx>14+3+strlen(info))
						yascreen_printxy(s,wssx-1-strlen(info),0,DA|(inverse^YAS_INVERSE),"%s",info);
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
		FD_SET(pcfd,&r);
		fdmax=mymax(fdmax,pcfd);
		to.tv_sec=0;
		to.tv_usec=500*1000; // at least 2 times per sec
		if (-1!=select(fdmax+1,&r,NULL,NULL,&to)) {
			char c;
			int ch;

			if (mode==M_SCR) {
				int64_t now=mytime();

				if (now-lastroll>100) {
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

			while ((ch=yascreen_getch_nowait(s))!=-1) { // a key can be yielded by the pump above or by timeout (single ESC)
				if (ch=='q'||ch=='Q'||ch==0x03) { // also ^C
					toexit=1;
					break;
				}
				if (ch=='r'||ch=='R'||ch==0x0c) { // also ^L
					winch++;
					redraw=1;
				}
				if (ch=='n'||ch=='N') {
					redraw=1;
					inverse^=YAS_INVERSE;
					winch++;
				}
				if (ch=='z'||ch=='Z') {
					freemap();
					redraw=1;
					winch++;
				}
				if (ch=='a'||ch=='A') {
					if (drchars!=sp_chars_asci) {
						drchars=sp_chars_asci;
						winch++;
					}
				}
				if (ch=='u'||ch=='U') {
					if (drchars!=sp_chars_utf8) {
						if (!noutf8) {
							drchars=sp_chars_utf8;
							winch++;
						}
					}
				}
				if (ch=='h'||ch=='H'||ch=='?'||ch==YAS_K_F1||ch==YAS_K_ALT('1')) {
					shhelp=!shhelp;
					winch++;
				}
			}
			if (FD_ISSET(pcfd,&r))
				pcap_dispatch(pc,10000,pc_cb,NULL);
		}
		if (toexit)
			break;
	}

	if (mode==M_SCR) {
		yascreen_clear(s);
		yascreen_altbuf(s,0);
		yascreen_cursor(s,1);
		yascreen_term_restore(s);
		yascreen_free(s);
	}
	return 0;
} // }}}
