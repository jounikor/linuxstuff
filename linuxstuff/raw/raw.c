/* Copyright (C) 1991-2001, 2003, 2004, 2006, 2007
   Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.


   Author: v0.1 Jouni Korhonen (jouni.korhonen@nsn.com) in 2010 for the
                WiBrA project.
           v0.2 Jouni - added MTU & SLLA options
 */


#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>		// exit()
#include <assert.h>

// address conversion stuff
#include <arpa/inet.h>

// sockets stuff
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/ip6.h>	// ipv6 header
#include <netinet/icmp6.h>	// for nd..

// interfaces
#include <net/if.h>

#include <linux/sockios.h>

// commandline parsing
#include <getopt.h>

// own stuff
#include "raw.h"

//
//

struct ra_config racfg = {
  .debug = 0,
  .interface = NULL,
  .mtu = 0,
  .sllao = NULL,
  .M = 0,
  .O = 0,
  .hoplimit = 64,
  .lifetime = 3*600,        // 3*MaxRtrAdvInterval.. a bit lame as
                                   // we do not know our MaxRtrAdvInterval ;)
  .reachable_time = 12*1000,       // 12 secs
  .retrans_time = 3*1000,          // 3 secs
  .router_preference = ND_RA_FLAG_PRF_MED,
  .numroutes = 0,
  .numprefixes = 0,
};


/*
 * uppper layer checksum calculation
 * return the checksum in network byte order
 */

static u_int16_t chksum( struct in6_addr* src, struct in6_addr* dst,
		  void* data, int len, int nxt ) {

	struct pseudo6 ip6hdr;
	u_int32_t csum = 0;
	int n;
	u_int16_t* pkt;
	u_int8_t* p8;

	/* make sure the pseudo header has everything
	   in network byte order..
           we should avoid copying actually.. linux kernel has
	   much nicer way of calculating the checksum over the
	   pseudoheader.
	*/

	ip6hdr.ulp_len = htons(len);
	memcpy(&ip6hdr.src,src,16);
	memcpy(&ip6hdr.dst,dst,16);
	ip6hdr.nxt = nxt;

	pkt = (u_int16_t*)&ip6hdr;
	p8 = (u_int8_t*)&ip6hdr;

	if (racfg.debug) {
	  printf("Pseudo header..\n");

	  for (n = 0; n < sizeof(ip6hdr); n += 4) {
	    printf("%02x %02x %02x %02x\n",p8[n],p8[n+1],p8[n+2],p8[n+3]);
	  }
	}

	/* this checksum calculation is not the fastest one..
	    we know that header is always 16 bits aligned..
	*/

	n = sizeof(ip6hdr);

	while (n > 1) {
		csum += *pkt++;
		n -= 2;
	}

	/* next the payload..  */

	pkt = data;

	while (len > 1) {
		csum += *pkt++;
		len -= 2;
	}

	if (len) {
		csum += *(u_int8_t*)pkt;
	}

	/* htons takes care of endianess.. */
	return htons(~((csum >> 16) + (csum & 0xffff))); 
}

/*
 * returns prefix length. -1 if not a valif IPv6 address/prefix
 */
static int parse_prefix( char* s, struct in6_addr* p ) {
  char *c = strchr(s,'/');
  int plen;

  if (c == NULL) {
    return -1;
  }
  
  *c++ = '\0';
  plen = strtol(c,NULL,10);

  if (errno == EINVAL || plen > 128 || plen < 0) {
    return -1;
  }
  if (inet_pton(AF_INET6,s,&p->s6_addr) <= 0) {
    return -1;
  }

  return plen;
}

static int parse_route_list( char* s ) {
  char* w;           // our found string
  char* p;           // our subphase
  char* ctx1;
  char* ctx2;
  int n = 0;         // num of found routes
  int i;

  for (w = strtok_r(s,",",&ctx1); w && n < RIOPT_MAX; w = strtok_r(NULL,",",&ctx1)) {
    if (racfg.debug) {
      printf("Found more specific route bundle: %s ->\n",w);
    }

    if (p = strtok_r(w,";",&ctx2)) {
      if ((racfg.routes[n].prefixlen = 
	   parse_prefix(p,&racfg.routes[n].prefix)) < 0) {
	return -1;
      }

#if 1
      i = (racfg.routes[n].prefixlen + 7) >> 3;

      while (i < 16) {
	if (racfg.routes[n].prefix.s6_addr[i++]) {
	  /* RFC 4191 Section 2.3 states that the encoded prefix in the
	     option must have all bits zeroed after the prefix length
	     bits of the prefix data.
	   */

	  printf("**Warning: Prefix %s/%d violates RFC 4191 Section 2.3\n",
		 s,racfg.routes[n].prefixlen);
	  break;
	}
      }
#endif
    } else {
      return -1;
    }

    if (p = strtok_r(NULL,";",&ctx2)) {
      racfg.routes[n].lifetime = strtoul(p,NULL,10);
      if (errno == EINVAL) {
	return -1;
      }
    } else {
      return -1;
    }

    if (p = strtok_r(NULL,";",&ctx2)) {
      if (!strcmp(p,"low")) {
	racfg.routes[n].prf = RIOPT_PRF_LOW;
      } else if (!strcmp(p,"med")) {
	racfg.routes[n].prf = RIOPT_PRF_MED;
      } else if (!strcmp(p,"hgh")) {
	racfg.routes[n].prf = RIOPT_PRF_HGH;
      } else if (!strcmp(p,"")) {
	/* empty means the default.. */
	racfg.routes[n].prf = RIOPT_PRF_MED;
      } else {
	return -1;
      }
    } else {
      return -1;
    }

    n++;
  }
  if (racfg.debug) {
    printf("Total more specific routes: %d\n",n); 
  }

  return n;
}

/*
 * Parse list of prefixes for PIO
 *
 * The format is one or more comman separated entries of
 * "LA;prefix/len;validlifetime;preflifetime"
 * The absence of L or A are interpreted as 0..
 * The absense of lifetimes are interpreted as 30 and 7 days.. 
 */

static int parse_prefix_list( char* s ) {
  char* w;           // our found string
  char* p;           // our subphase
  char* ctx1;
  char* ctx2;
  int n = 0;         // num of found routes
  int i;

  for (w = strtok_r(s,",",&ctx1); w && n < PIOPT_MAX; w = strtok_r(NULL,",",&ctx1)) {
    if (racfg.debug) {
      printf("Found prefix bundle: %s ->\n",w);
    }
    if (p = strtok_r(w,";",&ctx2)) {
      if (!strcmp(p,"LA")) {
        racfg.pis[n].LA = ND_OPT_PI_FLAG_ONLINK|ND_OPT_PI_FLAG_AUTO;
      } else if (!strcmp(p,"L")) {
        racfg.pis[n].LA = ND_OPT_PI_FLAG_ONLINK;
      } else if (!strcmp(p,"A")) {
        racfg.pis[n].LA = ND_OPT_PI_FLAG_AUTO;
      } else if (!strcmp(p,"AL")) {
        racfg.pis[n].LA = ND_OPT_PI_FLAG_ONLINK|ND_OPT_PI_FLAG_AUTO;
      } else if (!strcmp(p,"-")) {
        racfg.pis[n].LA = 0;
      } else {
	return -1;
      }
    } else {
      return -1;
    }
    if (p = strtok_r(NULL,";",&ctx2)) {
      if ((racfg.pis[n].prefixlen = 
	   parse_prefix(p,&racfg.pis[n].prefix)) < 0) {
	return -1;
      }
    } else {
      return -1;
    }
    if (p = strtok_r(NULL,";",&ctx2)) {
      if (*p == ';') {
	racfg.pis[n].valid_lifetime = 2592000;
      } else {
	racfg.pis[n].valid_lifetime = strtoul(p,NULL,10);
	if (errno == EINVAL) {
	  return -1;
	}
      }
    } else {
      return -1;
    }
    if (p = strtok_r(NULL,";",&ctx2)) {
      if (*p == '\0' || *p == ';'){
	racfg.pis[n].preferred_lifetime = 604800;
      } else {
	racfg.pis[n].preferred_lifetime = strtoul(p,NULL,10);
	if (errno == EINVAL) {
	  return -1;
	}
      }
    } else {
      return -1;
    }
    n++;
  }

  if (racfg.debug) {
    printf("Total prefixes: %d\n",n); 
  }

  return n;
}


//
//

static int addPIO( int pos, u_int8_t* pkt, 
		   int plen, u_int8_t flags,
		u_int32_t vlifetime, u_int32_t plifetime,
		struct in6_addr* prefix ) {

 struct nd_opt_prefix_info* pi = (struct nd_opt_prefix_info*)&pkt[pos];

  if (plifetime > vlifetime) {
    plifetime = vlifetime;
  }

  pi->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
  pi->nd_opt_pi_len = 4;
  pi->nd_opt_pi_prefix_len = plen;
  pi->nd_opt_pi_flags_reserved = flags;
  pi->nd_opt_pi_valid_time = htonl(vlifetime);
  pi->nd_opt_pi_preferred_time = htonl(plifetime);
  pi->nd_opt_pi_reserved2 = 0;
  pi->nd_opt_pi_prefix = *prefix;

  return sizeof(struct nd_opt_prefix_info);
}


static int addRIO( int pos, u_int8_t* pkt,
		int plen, u_int8_t prf,
		u_int32_t lifetime, struct in6_addr* prefix ) {

  struct nd_opt_route_info* ri = (struct nd_opt_route_info*)&pkt[pos];
  int n, m;

  ri->nd_opt_ri_type = 24;   // ND_OPT_ROUTE_INFORMATION;
  ri->nd_opt_ri_prefix_len = plen;
  ri->nd_opt_ri_flags_reserved = prf;
  ri->nd_opt_ri_valid_time = htonl(lifetime);

  n = ((plen + 7) & ~7) >> 3;
  if (n > 0) {
    memcpy(&ri->nd_opt_ri_prefix,&prefix->s6_addr,n);
#if 1
    if (plen < 8 || plen & ~7) {
      ri->nd_opt_ri_prefix.s6_addr[plen >> 3] &= (0xff << (~(plen-1) & 7));
    }

    for (m = n; m < ((n + 7) & ~7); m++) {
      ri->nd_opt_ri_prefix.s6_addr[m] = 0;
    }
  }
#endif
  n = (n + 7) >> 3;
  ri->nd_opt_ri_len = n+1;
  return (n+1) << 3;
} 


static int addMTU( int pos, u_int8_t* pkt, u_int32_t mtu ) {
  struct nd_opt_mtu* m;

  m = (struct nd_opt_mtu*)&pkt[pos];

  m->nd_opt_mtu_type = ND_OPT_MTU;
  m->nd_opt_mtu_len  = 1;
  m->nd_opt_mtu_reserved = 0;
  m->nd_opt_mtu_mtu = htonl(mtu);

  return 8;
}

static int addSLLAO( int pos, u_int8_t* pkt, char* slla ) {
  int n;
  char* w;
  char* ctx;

  struct nd_opt_slla* s = (struct nd_opt_slla*)&pkt[pos];

  s->nd_opt_slla_type = ND_OPT_SOURCE_LINKADDR;

  for (n = 0, w = strtok_r(slla,"-",&ctx); w; w = strtok_r(NULL,"-",&ctx)) {
    s->nd_opt_slla_lla[n++] = strtoul(w,NULL,16);
  }

  n = (n + 7 + 2) & ~7;
  s->nd_opt_slla_len = n >> 3;

  return n;
}


static int buildRA( int pos, u_int8_t* pkt,
		int hlim, u_int8_t flags, int rlifetime,
		u_int32_t rtime, u_int32_t rettime ) {

  struct nd_router_advert* ra;

  ra = (struct nd_router_advert*)&pkt[pos];

  ra->nd_ra_hdr.icmp6_type  = ND_ROUTER_ADVERT;
  ra->nd_ra_hdr.icmp6_code  = 0;
  ra->nd_ra_hdr.icmp6_cksum = 0;  // calculated later..                                                                            
  ra->nd_ra_curhoplimit     = hlim;
  ra->nd_ra_router_lifetime = htonl(rlifetime);
  ra->nd_ra_flags_reserved  = flags;

  if (rtime) {
    ra->nd_ra_reachable = rtime;
  } else {
    ra->nd_ra_reachable = htonl(30000);       // RFC4861 REACHABLE_TIME                                                        
  }
  if (rettime) {
    ra->nd_ra_retransmit = rettime;
  } else {
    ra->nd_ra_retransmit = htonl(1000);        // RFC4861 RETRANS_TIMER  
  }

  return sizeof(struct nd_router_advert);
} 


static struct option longopts[] = {
  {"interface",            required_argument, NULL, 'i'},
  {"help",                 no_argument, NULL, 'h'},
  {"debug",                no_argument, NULL, 'd'},

  {"ra-managed",           no_argument, NULL, 'm'},
  {"ra-other",             no_argument, NULL, 'o'},
  {"ra-hoplimit",          required_argument, NULL, 'H'},
  {"ra-lifetime",          required_argument, NULL, 'f'},
  {"ra-reachable-time",    required_argument, NULL, 'r'},
  {"ra-retrans-time",      required_argument, NULL, 't'},
  {"ra-preference",        required_argument, NULL, 'p'},
  {"add-pio",              required_argument, NULL, 'P'},
  {"add-rio",              required_argument, NULL, 'R'},
  {"add-mtu",              required_argument, NULL, 'M'},
  {"add-sllao",            required_argument, NULL, 'S'}

};

static char shortopts[] = "i:hdmoH:f:r:t:p:P:R:M:S:";

static void usage( void ) {
  fprintf(stderr,"usage: raw [-i iface] [-mo] [-H ra_hoplimit] [-f router_lifetime]\n"
	  "           [-r router_reachable_time] [-t router_retrans_time] [-M mtu]\n"
	  "           [-p (low|med|hgh)] [-S slla] [-P prefix_list] [-R route_info_list]\n"
	  "           [-h] [-d] [source] destination\n\n"
	  "  -i iface\n"
	  "  --interface=iface\n"
	  "      Interface to which the Router Advertisement will be sent. The tool\n"
	  "      allows sending Router Advertisements with a source address that is\n"
	  "      is not bound to the interface.\n\n"
	  //	  "  -x\n"
	  //	  "  --prefix\n"
	  //	  "      Prefix to advertise (e.g. 2001:db8:aaaa::/64). The tool supports\n"
	  //	  "      advertising only one prefix.\n\n"
	  "  -P list\n"
	  "  --ri-list=list\n"
	  "      One or more specific routes in form of comma separated list e.g.:\n"
	  "      LA;2001:db8:a::/64;valid_lifetime;pref_lifetime,...\n"
	  "      '-' instead of LA means no L or A flag set.\n\n"
	  "  -R list\n"
	  "  --ri-list=list\n"
	  "      One or more specific routes in form of comma separated list e.g.:\n"
	  "      2001:db8:a::/64;lifetime;pref,2001:db8:b::/64;lifetime;pref,...\n"
	  "      where pref is 'low', 'med', 'hgh' or ''. Up to 17 routes are supported.\n\n"
	  "  -S lla\n"
	  "  --ra-sllao=lla\n"
	  "      Source Link-Layer address in form of a hexadecimals '34-56-78-9A-BC-DE'.\n\n"
	  "to be completed...\n\n"
	  );
  
  exit(EXIT_FAILURE);
}




//
//
//
int main(int argc, char** argv) {

	char buf[256];
	int s,n;
	struct sockaddr_in6 src, dst;
	struct if_nameindex *ifs;
	struct nd_router_advert* ra;
	struct ip6_hdr* ip6;
	struct ifreq iface;
	struct in6_addr pref;
	int pktlen;
	char opt, *ptr;
	int longidx;
	u_int8_t flgs;
	u_int8_t pkt[1024];	// our max packet size is 1K


	//
	if (argc < 2) {
		usage();
	}

	while ((opt = getopt_long(argc,argv,shortopts,longopts,&longidx)) != -1) {
	  switch (opt) {
	  case '?':
	  case 'h':
	  case ':':
	  default:   // opt == -1
	    usage();
	    break;
	  case 'M':
	    racfg.mtu = strtoul(optarg,NULL,10);
            if (errno == EINVAL) {
              usage();
            }
	    break;
	  case 'S':
	    racfg.sllao = optarg;
	    break;
	  case 'i':
	    racfg.interface = optarg;
	    break;
	  case 'd':
	    racfg.debug = 1;
	    break;
	  case 'm':
	    racfg.M = 1;
	    break;
	  case 'o':
	    racfg.O = 1;
	    break;
	  case 'H':
	    racfg.hoplimit = strtoul(optarg,NULL,10);
	    if (errno == EINVAL) {
	      usage();
	    }
	    if (racfg.hoplimit > 255) {
	      racfg.hoplimit = 255;
	    }
	    break;
	  case 'f':
	    racfg.lifetime = strtoul(optarg,NULL,10);
	    if (errno == EINVAL) {
	      usage();
	    }
	    break;
	  case 'r':
	    racfg.reachable_time = strtoul(optarg,NULL,10);
            if (errno == EINVAL) {
              usage();
            }
            break;
	  case 't':
	    racfg.retrans_time = strtoul(optarg,NULL,10);
            if (errno == EINVAL) {
              usage();
            }
            break;
	  case 'p':
	    if (!strcmp(optarg,"low")) {
	      racfg.router_preference = ND_RA_FLAG_PRF_LOW;
	    } else if (!strcmp(optarg,"med")) {
	      racfg.router_preference = ND_RA_FLAG_PRF_MED;
	    } else if (!strcmp(optarg,"hgh")) {
	      racfg.router_preference = ND_RA_FLAG_PRF_HGH;
	    } else {
              usage();
	    }
	    break;
	  case 'R':
	    racfg.numroutes = parse_route_list(optarg);
	    if (racfg.numroutes < 0) {
	      fprintf(stderr,"**Error: Invalid more specific routes.\n\n");
	      usage();
	    }
	    break;
	  case 'P':
	    racfg.numprefixes = parse_prefix_list(optarg);
	    if (racfg.numprefixes < 0) {
	      fprintf(stderr,"**Error: Invalid prefix.\n\n");
	      usage();
	    }
	    break;
	  }
	}

	//
	//

	argc -= optind;
	argv += optind;

	//
	// prepare our sockaddr_in6 structures

	memset(&src,0,sizeof(src));
	memset(&dst,0,sizeof(dst));
	src.sin6_family=AF_INET6;
	dst.sin6_family=AF_INET6;
 
	if (argc == 0) {
	  usage();
	}
	if (argc > 1) {
	  if (inet_pton(AF_INET6,argv[0],&src.sin6_addr.s6_addr) < 0) {
	    usage();
	  }
	  argv++;
	}
	if (inet_pton(AF_INET6,argv[0],&dst.sin6_addr.s6_addr) < 0) {
	  usage();
	}

	/* open a raw socket for PF_INET6, IPPROTO_RAW..
	 * this ensures we are in charge of building the whole
	 * packet including the IPv6 header and calculation of
	 * transport layer checksums.
	 */

	s = socket(PF_INET6,SOCK_RAW,IPPROTO_RAW);

	if (s < 0) {
		perror("socket(INET6,SOCK_RAW,ICMPV6)");
		exit(EXIT_FAILURE);
	}

	/* we bind this socket to a specific interface. */

	if (racfg.interface) {
	  memset(&iface,0,sizeof(iface));
	  strcpy(iface.ifr_name,racfg.interface);

	  if ((ifs = if_nameindex()) == NULL) {
	    perror("if_nameindex()");
	    close(s);
	    exit(EXIT_FAILURE);
	  }

	  if (setsockopt(s,SOL_SOCKET,SO_BINDTODEVICE,&iface,sizeof(iface)) < 0) {
	    perror("setsockopt(SO_BINDTODEVICE)");
	    close(s);
	    exit(EXIT_FAILURE);
	  }

	  /* set scope_id based on the interface */
	  if ((n = if_nametoindex(racfg.interface)) == 0) {
	    perror("if_nametoindex()");
	  } else {
	    if (IN6_IS_ADDR_UNSPECIFIED(&src.sin6_addr)) {
	      /* we have not defined the source address.. */
	      printf("**Warning: getting source address not supported yet..\n");
	    }
	    if (IN6_IS_ADDR_LINKLOCAL(&src.sin6_addr)) {
	      src.sin6_scope_id = n;
	    }
	    if (racfg.debug) {
	      printf("interface: %s = %d\n",racfg.interface,n);
	    }
	  }

	  if (ifs) {
	    if_freenameindex(ifs);
	  }
	}

	if (IN6_IS_ADDR_LINKLOCAL(&src.sin6_addr)) {
	  printf("**Warning: RA source address is not a link-local, which\n"
		 "           is a violation of RFC 4861 Section 4.2\n");
	}

	/*
	 * Build the IPv6 header..
         */

	ip6 = (struct ip6_hdr*)&pkt[0];

	ip6->ip6_flow = 0;		// flow label =0
	ip6->ip6_vfc |= (6 << 4);	// version 6
	ip6->ip6_plen = 0;		// payload length will be caluculated later
	ip6->ip6_nxt  = IPPROTO_ICMPV6;	// next header is ICMPV6 as ND_RA is ICMP..
	ip6->ip6_hlim = 255;		// hop limit must be 255
	ip6->ip6_src  = src.sin6_addr;	// already in network byte order
	ip6->ip6_dst  = dst.sin6_addr; 	// already in network byte order
	pktlen = sizeof(struct ip6_hdr);

	/* Build the RA & ICMPv6 header.. */

	flgs = racfg.router_preference;
	  
	if (racfg.M) {
	  flgs |= ND_RA_FLAG_MANAGED;
	}
	if (racfg.O) {
	  flgs |= ND_RA_FLAG_OTHER;
	}
	
	pktlen += buildRA(pktlen,pkt,
			  racfg.hoplimit,
			  flgs,
			  racfg.lifetime,
			  racfg.reachable_time,
			  racfg.retrans_time);
	
	/* add the MTU option */

	if (racfg.mtu) {
	  pktlen += addMTU(pktlen,pkt,racfg.mtu);
	}

	/* add the SLLA option */

	if (racfg.sllao) {
	  pktlen += addSLLAO(pktlen,pkt,racfg.sllao);
	}

	/* add the PIO option */
	
	if (racfg.numprefixes > 0) {
	  char b[256];
	  for (n = 0; n < racfg.numprefixes; n++) {
	    flgs = racfg.pis[n].LA;

	    if (racfg.pis[n].prefix.s6_addr[0] & 0xe0 && racfg.pis[n].prefixlen > 64) {
	      printf("**Warning: RA prefix %s and its length violates RFC4291 Section 2.5.1\n",
		     inet_ntop(AF_INET6,&racfg.pis[n].prefix,b,sizeof(b)));
	    }
	    if (flgs &  ND_OPT_PI_FLAG_AUTO && racfg.pis[n].prefixlen != 64) {
	      printf("**Warning: RA A-flag set and prefix length is %d\n",
		     racfg.pis[n].prefixlen);
	    }
	  
	    pktlen += addPIO(pktlen,pkt,
			     racfg.pis[n].prefixlen,
			     flgs,
			     racfg.pis[n].valid_lifetime,
			     racfg.pis[n].preferred_lifetime,
			     &racfg.pis[n].prefix);
	  }
	}
	
	// add route information option..
	if (racfg.numroutes > 0) {
	  for (n = 0; n < racfg.numroutes; n++) {
	    pktlen += addRIO(pktlen,pkt,
			     racfg.routes[n].prefixlen,
			     racfg.routes[n].prf,
			     racfg.routes[n].lifetime,
			     &racfg.routes[n].prefix);
	  }
	}
	
	/*
	 * care to send it..
	 */

	ra = (struct nd_router_advert*)&pkt[sizeof(struct ip6_hdr)];
	ip6->ip6_plen = pktlen-sizeof(struct ip6_hdr);
	ra->nd_ra_cksum = chksum(&src.sin6_addr,&dst.sin6_addr,
				 ra,pktlen-sizeof(struct ip6_hdr),IPPROTO_ICMPV6);
	
	if (sendto(s,pkt,pktlen,0,
		   (struct sockaddr*)&dst,sizeof(dst)) < 0) {
	  perror("sendto()");
	  close(s);
	  exit(EXIT_FAILURE);
	} 
	
	//
	
	if (racfg.debug) {
	  printf("Packet size: %d\n",pktlen);
	  
	  for (n = 0; n < pktlen; n+=4) {
	    printf("%02x %02x %02x %02x\n",pkt[n],pkt[n+1],pkt[n+2],pkt[n+3]);
	  }
	}
	
	
	if (racfg.debug) {
	  printf("\nFabricated IPv6 Router Adverisement sent OK.\n");
	}
	
	//
	close(s);
	return 0;
}
