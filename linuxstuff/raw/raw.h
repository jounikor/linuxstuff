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

*/


#ifndef __RAW_H_INCLUDED
#define __RAW_H_INCLUDED

#define ND_RA_FLAG_PRF_LOW 0x18
#define ND_RA_FLAG_PRF_MED 0x00
#define ND_RA_FLAG_PRF_HGH 0x08

#define RIOPT_PRF_LOW 0x18
#define RIOPT_PRF_MED 0x00
#define RIOPT_PRF_HGH 0x08

#define RIOPT_MAX 17
#define PIOPT_MAX 16

//

struct pseudo6 {
	struct in6_addr src;
	struct in6_addr dst;
	u_int32_t ulp_len;
	u_int8_t zero[3];
	u_int8_t nxt;		// will be IPPROTO_NONE 
} __attribute__ ((packed)) ;	// make sure gcc does not mess the alignment


struct nd_opt_route_info {
  u_int8_t   nd_opt_ri_type;
  u_int8_t   nd_opt_ri_len;
  u_int8_t   nd_opt_ri_prefix_len;
  u_int8_t   nd_opt_ri_flags_reserved;
  u_int32_t  nd_opt_ri_valid_time;
  struct in6_addr  nd_opt_ri_prefix;
};

struct nd_opt_slla {
  u_int8_t   nd_opt_slla_type;
  u_int8_t   nd_opt_slla_len;
  char nd_opt_slla_lla[0];
};

struct rio {
  u_int8_t prf;
  u_int32_t lifetime;
  int prefixlen;
  struct in6_addr prefix;
};

struct pio {
  u_int8_t LA;
  int prefixlen;
  struct in6_addr prefix;
  u_int32_t valid_lifetime;
  u_int32_t preferred_lifetime;
};


static struct ra_config {
  char addpio;
  char addrio;
  char debug;
  char* interface;
  char M;
  char O;
  //  char L;
  //  char A;
  int hoplimit;
  u_int32_t mtu;             // mtu option
  char* sllao;               // sllao option
  u_int32_t lifetime;
  u_int32_t reachable_time;
  u_int32_t retrans_time;
  u_int8_t router_preference;
  //  u_int32_t pi_valid_lifetime;
  //  u_int32_t pi_preferred_lifetime;
  //  int pi_prefixlen;
  //  struct in6_addr pi_prefix;
  int numroutes;
  struct rio routes[RIOPT_MAX];
  int numprefixes;
  struct pio pis[PIOPT_MAX];
};
#endif
