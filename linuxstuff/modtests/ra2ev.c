#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>


#define MYNL 31
#define MYNLGRP 666


/* Oh my.. it does not get included even if it were supposed to be..
 */

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif




struct mymsg {
  struct nlmsghdr hdr;
  char msg[256];
};



static int open_nl( int grps ) {
  struct sockaddr_nl nl;
  int fd;
  int val;

  fd = socket(PF_NETLINK,SOCK_DGRAM,MYNL);

  if (fd < 0) {
    perror("socket(): ");
    return -1;
  }

  memset(&nl,0,sizeof(nl));
  nl.nl_family = AF_NETLINK;
  nl.nl_pid = getpid();
  nl.nl_groups = 0;  //grps;

  if (bind(fd,(struct sockaddr*)&nl,sizeof(nl)) < 0) {
    perror("bind(): ");
    close(fd);
    return -1;
  }

  /* Next setsockopt() is needed for receiving
   * broadcasts from groups other than 1..
   */

  val = grps;

  if (setsockopt(fd,SOL_NETLINK,NETLINK_ADD_MEMBERSHIP,
		 &val,sizeof(val)) < 0) {

    perror("setsockopt(): ");
    close(fd);
    return -1;
  }


  return fd;
}

static int eventLoop( int fd, char* b, int len ) {
  struct nlmsghdr* nlh;
  int n;

  if ((n = recv(fd,b, len-1, 0)) < 0) {
    fprintf(stderr,"recv() returned 0\n");
    return 0;
  }
  if (n >= 0) {
    nlh = (struct nlmsghdr*)b;

    if (!NLMSG_OK(nlh,n)) {
      fprintf(stderr,"NLMSG_HDR() failed\n");
      return -1;
    }

    b = NLMSG_DATA(nlh);
    fprintf(stderr,"recv() returned %d\n",n);
    fprintf(stderr,"read: %s\n",b);
  }

  return n;
}


static int send2kernel( int fd, char* str ) {
  struct mymsg msg;


  memset(&msg,0,sizeof(msg));
  msg.hdr.nlmsg_len = sizeof(msg);
  msg.hdr.nlmsg_type = RTM_MAX;
  msg.hdr.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
  msg.hdr.nlmsg_pid = getpid();
  msg.hdr.nlmsg_seq = 0;
  strcpy(msg.msg,str);
  return send(fd,&msg,sizeof(msg),MSG_DONTWAIT);



  return 0;
}




int main( int argc, char** argv ) {
  int fd;
  int n;
  char buf[1024];

  if ((fd = open_nl(MYNLGRP)) < 0) {
    fprintf(stderr,"**Error: open_nl() failed\n");
    return 0;
  }


  send2kernel( fd, argv[1] );

  fprintf(stderr,"entering eventloop..\n");

  while ((n = eventLoop(fd,buf,sizeof(buf))) >= 0) {
  }



  close(fd);


  return 0;
}
