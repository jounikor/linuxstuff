#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/socket.h>
#include <linux/netlink.h>


#define NETLINK_MY_UEVENT  31



static int open_nl( int grps ) {
  struct sockaddr_nl nl;
  int fd;


  fd = socket(PF_NETLINK,SOCK_DGRAM,NETLINK_MY_UEVENT);

  if (fd < 0) {
    perror("socket(): ");
    return -1;
  }

  memset(&nl,0,sizeof(nl));
  nl.nl_family = AF_NETLINK;
  nl.nl_pid = getpid();
  nl.nl_groups = grps;

  if (bind(fd,(struct sockaddr*)&nl,sizeof(nl)) < 0) {
    perror("bind(): ");
    close(fd);
    return -1;
  }

  return fd;
}

static int eventLoop( int fd, char* b, int len ) {
  int n;

  if ((n = recv(fd,b, len-1, 0)) < 0) {
    return 0;
  }
  if (n > 0) {
    b[n] = '\0';
  }

  return n;
}




int main( int argc, char** argv ) {
  int fd;
  int n;
  char buf[1024];

  if ((fd = open_nl(atoi(argv[1]))) < 0) {
    fprintf(stderr,"**Error: open_nl() failed\n");
    return 0;
  }

  while (n = eventLoop(fd,buf,sizeof(buf))) {
    printf("read: %s\n",buf);
  }



  close(fd);


  return 0;
}
