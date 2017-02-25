#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <net/netlink.h>
#include <net/sock.h>
#include <net/net_namespace.h>

#include <linux/kobject.h>
#include <linux/sysfs.h>

/* purely for experimental use */

#define KNETLINK_RA2UP     31
#define KNETLINK_RA2UP_GRP 666


/*
 *
 */


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jouni Korhonen");


/* My RA2UP Attribute structure.. 
 */

struct ra2attribute {
  struct attribute attr;
  ssize_t (*show)(struct ra2object*, struct ra2attribute*, char* );
  ssize_t (*store)(struct ra2object*, struct ra2attribute*, char*, size_t );
};



/* My RA2UP kobject structure..
 */

struct ra2object {
  struct kobject kobj;
  struct ra2attribute* attr; /* reference to the file associated to this kobject */
  int metric;       /* metric value for IPv4 gateway */
  int lifetime;     /* life time of the prefix */
  int prefixlen;    /* prefix length for IPv4-mapped */
  int preference;   /* prf bits */
  char prefix[64];  /* IPv4-mapped address */
  char gatway[16];  /* IPv4 address */
};

/* This macro find the start of the stuct ra2object when we get a pointer
 * to ra2objects kobj.kobj
 * We actually know it is the start of ra2object structure as well based on
 * how we defined the ra2object structure.. The macro just hides the detail.
 */

#define RA2OBJECT_PTR(x) (struct ra2object*)(x)

/* This macro find the start of the stuct ra2attribute when we get a pointer
 * to ra2attribute's attribute.attr
 * We actually know it is the start of ra2attribute structure as well based on
 * how we defined the ra2attribute structure.. The macro just hides the detail.
 */

#define RA2ATTRIBUTE_PTR(x) (struct ra2attribute*)(x)

/*
 * our generic attribute show/store functions.
 */

static ssize_t ra2_show( struct kobject* k, struct attribute* a, char* b ) {


  return 0;
}

static ssize_t ra2_store( struct kobject* k, struct attribute* a, char* b, size_t l ) {
  return 0;
}


/* Our rs2object release function. It also releases the file associated to this
 * kobject..
 */

static void ra2_release( struct kobject* k ) {
  struct ra2object* ra2obj;

  ra2obj = RA2OBJECT_PTR(k);

  if (ra2obj->attr) {
    sysfs_remove_file(ra2obj,ra2obj->attr);
  }

  kfree(ra2obj);
}





static const struct sysfs_ops ra2_sysfs_ops = {
  .show = ra2_show,
  .store = ra2_store
};




/* max 17 routes in a RA */

static int numroutes = 0;
static struct ra2object* ra2array[17+1] = {0};

/* foo */


static ssize_t ra2_attr_show( struct kobject* k, 
			struct kobj_attribute* a,
			char* b ) {
  struct ra2object* obj = 

  return 0;
}

static ssize_t ra2_attr_store( struct kobject* k,
			       struct kobj_attribute* a,
			       char* b,
			       size_t l ) {


  return 0;
}

/* Allocate and initialize our ra2object
 */




static int fsa;
static int fsb;
static int fsc;
static int fsd;

static ssize_t intshow( struct kobject* k, struct kobj_attribute* a,
			char* b ) {
  int v;

  if (!strcmp(a->attr.name,"fsa")) { v=fsa; }
  else if (!strcmp(a->attr.name,"fsa")) { v=fsb; }
  else if (!strcmp(a->attr.name,"fsa")) { v=fsc; }
  else if (!strcmp(a->attr.name,"fsa")) { v=fsd; }
  else { v=0; }

  sprintf(b,"%d",v);
  printk(KERN_ALERT "intshow(%s): %s=%d\n",a->attr.name,b,v);
  return 0;
}

static ssize_t intstore( struct kobject* k, struct kobj_attribute* a,
			const char* b, size_t blen ) {
  int* v;
  int foo=-1;

  if (!strcmp(a->attr.name,"fsa")) { v=&fsa; }
  else if (!strcmp(a->attr.name,"fsa")) { v=&fsb; }
  else if (!strcmp(a->attr.name,"fsa")) { v=&fsc; }
  else if (!strcmp(a->attr.name,"fsa")) { v=&fsd; }
  else { v=&foo; }
  
  sscanf(b,"%d",v);
  printk(KERN_ALERT "intstore(%s) %s=%d\n",a->attr.name,b,*v);
  return *v;
}


static struct kobj_attribute fsaattr = 
  __ATTR(fsa,0666,intshow, intstore);
static struct kobj_attribute fsbattr = 
  __ATTR(fsb,0666,intshow, intstore);
static struct kobj_attribute fscattr = 
  __ATTR(fsc,0666,intshow, intstore);
static struct kobj_attribute fsdattr = 
  __ATTR(fsd,0666,intshow, intstore);

static struct attribute* fsattrs[] = {
  &fsaattr.attr,
  &fsbattr.attr,
  &fscattr.attr,
  &fsdattr.attr,
  NULL
};

static struct attribute_group fsgroup = {
  .attrs = fsattrs
};





/*
 *
 *
 *
 */








/*
 */

static struct sock* nl_sk = NULL;
static struct kobject* ra2kobj = NULL;


static int ra2up_recv( struct sk_buff* skb, struct nlmsghdr* nl ) {
 
  struct sk_buff* rep;
  struct nlmsghdr* nlh;
  char hello[256];

  u8* payLoad = NULL;
  int payLoadSize;
  int len;
  int seq;
  pid_t pid;
  int n;


  printk(KERN_ALERT "ra2up_recv() called\n");
  pid = nl->nlmsg_pid;    /* caller pid */
  len = nl->nlmsg_len;
  seq = nl->nlmsg_seq;
  printk(KERN_ALERT "nlmsg_pid = %d, nlmsg_len = %d, nlmsg_seq = %d\n",
	 pid, len, seq);

  payLoadSize = nl->nlmsg_len - NLMSG_LENGTH(0);
  payLoad = NLMSG_DATA(nl);

  if (payLoadSize > 0) {
    printk(KERN_ALERT "Received from up: %s\n",payLoad);
  }

  /*
   * Send response..
   */

  sprintf(hello,"Hi process number %d",pid);
  len = strlen(hello)+1+NLMSG_HDRLEN;

  if ((rep = alloc_skb(NLMSG_SPACE(len),GFP_KERNEL)) == NULL) {
    printk(KERN_ERR "Allocating skb failed\n");
    return 1;
  }

  printk(KERN_ALERT "Sending to %d (%d) '%s'\n",pid,KNETLINK_RA2UP_GRP,hello);


#if 0
  skb_put(rep,NLMSG_SPACE(len));
  nlh = (struct nlmsghdr*)rep->data;
  nlh->nlmsg_len = NLMSG_LENGTH(len);
  nlh->nlmsg_pid = 0;  /* sent from kernel.. */
  nlh->nlmsg_flags = NLMSG_DONE;
#else
  pid = 0;
  seq = 0;
  nlh = NLMSG_PUT(rep,pid,seq,NLMSG_DONE,len);
#endif
  strcpy(NLMSG_DATA(nlh),hello);
  NETLINK_CB(rep).dst_group = KNETLINK_RA2UP_GRP;
  NETLINK_CB(rep).pid = 0;
  //n = netlink_broadcast(nl_sk,rep,0,1,GFP_KERNEL);
  n = netlink_broadcast(nl_sk,rep,0,KNETLINK_RA2UP_GRP,GFP_KERNEL);
  //n = netlink_unicast(nl_sk,rep,pid,0);
  
  printk(KERN_ALERT "Reply sent, %d bytes\n",len);
  printk(KERN_ALERT "netlink_unicast() returned %d\n",n);
  return 0;
nlmsg_failure:
  printk(KERN_ERR "NLMSG_PUT() macro failed\n");
  return 1;
}

static void ra2up_input( struct sk_buff* skb ) {
  printk(KERN_ALERT "ra2up_input() called\n");
  netlink_rcv_skb(skb,&ra2up_recv);
  printk(KERN_ALERT "ra2up_input() exiting\n");
}


					    
static int setupNetlink(void) {
  nl_sk = netlink_kernel_create(&init_net,KNETLINK_RA2UP,
				KNETLINK_RA2UP_GRP,ra2up_input,
				0,THIS_MODULE);

  if (nl_sk == NULL) {
    printk(KERN_ERR "netlink_kernel_create() failed\n");
    return 1;
  }

  return 0;
}

static int setupSysfs( void ) {
  int n;

  if ((ra2kobj = kobject_create_and_add("ra2up",kernel_kobj)) == NULL) {
    printk(KERN_ERR "kobject_create_and_add() failed\n");
    return -ENOMEM;
  }
  if ((n = sysfs_create_group(ra2kobj,&fsgroup))) {
    printk(KERN_ERR "sysfs_create_group() failed: %d\n",n);
    kobject_put(ra2kobj);
    return n;
  }

  return 0;
}


static int ra2up_init( void ) {
  printk(KERN_ALERT "ra2up_init() called\n");

  if (setupNetlink()) {
    printk(KERN_ERR "Opening netlink socket for RA processing failed\n");
    return 1;
  }
  if (setupSysfs()) {
    printk(KERN_ERR "Creating sysfs entries failed\n");
    return 1;
  }

  return 0;
}

static void ra2up_exit( void ) {
  printk(KERN_ALERT "ra2up_exit() called\n");

  if (nl_sk) {
    printk(KERN_ALERT "Closing ra2up netlink socket\n");
    netlink_kernel_release(nl_sk);
  }
  if (ra2kobj) {
    kobject_put(ra2kobj);
  }
}




/*
 *
 *
 */

module_init(ra2up_init);
module_exit(ra2up_exit);
