#
# (c) jouni Korhonen 2010
# v0.1 first ever try on kernel modules and own netlink stuff
#

EXTRA_CFLAGS += -DFOO
KVERSION = $(shell uname -r)
KDIR = $(HOME)/devel/linux-source-2.6.32/

CONFIG_RA_TO_UP = m


#

obj-$(CONFIG_RA_TO_UP) += ra2upmod.o
ra2upmod-objs := ra2up.o

#

all:
	make -C $(KDIR) M=`pwd` modules

clean:
	make -C $(KDIR) M=`pwd` clean

install:
	make -C $(KDIR) M=`pwd` modules_install


