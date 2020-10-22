CONFIG_MODULE_SIG=n
CONFIG_MODULE_SIG_ALL=n

#ifneq ($(KERNELRELEASE),)
obj-m += ippp.o
ippp-objs := af_inetpp.o protocol.o route.o \
	         ippp_input.o ippp_output.o ippp_forward.o ippp_fragment.o ippp_exthdr.o ippp_icmp.o \
	         tcp_ippp.o inetpp_hashtables.o udp.o
#else
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)
all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
clean:  
	rm -f *.ko *.o *.mod.o *.mod.c *.symvers modules.order *.unsigned
#endif