obj-m 		:= malefik.o
KERNEL_ROOT := /lib/modules/$(shell uname -r)/build
DEBUG		:= 0

modules:
	@$(MAKE) -C $(KERNEL_ROOT) M=$(shell pwd) modules
	modprobe malefik.ko

clean:
	modprobe -r malefik
	@$(MAKE) -C $(KERNEL_ROOT) M=$(shell pwd) clean
