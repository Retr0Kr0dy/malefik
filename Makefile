obj-m 		:= malefik.o
KERNEL_ROOT := /lib/modules/$(shell uname -r)/build
FINAL_DEST	:= /lib/modules/$(shell uname -r)/kernel/drivers/mlfk/
DEBUG		:= 0

modules:
	@$(MAKE) -C $(KERNEL_ROOT) M=$(shell pwd) modules
#	mkdir $(FINAL_DEST) 
#	mv malefik.ko $(FINAL_DEST)
#	modprobe malefik.ko
	insmod malefik.ko

clean:
#	modprobe -r malefik
	rmmod malefik.ko
	@$(MAKE) -C $(KERNEL_ROOT) M=$(shell pwd) clean
