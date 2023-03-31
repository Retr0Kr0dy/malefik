obj-m := malefik.o
CC := gcc -Wall
DIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	make -C $(DIR) M=$(PWD) modules

clean:
	make -C $(DIR) M=$(PWD) clean
