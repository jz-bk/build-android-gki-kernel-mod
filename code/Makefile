obj-m += cpuset_hook.o

all:
make -C $(KDIR) M=$(PWD) modules

clean:
make -C $(KDIR) M=$(PWD) clean
