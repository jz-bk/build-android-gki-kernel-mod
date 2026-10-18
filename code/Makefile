obj-m += cpuset_hook.o

obj-m += your_driver.o

all:
make -C $(KDIR) M=$(PWD) modules

clean:
make -C $(KDIR) M=$(PWD) clean
