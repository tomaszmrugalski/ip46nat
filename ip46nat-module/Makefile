# to compile this module (as a separate module, not integrated to 
# kernel tree), use fololwing command:
# make -C /path/to/your/linux/source SUBDIRS=$PWD modules
#
# e.g.
# make -C /usr/src/linux-2.6.23 SUBDIRS=$PWD modules
#

build-and-copy:
	$(MAKE) -C /usr/src/linux-source-2.6.25 SUBDIRS=$(PWD) modules
	cp -f ip46nat.ko /usr/src/modules/

clean:
	rm -f *.mod.c *.ko *.o Module.symvers modules.order

DIR=`basename $(PWD)` 

snapshot: clean
	rm -f ip46nat-`date +%Y%m%d`.tar.gz
	cd ..; tar czf ip46nat.tar.gz $(DIR)
	mv ../ip46nat.tar.gz ip46nat-`date +%Y%m%d`.tar.gz
	echo "Snapshot has been stored in the ip46nat-`date +%Y%m%d`.tar.gz file."

openwrt:
	cp ip46nat.c /home/thomson/devel/openwrt/kamikaze-12386/build_dir/linux-brcm47xx/linux-2.6.25.16/net/ipv6/
	make -C /home/thomson/devel/openwrt/kamikaze-12386/ V=99

obj-m := ip46nat.o

.PHONY: clean build-and-copy snapshot
