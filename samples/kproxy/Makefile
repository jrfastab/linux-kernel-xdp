# List of programs to build
hostprogs-y := kproxy

# Tell kbuild to always build the programs
always := $(hostprogs-y)

HOSTCFLAGS += -I$(objtree)/usr/include

HOSTLOADLIBES_kproxy += -lelf -lpthread

# Trick to allow make to be run from this directory
all:
	$(MAKE) -C ../../ $(CURDIR)/

clean:
	$(MAKE) -C ../../ M=$(CURDIR) clean
	@rm -f *~
