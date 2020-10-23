CC = clang

LDFLAGS += -lpthread

objects += src/config.o src/cmdline.o src/sequence.o
objects += src/pcktseq.o

all: libyaml pcktsequence

libyaml:
	cd libyaml; ./bootstrap && ./configure
	$(MAKE) -C libyaml/
	$(MAKE) -C libyaml/ install

pcktsequence: $(objects)
	clang $(LDFLAGS) -o pcktseq $(objects)

clean:
	rm -f pcktseq
	rm -f src/*.o

.PHONY: libyaml pcktsequence

.DEFAULT: all