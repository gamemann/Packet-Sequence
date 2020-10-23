CC = clang

LDFLAGS += -lpthread

objects += src/config.o src/cmdline.o src/sequence.o
objects += src/pcktseq.o

all: libyaml pcktsequence

libyaml:

pcktsequence: $(objects)
	clang $(LDFLAGS) -o pcktseq $(objects)

clean:
	rm -f pcktseq
	rm -f src/*.o

.PHONY: all

.DEFAULT: all