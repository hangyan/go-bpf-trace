BASEDIR = $(abspath)

OUTPUT = ./output

LIBBPF_SRC = $(abspath libbpf/src)
LIBBPF_OBJ = $(abspath $(OUTPUT)/libbpf.a)
LIBBPF_OBJDIR = $(abspath ./$(OUTPUT)/libbpf)
LIBBPF_DESTDIR = $(abspath ./$(OUTPUT))


CC = gcc
CLANG = clang

ARCH := $(shell uname -m)
ARCH := $(subst x86_64,amd64,$(ARCH))

CFLAGS = -g -O2 -Wall -fpie
LDFLAGS =

CGO_CFLAGS_STATIC = "-I$(abspath $(OUTPUT))"
CGO_LDFLAGS_STATIC = "-lelf -lz $(LIBBPF_OBJ)"
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'

CGO_CFGLAGS_DYN = "-I. -I/usr/include/"
CGO_LDFLAGS_DYN = "-lelf -lz -lbpf"

.PHONY: $(TEST)
.PHONY: $(TEST).go
.PHONY: $(TEST).bpf.c

TEST = flowsnoop

all: $(TEST)-static

.PHONY: libbpfgo
.PHONY: libbpfgo-static
.PHONY: libbpfgo-dynamic

## libbpfgo

libbpfgo-static:
	$(MAKE) -C $(BASEDIR) libbpfgo-static

libbpfgo-dynamic:
	$(MAKE) -C $(BASEDIR) libbpfgo-dynamic

outputdir:
	$(MAKE) -C $(BASEDIR) outputdir

## test bpf dependency



# static libbpf generation for the git submodule

.PHONY: libbpf-static
libbpf-static: $(LIBBPF_SRC) $(wildcard $(LIBBPF_SRC)/*.[ch])
	cp -r libbpf output/

	CC="$(CC)" CFLAGS="$(CFLAGS)" LD_FLAGS="$(LDFLAGS)" \
	   $(MAKE) -C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPF_OBJDIR) \
		DESTDIR=$(LIBBPF_DESTDIR) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install



$(TEST).bpf.o: $(TEST).bpf.c
	cp vmlinux.h output/
	cp trace.bpf.h output/
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_x86 -I$(OUTPUT) -c $< -o $@

## test

.PHONY: $(TEST)-static
.PHONY: $(TEST)-dynamic

$(TEST)-static:  $(TEST).bpf.o
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
		GOOS=linux GOARCH=$(ARCH) \
		go build \
		-tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
		-o $(TEST)-static ./$(TEST).go

$(TEST)-dynamic: libbpfgo-dynamic | $(TEST).bpf.o
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_DYN) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_DYN) \
		go build -o ./$(TEST)-dynamic ./$(TEST).go


docker:
	docker build -t flowsnoop .
docker-run:
	docker run -d --name fs --privileged flowsnoop tail -f /dev/null


## run

.PHONY: run
.PHONY: run-static
.PHONY: run-dynamic

run: run-static

run-static: $(TEST)-static
	sudo ./run.sh $(TEST)-static

run-dynamic: $(TEST)-dynamic
	sudo ./run.sh $(TEST)-dynamic

clean:
	rm -f *.o *-static *-dynamic
