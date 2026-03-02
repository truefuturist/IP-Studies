CC     = gcc
CLANG  = clang
BPF_FLAGS = -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu
CFLAGS = -O2 -Wall

all: xdp_kern.o xdp_http

xdp_kern.o: xdp_kern.c
	$(CLANG) $(BPF_FLAGS) -c $< -o $@

xdp_http: xdp_http.c
	$(CC) $(CFLAGS) -o $@ $< -lbpf

clean:
	rm -f xdp_kern.o xdp_http
