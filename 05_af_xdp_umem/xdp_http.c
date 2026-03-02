/*
 * xdp_http.c — AF_XDP / UMEM HTTP GET client
 *
 * HTTP GET via AF_XDP sockets with a kernel-registered UMEM.
 *
 * Data path (lower than PACKET_MMAP level 4):
 *
 *   RX: Wire → NIC DMA → UMEM page (zero-copy, or kernel-copy in copy mode)
 *       The XDP eBPF program (xdp_kern.o) intercepts the packet at the
 *       NIC driver's NAPI poll hook — before sk_buff allocation — and
 *       issues bpf_redirect_map() to deliver it straight into our UMEM.
 *       No kernel IP/TCP stack ever sees the packet.
 *
 *   TX: We write frame into a UMEM chunk → place descriptor in TX ring →
 *       sendto(NULL) wakes the kernel → NIC DMA reads from UMEM → wire.
 *
 * The TCP three-way handshake and HTTP request are hand-built exactly as
 * in levels 3 and 4; checksums computed manually.
 *
 * Requires: CAP_NET_ADMIN + CAP_NET_RAW (sudo), xdp_kern.o in same dir.
 * Compile:  see Makefile
 * Run:      sudo ./xdp_http
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* ── Network configuration ──────────────────────────────────────────────── */
#define IFACE      "wlp0s20f3"
#define SRC_IP     "10.0.0.9"
#define DST_IP     "34.160.111.145"
#define DST_PORT   80
#define SRC_PORT   54323

static uint8_t SRC_MAC[] = {0x70,0x32,0x17,0x44,0x3f,0x59};
static uint8_t GW_MAC[]  = {0x44,0xa5,0x6e,0x70,0x28,0x54};

/* ── UMEM / ring geometry ────────────────────────────────────────────────── */
#define FRAME_SIZE   2048
#define NUM_FRAMES   64
#define RX_FRAMES    32                         /* frames 0–31: fill ring */
#define TX_FRAME_BASE (RX_FRAMES * FRAME_SIZE)  /* TX frames start here   */
#define UMEM_SIZE    (NUM_FRAMES * FRAME_SIZE)  /* 128 KiB                */
#define RING_SIZE    64                         /* power-of-2 ring depth  */

/* ── HTTP request ────────────────────────────────────────────────────────── */
static const char HTTP_GET[] =
    "GET / HTTP/1.0\r\n"
    "Host: ifconfig.me\r\n"
    "User-Agent: af-xdp-umem/napi-hook\r\n"
    "\r\n";

/* ── Ring accessor helpers ───────────────────────────────────────────────── */
typedef struct { uint8_t *base; struct xdp_mmap_offsets *off; } ring_t;

#define RING_PROD(r, field) \
    ((uint32_t *)((r).base + (r).off->field.producer))
#define RING_CONS(r, field) \
    ((uint32_t *)((r).base + (r).off->field.consumer))
#define RING_DESC(r, field, T) \
    ((T *)((r).base + (r).off->field.desc))
#define RING_FLAGS(r, field) \
    ((uint32_t *)((r).base + (r).off->field.flags))

/* ── Internet checksum ───────────────────────────────────────────────────── */
static uint16_t inet_cksum(void *buf, int len)
{
    uint16_t *p = buf; uint32_t s = 0;
    for (; len > 1; len -= 2) s += *p++;
    if (len) s += *(uint8_t *)p;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return ~s;
}

static uint16_t tcp_cksum(struct iphdr *ip, struct tcphdr *tcp,
                           const void *payload, int plen)
{
    uint8_t pseudo[12];
    uint16_t tlen = htons((uint16_t)(sizeof(*tcp) + plen));
    memcpy(pseudo,    &ip->saddr, 4);
    memcpy(pseudo+4,  &ip->daddr, 4);
    pseudo[8]=0; pseudo[9]=IPPROTO_TCP; memcpy(pseudo+10, &tlen, 2);
    uint32_t s = 0; int i;
    for (i=0;i<6;i++)               s += ((uint16_t *)pseudo)[i];
    for (i=0;i<(int)sizeof(*tcp)/2;i++) s += ((uint16_t *)tcp)[i];
    for (i=0;i<plen/2;i++)          s += ((uint16_t *)payload)[i];
    if (plen&1) s += ((uint8_t *)payload)[plen-1];
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return ~s;
}

/* ── Build Ethernet+IP+TCP frame into a UMEM chunk ──────────────────────── */
/* flags: SYN=0x02 ACK=0x10 PSH=0x08 FIN=0x01                               */
static int build_frame(void *dst,
                       uint32_t seq, uint32_t ack, uint8_t flags,
                       const void *payload, int plen)
{
    struct ethhdr *eth = dst;
    struct iphdr  *ip  = dst + 14;
    struct tcphdr *tcp = dst + 34;

    memcpy(eth->h_dest,   GW_MAC,  6);
    memcpy(eth->h_source, SRC_MAC, 6);
    eth->h_proto = htons(ETH_P_IP);

    memset(ip, 0, 20);
    ip->version=4; ip->ihl=5; ip->ttl=64; ip->protocol=IPPROTO_TCP;
    ip->saddr=inet_addr(SRC_IP); ip->daddr=inet_addr(DST_IP);
    ip->tot_len=htons((uint16_t)(40+plen));
    ip->check=inet_cksum(ip,20);

    memset(tcp, 0, 20);
    tcp->source=htons(SRC_PORT); tcp->dest=htons(DST_PORT);
    tcp->seq=htonl(seq); tcp->ack_seq=htonl(ack);
    tcp->doff=5; tcp->window=htons(65535);
    if (flags&0x02) tcp->syn=1;
    if (flags&0x10) tcp->ack=1;
    if (flags&0x08) tcp->psh=1;
    if (flags&0x01) tcp->fin=1;
    if (plen) memcpy(dst+54, payload, plen);
    tcp->check=0; tcp->check=tcp_cksum(ip,tcp,payload,plen);
    return 54+plen;
}

/* ── Packet filter: is this from our server connection? ─────────────────── */
static int our_pkt(const uint8_t *f, int n,
                   struct iphdr **ri, struct tcphdr **rt,
                   uint8_t **rd, int *rdn)
{
    if (n < 54) return 0;
    struct ethhdr *eth = (struct ethhdr *)f;
    if (ntohs(eth->h_proto) != ETH_P_IP) return 0;
    struct iphdr  *ip = (struct iphdr *)(f+14);
    if (ip->protocol != IPPROTO_TCP)       return 0;
    if (ip->saddr != inet_addr(DST_IP))    return 0;
    int iph=ip->ihl*4;
    struct tcphdr *tcp = (struct tcphdr *)(f+14+iph);
    if (ntohs(tcp->source) != DST_PORT)    return 0;
    if (ntohs(tcp->dest)   != SRC_PORT)    return 0;
    int tcph=tcp->doff*4;
    *ri=ip; *rt=tcp;
    *rd=(uint8_t *)f+14+iph+tcph; *rdn=n-(14+iph+tcph);
    return 1;
}

/* ── TX: write frame into UMEM, post descriptor, kick kernel ────────────── */
static int tx_idx_g = 0;

static void xsk_tx(int xsk_fd, uint8_t *umem,
                   uint32_t *tx_prod, struct xdp_desc *tx_descs,
                   uint32_t seq, uint32_t ack, uint8_t flags,
                   const void *payload, int plen)
{
    /* Rotate through TX frame slots */
    int slot = (tx_idx_g % (NUM_FRAMES - RX_FRAMES));
    uint64_t addr = TX_FRAME_BASE + (uint64_t)slot * FRAME_SIZE;
    tx_idx_g++;

    /* Write directly into UMEM — NIC will DMA this to wire */
    int flen = build_frame(umem + addr, seq, ack, flags, payload, plen);

    uint32_t prod = __atomic_load_n(tx_prod, __ATOMIC_ACQUIRE);
    uint32_t idx  = prod & (RING_SIZE - 1);
    tx_descs[idx].addr    = addr;
    tx_descs[idx].len     = flen;
    tx_descs[idx].options = 0;
    __atomic_store_n(tx_prod, prod + 1, __ATOMIC_RELEASE);

    /* Wakeup: kernel queues descriptor for NIC DMA — no data copy */
    sendto(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
}

/* ── RX: wait for NIC DMA to deliver a frame into UMEM ─────────────────── */
/* Returns pointer into UMEM (zero-copy in zerocopy mode, else copy-mode)    */
static const uint8_t *xsk_rx_wait(int xsk_fd, uint8_t *umem,
                                   uint32_t *rx_prod, uint32_t *rx_cons,
                                   struct xdp_desc *rx_descs,
                                   uint32_t *fill_prod, uint64_t *fill_descs,
                                   int *out_len, uint64_t *out_addr)
{
    while (__atomic_load_n(rx_prod, __ATOMIC_ACQUIRE)
           == __atomic_load_n(rx_cons, __ATOMIC_ACQUIRE)) {
        struct pollfd pf = { .fd=xsk_fd, .events=POLLIN };
        int r = poll(&pf, 1, 5000);
        if (r <= 0 || !(pf.revents & POLLIN)) return NULL;
    }

    uint32_t cons = __atomic_load_n(rx_cons, __ATOMIC_ACQUIRE);
    struct xdp_desc *d = &rx_descs[cons & (RING_SIZE - 1)];
    *out_len  = d->len;
    *out_addr = d->addr;

    /* Data lives directly in UMEM — read it in-place, zero kernel copy */
    return umem + d->addr;
}

static void xsk_rx_release(uint32_t *rx_cons, uint32_t *fill_prod,
                            uint64_t *fill_descs, uint64_t addr)
{
    /* Return the UMEM chunk to the fill ring so the kernel can reuse it */
    uint32_t fp = __atomic_load_n(fill_prod, __ATOMIC_ACQUIRE);
    fill_descs[fp & (RING_SIZE - 1)] = addr;
    __atomic_store_n(fill_prod, fp + 1, __ATOMIC_RELEASE);

    uint32_t rc = __atomic_load_n(rx_cons, __ATOMIC_ACQUIRE);
    __atomic_store_n(rx_cons, rc + 1, __ATOMIC_RELEASE);
}

/* ── Main ───────────────────────────────────────────────────────────────── */
int main(void)
{
    int ret = 0;
    struct bpf_object  *bpf_obj  = NULL;
    int                 xsk_fd   = -1;
    uint8_t            *umem     = MAP_FAILED;
    uint8_t            *fill_map = MAP_FAILED;
    uint8_t            *comp_map = MAP_FAILED;
    uint8_t            *rx_map   = MAP_FAILED;
    uint8_t            *tx_map   = MAP_FAILED;
    int                 ifindex;

    /* ── Interface index ────────────────────────────────────────────────── */
    ifindex = if_nametoindex(IFACE);
    if (!ifindex) { perror("if_nametoindex"); goto done; }

    /* ── Load and attach XDP eBPF program ─────────────────────────────── */
    bpf_obj = bpf_object__open_file("xdp_kern.o", NULL);
    if (libbpf_get_error(bpf_obj)) { fprintf(stderr, "bpf open\n"); goto done; }
    if (bpf_object__load(bpf_obj)) { fprintf(stderr, "bpf load\n"); goto done; }

    struct bpf_program *prog =
        bpf_object__find_program_by_name(bpf_obj, "xdp_http_redirect");
    if (!prog) { fprintf(stderr, "bpf prog not found\n"); goto done; }
    int prog_fd = bpf_program__fd(prog);

    /* Attach XDP program at native (driver) hook — runs in NAPI context */
    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL)) {
        perror("bpf_xdp_attach"); goto done;
    }
    fprintf(stderr, "[XDP]  program attached to %s (driver/NAPI hook)\n", IFACE);

    /* ── Create AF_XDP socket ───────────────────────────────────────────── */
    xsk_fd = socket(AF_XDP, SOCK_RAW, 0);
    if (xsk_fd < 0) { perror("socket AF_XDP"); goto detach; }

    /* ── Allocate UMEM (page-aligned, suitable for NIC DMA) ─────────────── */
    umem = mmap(NULL, UMEM_SIZE,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                -1, 0);
    if (umem == MAP_FAILED) { perror("mmap umem"); goto detach; }

    /* Register UMEM with the kernel / NIC DMA engine */
    struct xdp_umem_reg ureg = {
        .addr       = (uint64_t)umem,
        .len        = UMEM_SIZE,
        .chunk_size = FRAME_SIZE,
        .headroom   = 0,
        .flags      = 0,
    };
    if (setsockopt(xsk_fd, SOL_XDP, XDP_UMEM_REG, &ureg, sizeof(ureg))) {
        perror("XDP_UMEM_REG"); goto detach;
    }
    fprintf(stderr, "[XDP]  UMEM %p–%p (%u KiB) registered for DMA\n",
            umem, umem + UMEM_SIZE, UMEM_SIZE / 1024);

    /* ── Configure ring sizes ───────────────────────────────────────────── */
    int rs = RING_SIZE;
    if (setsockopt(xsk_fd, SOL_XDP, XDP_UMEM_FILL_RING,       &rs, sizeof(rs)) ||
        setsockopt(xsk_fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &rs, sizeof(rs)) ||
        setsockopt(xsk_fd, SOL_XDP, XDP_RX_RING,              &rs, sizeof(rs)) ||
        setsockopt(xsk_fd, SOL_XDP, XDP_TX_RING,              &rs, sizeof(rs))) {
        perror("ring setsockopt"); goto detach;
    }

    /* ── Query ring mmap offsets ────────────────────────────────────────── */
    struct xdp_mmap_offsets off;
    socklen_t olen = sizeof(off);
    if (getsockopt(xsk_fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &olen)) {
        perror("XDP_MMAP_OFFSETS"); goto detach;
    }

    /* ── mmap all four rings ─────────────────────────────────────────────── */
    fill_map = mmap(NULL, off.fr.desc + RING_SIZE * sizeof(uint64_t),
                    PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE,
                    xsk_fd, XDP_UMEM_PGOFF_FILL_RING);
    comp_map = mmap(NULL, off.cr.desc + RING_SIZE * sizeof(uint64_t),
                    PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE,
                    xsk_fd, XDP_UMEM_PGOFF_COMPLETION_RING);
    rx_map   = mmap(NULL, off.rx.desc + RING_SIZE * sizeof(struct xdp_desc),
                    PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE,
                    xsk_fd, XDP_PGOFF_RX_RING);
    tx_map   = mmap(NULL, off.tx.desc + RING_SIZE * sizeof(struct xdp_desc),
                    PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE,
                    xsk_fd, XDP_PGOFF_TX_RING);

    if (fill_map == MAP_FAILED || comp_map == MAP_FAILED ||
        rx_map   == MAP_FAILED || tx_map   == MAP_FAILED) {
        perror("ring mmap"); goto detach;
    }

    /* Ring pointers */
    uint32_t      *fill_prod  = (uint32_t *)(fill_map + off.fr.producer);
    uint64_t      *fill_descs = (uint64_t *)(fill_map + off.fr.desc);
    uint32_t      *rx_prod    = (uint32_t *)(rx_map   + off.rx.producer);
    uint32_t      *rx_cons    = (uint32_t *)(rx_map   + off.rx.consumer);
    struct xdp_desc *rx_descs = (struct xdp_desc *)(rx_map + off.rx.desc);
    uint32_t      *tx_prod    = (uint32_t *)(tx_map   + off.tx.producer);
    struct xdp_desc *tx_descs = (struct xdp_desc *)(tx_map + off.tx.desc);

    /* ── Pre-populate fill ring: give RX UMEM chunks to the NIC DMA ─────── */
    for (int i = 0; i < RX_FRAMES; i++) {
        fill_descs[i] = (uint64_t)(i * FRAME_SIZE);
    }
    __atomic_store_n(fill_prod, RX_FRAMES, __ATOMIC_RELEASE);
    fprintf(stderr, "[XDP]  fill ring seeded with %d UMEM chunks for NIC DMA\n",
            RX_FRAMES);

    /* ── Bind to interface queue 0 ──────────────────────────────────────── */
    struct sockaddr_xdp sxdp = {
        .sxdp_family   = AF_XDP,
        .sxdp_flags    = XDP_COPY,   /* copy mode: works on all drivers     */
        .sxdp_ifindex  = ifindex,
        .sxdp_queue_id = 0,
    };
    if (bind(xsk_fd, (struct sockaddr *)&sxdp, sizeof(sxdp))) {
        perror("bind AF_XDP"); goto detach;
    }
    fprintf(stderr, "[XDP]  bound to %s queue 0 (XDP_COPY mode)\n", IFACE);

    /* ── Register our socket in the XSKMAP ─────────────────────────────── */
    struct bpf_map *xsk_map_obj =
        bpf_object__find_map_by_name(bpf_obj, "xsk_map");
    if (!xsk_map_obj) { fprintf(stderr, "xsk_map not found\n"); goto detach; }
    int xsk_map_fd = bpf_map__fd(xsk_map_obj);
    int key = 0;
    if (bpf_map_update_elem(xsk_map_fd, &key, &xsk_fd, BPF_ANY)) {
        perror("xsk_map_update"); goto detach;
    }
    fprintf(stderr, "[XDP]  socket registered in XSKMAP — redirection active\n");

    /* ── TCP state machine ──────────────────────────────────────────────── */
    struct iphdr  *rip;  struct tcphdr *rtcp;
    uint8_t *rdata;      int rdlen;
    uint32_t isn = 0xFEEDC0DEu, seq = isn, ack = 0;
    uint64_t rx_addr;   int rx_len;

#define TX(fl, pay, plen) \
    xsk_tx(xsk_fd, umem, tx_prod, tx_descs, seq, ack, fl, pay, plen)

    /* SYN */
    fprintf(stderr, "[TCP]  SYN  seq=%u\n", seq);
    TX(0x02, NULL, 0);  seq++;

    /* Wait for SYN-ACK */
    for (;;) {
        const uint8_t *f = xsk_rx_wait(xsk_fd, umem,
                                        rx_prod, rx_cons, rx_descs,
                                        fill_prod, fill_descs,
                                        &rx_len, &rx_addr);
        if (!f) { fprintf(stderr, "timeout\n"); goto detach; }
        if (our_pkt(f, rx_len, &rip, &rtcp, &rdata, &rdlen)
            && rtcp->syn && rtcp->ack) {
            ack = ntohl(rtcp->seq) + 1;
            fprintf(stderr, "[TCP]  SYN-ACK  server_isn=%u  ack=%u\n",
                    ntohl(rtcp->seq), ack);
            xsk_rx_release(rx_cons, fill_prod, fill_descs, rx_addr);
            break;
        }
        xsk_rx_release(rx_cons, fill_prod, fill_descs, rx_addr);
    }

    /* ACK */
    TX(0x10, NULL, 0);
    fprintf(stderr, "[TCP]  ACK  (ESTABLISHED)\n");

    /* PSH+ACK: HTTP GET */
    int glen = (int)strlen(HTTP_GET);
    TX(0x18, HTTP_GET, glen);  seq += glen;
    fprintf(stderr, "[TCP]  PSH+ACK  %d bytes HTTP GET\n", glen);

    /* Data receive loop */
    for (;;) {
        const uint8_t *f = xsk_rx_wait(xsk_fd, umem,
                                        rx_prod, rx_cons, rx_descs,
                                        fill_prod, fill_descs,
                                        &rx_len, &rx_addr);
        if (!f) break;
        if (!our_pkt(f, rx_len, &rip, &rtcp, &rdata, &rdlen)) {
            xsk_rx_release(rx_cons, fill_prod, fill_descs, rx_addr);
            continue;
        }
        if (rdlen > 0) {
            /* Read directly from UMEM — zero kernel copy in zero-copy mode */
            fwrite(rdata, 1, rdlen, stdout);
            fflush(stdout);
            ack = ntohl(rtcp->seq) + rdlen;
            TX(0x10, NULL, 0);
            fprintf(stderr, "[TCP]  ACK %d bytes  ack=%u\n", rdlen, ack);
        }
        if (rtcp->fin) {
            ack++;
            TX(0x11, NULL, 0);
            fprintf(stderr, "[TCP]  FIN-ACK (CLOSED)\n");
            xsk_rx_release(rx_cons, fill_prod, fill_descs, rx_addr);
            break;
        }
        if (rtcp->rst) {
            fprintf(stderr, "[TCP]  RST\n");
            xsk_rx_release(rx_cons, fill_prod, fill_descs, rx_addr);
            break;
        }
        xsk_rx_release(rx_cons, fill_prod, fill_descs, rx_addr);
    }

detach:
    /* Detach XDP program from interface */
    bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    fprintf(stderr, "[XDP]  program detached\n");

done:
    if (fill_map != MAP_FAILED)
        munmap(fill_map, off.fr.desc + RING_SIZE * sizeof(uint64_t));
    if (comp_map != MAP_FAILED)
        munmap(comp_map, off.cr.desc + RING_SIZE * sizeof(uint64_t));
    if (rx_map != MAP_FAILED)
        munmap(rx_map, off.rx.desc + RING_SIZE * sizeof(struct xdp_desc));
    if (tx_map != MAP_FAILED)
        munmap(tx_map, off.tx.desc + RING_SIZE * sizeof(struct xdp_desc));
    if (umem != MAP_FAILED)
        munmap(umem, UMEM_SIZE);
    if (xsk_fd >= 0)  close(xsk_fd);
    if (bpf_obj)      bpf_object__close(bpf_obj);
    return ret;
}
