/*
 * raw_mmap_tcp.c — PACKET_MMAP / TPACKET_V2 zero-copy ring buffers
 *
 * HTTP GET by writing Ethernet frames directly into mmap'd kernel DMA ring
 * buffers.  There is no per-packet data copy on either the TX or RX path:
 *
 *   TX: frame written into shared ring slot → tp_status=SEND_REQUEST →
 *       send(NULL,0) wakeup (not data transfer) → NIC DMA
 *
 *   RX: NIC DMA → ring slot → tp_status=USER → we read directly →
 *       tp_status=KERNEL (slot returned)
 *
 * This is lower than AF_PACKET SOCK_RAW (level 3) because:
 *   - Level 3 sendto()  : userspace buf → kernel copies → ring buf → DMA
 *   - Level 4 ring write: userspace writes directly into ring buf   → DMA
 *   - Level 3 recvfrom(): DMA → ring buf → kernel copies → userspace buf
 *   - Level 4 ring read : DMA → ring buf → userspace reads directly (zero-copy)
 *
 * We still implement TCP from scratch (SYN/SYN-ACK/ACK/data/FIN) and build
 * every Ethernet+IP+TCP header manually, exactly as in level 3.
 *
 * Requires CAP_NET_RAW (sudo).
 * Compile: gcc -O2 -o raw_mmap_tcp raw_mmap_tcp.c
 * Run:     sudo ./raw_mmap_tcp
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
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* ── Network config ─────────────────────────────────────────────────────── */
#define IFACE    "wlp0s20f3"
#define SRC_IP   "10.0.0.9"
#define DST_IP   "34.160.111.145"      /* ifconfig.me */
#define DST_PORT  80
#define SRC_PORT  54322                /* different from level 3, avoids TIME_WAIT */

static uint8_t SRC_MAC[] = {0x70,0x32,0x17,0x44,0x3f,0x59};
static uint8_t GW_MAC[]  = {0x44,0xa5,0x6e,0x70,0x28,0x54};

/* ── TPACKET_V2 ring geometry ───────────────────────────────────────────── */
#define TP_BLOCK_SIZE  4096
#define TP_BLOCK_NR    16
#define TP_FRAME_SIZE  2048
#define TP_FRAME_NR    (TP_BLOCK_SIZE * TP_BLOCK_NR / TP_FRAME_SIZE)  /* 32 */
#define TP_RING_BYTES  (TP_BLOCK_SIZE * TP_BLOCK_NR)                  /* 64 KiB */

/*
 * Within each ring slot the tpacket2_hdr sits first (aligned).
 * For TX: packet data begins immediately after that header.
 * For RX: the kernel sets hdr->tp_mac to the actual data offset.
 */
#define TPHDR_LEN  TPACKET_ALIGN(sizeof(struct tpacket2_hdr))

/* ── HTTP request ───────────────────────────────────────────────────────── */
static const char HTTP_GET[] =
    "GET / HTTP/1.0\r\n"
    "Host: ifconfig.me\r\n"
    "User-Agent: raw-mmap-tpacketv2/zero-copy\r\n"
    "\r\n";

/* ── Internet checksum (RFC 1071) ───────────────────────────────────────── */
static uint16_t inet_cksum(void *buf, int len)
{
    uint16_t *p = buf;
    uint32_t  s = 0;
    for (; len > 1; len -= 2) s += *p++;
    if (len) s += *(uint8_t *)p;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return ~s;
}

static uint16_t tcp_cksum(struct iphdr *ip, struct tcphdr *tcp,
                           const void *payload, int plen)
{
    uint8_t  pseudo[12];
    uint16_t tlen = htons((uint16_t)(sizeof(*tcp) + plen));
    memcpy(pseudo,    &ip->saddr, 4);
    memcpy(pseudo+4,  &ip->daddr, 4);
    pseudo[8]=0; pseudo[9]=IPPROTO_TCP;
    memcpy(pseudo+10, &tlen, 2);

    uint32_t s = 0;
    int i;
    for (i = 0; i < 6;                    i++) s += ((uint16_t *)pseudo)[i];
    for (i = 0; i < (int)sizeof(*tcp)/2;  i++) s += ((uint16_t *)tcp)[i];
    for (i = 0; i < plen/2;               i++) s += ((uint16_t *)payload)[i];
    if (plen & 1) s += ((uint8_t *)payload)[plen-1];
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return ~s;
}

/* ── Build Ethernet+IP+TCP frame directly into caller-supplied buffer ───── */
/* flags: SYN=0x02  ACK=0x10  PSH=0x08  FIN=0x01                           */
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

/* ── TX: write frame into mmap'd TX ring slot, hand to kernel ───────────── */
/*
 * No sendto() copy.  We write directly into the shared ring buffer.
 * The send(NULL) call is purely a kernel wakeup — not a data transfer.
 */
static void tx_send(uint8_t *tx_ring, int *idx, int sock,
                    uint32_t seq, uint32_t ack, uint8_t flags,
                    const void *payload, int plen)
{
    struct tpacket2_hdr *hdr =
        (struct tpacket2_hdr *)(tx_ring + (size_t)(*idx) * TP_FRAME_SIZE);

    /* Spin until this slot is free (returned by kernel after DMA) */
    while (__atomic_load_n(&hdr->tp_status, __ATOMIC_ACQUIRE)
           != TP_STATUS_AVAILABLE) {
        struct pollfd pf = { .fd=sock, .events=POLLOUT };
        poll(&pf, 1, 1000);
    }

    /* Write frame data straight into the ring buffer — zero kernel copy */
    int flen = build_frame((uint8_t *)hdr + TPHDR_LEN,
                           seq, ack, flags, payload, plen);

    hdr->tp_len     = flen;
    hdr->tp_snaplen = flen;
    /* tp_mac: offset from hdr to MAC header (kernel uses this for TX too) */
    hdr->tp_mac     = TPHDR_LEN;

    /* Release slot to kernel — this is a flag flip, not a copy */
    __atomic_store_n(&hdr->tp_status, TP_STATUS_SEND_REQUEST, __ATOMIC_RELEASE);

    /* Wakeup — tells kernel to DMA pending slots; no data crosses here */
    /* Wakeup — tells kernel to DMA pending slots; no data crosses here */
    int r = send(sock, NULL, 0, 0);
    if (r < 0) perror("[TX] send");

    *idx = (*idx + 1) % TP_FRAME_NR;
}

/* ── RX: wait (via poll) for kernel to fill a ring slot ─────────────────── */
/*
 * Returns a pointer directly into the mmap'd ring — zero kernel copy.
 * Caller must call rx_release() when done with the slot.
 */
static struct tpacket2_hdr *rx_wait(uint8_t *rx_ring, int *idx, int sock)
{
    struct tpacket2_hdr *hdr =
        (struct tpacket2_hdr *)(rx_ring + (size_t)(*idx) * TP_FRAME_SIZE);

    while (!(__atomic_load_n(&hdr->tp_status, __ATOMIC_ACQUIRE)
              & TP_STATUS_USER)) {
        struct pollfd pf = { .fd=sock, .events=POLLIN };
        int r = poll(&pf, 1, 5000);
        if (r <= 0 || !(pf.revents & POLLIN)) return NULL;
    }
    return hdr;
}

static void rx_release(uint8_t *rx_ring, int *idx)
{
    struct tpacket2_hdr *hdr =
        (struct tpacket2_hdr *)(rx_ring + (size_t)(*idx) * TP_FRAME_SIZE);
    __atomic_store_n(&hdr->tp_status, TP_STATUS_KERNEL, __ATOMIC_RELEASE);
    *idx = (*idx + 1) % TP_FRAME_NR;
}

/* ── Packet filter ───────────────────────────────────────────────────────── */
static int our_pkt(const uint8_t *f, int n,
                   struct iphdr **ri, struct tcphdr **rt,
                   uint8_t **rd, int *rdn)
{
    if (n < 54) return 0;
    struct ethhdr *eth = (struct ethhdr *)f;
    if (ntohs(eth->h_proto) != ETH_P_IP) return 0;
    struct iphdr  *ip = (struct iphdr *)(f+14);
    if (ip->protocol != IPPROTO_TCP)       return 0;
    if (ip->saddr    != inet_addr(DST_IP)) return 0;
    int iph = ip->ihl*4;
    struct tcphdr *tcp = (struct tcphdr *)(f+14+iph);
    if (ntohs(tcp->source) != DST_PORT) return 0;
    if (ntohs(tcp->dest)   != SRC_PORT) return 0;
    int tcph = tcp->doff*4;
    *ri  = ip;  *rt  = tcp;
    *rd  = (uint8_t *)f + 14 + iph + tcph;
    *rdn = n - (14 + iph + tcph);
    return 1;
}

/* ── Main ───────────────────────────────────────────────────────────────── */
int main(void)
{
    /* Suppress kernel RSTs — nothing is listening on SRC_PORT at OS level */
    system("iptables -A OUTPUT -p tcp --tcp-flags RST RST"
           " -d " DST_IP " --sport 54322 -j DROP");

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); goto done; }

    /* ── Request TPACKET_V2 ──────────────────────────────────────────────── */
    int ver = TPACKET_V2;
    if (setsockopt(sock, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver)) < 0) {
        perror("PACKET_VERSION"); goto done;
    }

    /* ── Set up TX and RX rings ──────────────────────────────────────────── */
    struct tpacket_req req = {
        .tp_block_size = TP_BLOCK_SIZE,
        .tp_block_nr   = TP_BLOCK_NR,
        .tp_frame_size = TP_FRAME_SIZE,
        .tp_frame_nr   = TP_FRAME_NR,
    };
    if (setsockopt(sock, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req)) < 0) {
        perror("PACKET_TX_RING"); goto done;
    }
    if (setsockopt(sock, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
        perror("PACKET_RX_RING"); goto done;
    }

    /*
     * ── mmap both rings in a single call ─────────────────────────────────
     * Layout: [ TX ring : TP_RING_BYTES ][ RX ring : TP_RING_BYTES ]
     * This is a shared mapping — the kernel's packet engine and our process
     * share the same physical pages.  No copy ever crosses this boundary.
     */
    uint8_t *ring = mmap(NULL, 2 * TP_RING_BYTES,
                         PROT_READ | PROT_WRITE,
                         MAP_SHARED,
                         sock, 0);
    if (ring == MAP_FAILED) { perror("mmap"); goto done; }

    /* Kernel mmap layout: RX ring at offset 0, TX ring immediately after */
    uint8_t *rx_ring = ring;
    uint8_t *tx_ring = ring + TP_RING_BYTES;

    fprintf(stderr,
            "[MMAP]  tx_ring=%p  rx_ring=%p\n"
            "[MMAP]  ring=%zu KiB each  frame_slots=%d  TPHDR_LEN=%zu\n",
            tx_ring, rx_ring,
            (size_t)TP_RING_BYTES / 1024, TP_FRAME_NR, (size_t)TPHDR_LEN);

    /* ── Bind to interface ───────────────────────────────────────────────── */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, IFACE, IFNAMSIZ-1);
    ioctl(sock, SIOCGIFINDEX, &ifr);

    struct sockaddr_ll sll = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex  = ifr.ifr_ifindex,
    };
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind"); goto munmap;
    }

    int tx_idx = 0, rx_idx = 0;
    struct iphdr  *rip;
    struct tcphdr *rtcp;
    uint8_t       *rdata;
    int            rdlen;

    uint32_t isn = 0xCAFEBABE;
    uint32_t seq = isn, ack = 0;

    /* ── SYN ─────────────────────────────────────────────────────────────── */
    fprintf(stderr, "[TCP]   SYN  seq=%u\n", seq);
    tx_send(tx_ring, &tx_idx, sock, seq, 0, 0x02, NULL, 0);
    seq++;

    /* ── SYN-ACK ─────────────────────────────────────────────────────────── */
    for (;;) {
        struct tpacket2_hdr *hdr = rx_wait(rx_ring, &rx_idx, sock);
        if (!hdr) { fprintf(stderr, "timeout waiting for SYN-ACK\n"); goto munmap; }

        uint8_t *f = (uint8_t *)hdr + hdr->tp_mac;
        int      n = hdr->tp_len;

        if (our_pkt(f, n, &rip, &rtcp, &rdata, &rdlen)
            && rtcp->syn && rtcp->ack) {
            ack = ntohl(rtcp->seq) + 1;
            fprintf(stderr, "[TCP]   SYN-ACK  server_isn=%u  ack=%u\n",
                    ntohl(rtcp->seq), ack);
            rx_release(rx_ring, &rx_idx);
            break;
        }
        rx_release(rx_ring, &rx_idx);
    }

    /* ── ACK ─────────────────────────────────────────────────────────────── */
    tx_send(tx_ring, &tx_idx, sock, seq, ack, 0x10, NULL, 0);
    fprintf(stderr, "[TCP]   ACK  (ESTABLISHED)\n");

    /* ── PSH+ACK: HTTP GET ───────────────────────────────────────────────── */
    int glen = (int)strlen(HTTP_GET);
    tx_send(tx_ring, &tx_idx, sock, seq, ack, 0x18, HTTP_GET, glen);
    seq += glen;
    fprintf(stderr, "[TCP]   PSH+ACK  %d bytes HTTP request\n", glen);

    /* ── Data receive loop ───────────────────────────────────────────────── */
    for (;;) {
        struct tpacket2_hdr *hdr = rx_wait(rx_ring, &rx_idx, sock);
        if (!hdr) break;

        uint8_t *f = (uint8_t *)hdr + hdr->tp_mac;
        int      n = hdr->tp_len;

        if (!our_pkt(f, n, &rip, &rtcp, &rdata, &rdlen)) {
            rx_release(rx_ring, &rx_idx); continue;
        }

        if (rdlen > 0) {
            /* Read directly from ring buffer — zero copy */
            fwrite(rdata, 1, rdlen, stdout);
            fflush(stdout);
            ack = ntohl(rtcp->seq) + rdlen;
            tx_send(tx_ring, &tx_idx, sock, seq, ack, 0x10, NULL, 0);
            fprintf(stderr, "[TCP]   ACK %d bytes  ack=%u\n", rdlen, ack);
        }

        if (rtcp->fin) {
            ack++;
            tx_send(tx_ring, &tx_idx, sock, seq, ack, 0x11, NULL, 0);
            fprintf(stderr, "[TCP]   FIN-ACK (CLOSED)\n");
            rx_release(rx_ring, &rx_idx);
            break;
        }
        if (rtcp->rst) { fprintf(stderr, "[TCP]   RST\n"); rx_release(rx_ring, &rx_idx); break; }

        rx_release(rx_ring, &rx_idx);
    }

munmap:
    munmap(ring, 2 * TP_RING_BYTES);
done:
    if (sock >= 0) close(sock);
    system("iptables -D OUTPUT -p tcp --tcp-flags RST RST"
           " -d " DST_IP " --sport 54322 -j DROP");
    return 0;
}
