/*
 * raw_ethernet_tcp.c
 *
 * HTTP GET by constructing raw Ethernet frames and implementing the TCP
 * three-way handshake manually.  The kernel TCP/IP stack is bypassed
 * entirely: we open AF_PACKET / SOCK_RAW, craft every Ethernet + IP + TCP
 * header by hand, compute all checksums ourselves, and drive the state
 * machine from CLOSED → SYN_SENT → ESTABLISHED → data → FIN_WAIT.
 *
 * Requires CAP_NET_RAW (run as root / sudo).
 *
 * Network values (hardcoded from `ip route`, `ip addr`, `/proc/net/arp`):
 *   interface : wlp0s20f3
 *   src MAC   : 70:32:17:44:3f:59
 *   gateway   : 44:a5:6e:70:28:54   (next-hop Ethernet dst for all traffic)
 *   src IP    : 10.0.0.9
 *   dst IP    : 34.160.111.145       (ifconfig.me, resolved offline)
 *
 * Compile: gcc -O2 -o raw_ethernet_tcp raw_ethernet_tcp.c
 * Run:     sudo ./raw_ethernet_tcp
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* ── Configuration ─────────────────────────────────────────────────────── */
#define IFACE     "wlp0s20f3"
#define SRC_IP    "10.0.0.9"
#define DST_IP    "34.160.111.145"   /* ifconfig.me */
#define DST_PORT  80
#define SRC_PORT  54321

static uint8_t SRC_MAC[] = {0x70,0x32,0x17,0x44,0x3f,0x59};
static uint8_t GW_MAC[]  = {0x44,0xa5,0x6e,0x70,0x28,0x54};

static const char HTTP_GET[] =
    "GET / HTTP/1.0\r\n"
    "Host: ifconfig.me\r\n"
    "User-Agent: raw-ethernet-tcp/handrolled\r\n"
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

/* TCP checksum over pseudo-header + TCP segment */
static uint16_t tcp_cksum(struct iphdr *ip, struct tcphdr *tcp,
                           const void *payload, int plen)
{
    /* pseudo-header: src_ip dst_ip 0 proto tcp_len */
    uint8_t  pseudo[12];
    uint16_t tcp_len = htons((uint16_t)(sizeof(*tcp) + plen));

    memcpy(pseudo + 0, &ip->saddr, 4);
    memcpy(pseudo + 4, &ip->daddr, 4);
    pseudo[8]  = 0;
    pseudo[9]  = IPPROTO_TCP;
    memcpy(pseudo + 10, &tcp_len, 2);

    /* accumulate over pseudo + header + payload without heap alloc */
    uint32_t s = 0;
    uint16_t *p;
    int       i;

    p = (uint16_t *)pseudo;
    for (i = 0; i < 6; i++) s += p[i];

    p = (uint16_t *)tcp;
    for (i = 0; i < (int)sizeof(*tcp) / 2; i++) s += p[i];

    p = (uint16_t *)payload;
    for (i = 0; i < plen / 2; i++) s += p[i];
    if (plen & 1) s += ((uint8_t *)payload)[plen - 1];

    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return ~s;
}

/* ── Packet builder ─────────────────────────────────────────────────────── */
/* flags: SYN=0x02, ACK=0x10, PSH=0x08, FIN=0x01, RST=0x04                */
static int build_pkt(uint8_t *frame,
                     uint32_t seq, uint32_t ack_seq, uint8_t flags,
                     const void *payload, int plen)
{
    struct ethhdr *eth = (struct ethhdr *) frame;
    struct iphdr  *ip  = (struct iphdr *)  (frame + 14);
    struct tcphdr *tcp = (struct tcphdr *) (frame + 14 + 20);

    /* Ethernet */
    memcpy(eth->h_dest,   GW_MAC,  6);
    memcpy(eth->h_source, SRC_MAC, 6);
    eth->h_proto = htons(ETH_P_IP);

    /* IP */
    memset(ip, 0, 20);
    ip->version  = 4;
    ip->ihl      = 5;
    ip->ttl      = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr    = inet_addr(SRC_IP);
    ip->daddr    = inet_addr(DST_IP);
    ip->tot_len  = htons((uint16_t)(20 + 20 + plen));
    ip->check    = inet_cksum(ip, 20);

    /* TCP */
    memset(tcp, 0, 20);
    tcp->source  = htons(SRC_PORT);
    tcp->dest    = htons(DST_PORT);
    tcp->seq     = htonl(seq);
    tcp->ack_seq = htonl(ack_seq);
    tcp->doff    = 5;
    tcp->window  = htons(65535);
    if (flags & 0x02) tcp->syn = 1;
    if (flags & 0x10) tcp->ack = 1;
    if (flags & 0x08) tcp->psh = 1;
    if (flags & 0x01) tcp->fin = 1;
    if (flags & 0x04) tcp->rst = 1;

    if (plen) memcpy(frame + 14 + 20 + 20, payload, plen);
    tcp->check = 0;
    tcp->check = tcp_cksum(ip, tcp, payload, plen);

    return 14 + 20 + 20 + plen;
}

/* ── Receive filter: is this packet from our server, to our port? ───────── */
static int is_our_pkt(const uint8_t *buf, int n,
                      struct iphdr **ip_out, struct tcphdr **tcp_out,
                      uint8_t **data_out, int *dlen_out)
{
    if (n < 14 + 20 + 20) return 0;
    struct ethhdr *eth = (struct ethhdr *)buf;
    if (ntohs(eth->h_proto) != ETH_P_IP) return 0;

    struct iphdr *ip = (struct iphdr *)(buf + 14);
    if (ip->protocol != IPPROTO_TCP) return 0;
    if (ip->saddr != inet_addr(DST_IP)) return 0;

    int iph = ip->ihl * 4;
    struct tcphdr *tcp = (struct tcphdr *)(buf + 14 + iph);
    if (ntohs(tcp->source) != DST_PORT) return 0;
    if (ntohs(tcp->dest)   != SRC_PORT) return 0;

    int tcph  = tcp->doff * 4;
    int hdrln = 14 + iph + tcph;
    *ip_out   = ip;
    *tcp_out  = tcp;
    *data_out = (uint8_t *)buf + hdrln;
    *dlen_out = n - hdrln;
    return 1;
}

/* ── Main ───────────────────────────────────────────────────────────────── */
int main(void)
{
    /*
     * Block the kernel from sending RST in response to the SYN-ACK it
     * didn't expect (nothing listening on SRC_PORT at OS level).
     */
    system("iptables -A OUTPUT -p tcp --tcp-flags RST RST"
           " -d " DST_IP " --sport " "54321" " -j DROP");

    /* Raw socket at Ethernet layer */
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); goto cleanup; }

    /* Bind to interface */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, IFACE, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); goto cleanup; }

    struct sockaddr_ll sll = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex  = ifr.ifr_ifindex,
    };
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind"); goto cleanup;
    }

    /* 5-second receive timeout */
    struct timeval tv = {5, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t frame[4096], rbuf[65536];
    struct iphdr  *rip;
    struct tcphdr *rtcp;
    uint8_t       *rdata;
    int            rdlen, flen, n;

    uint32_t isn = 0xC0FFEE00;   /* our initial sequence number */
    uint32_t seq = isn;
    uint32_t ack = 0;

    /* ── 1. SYN ─────────────────────────────────────────────────────────── */
    fprintf(stderr, "[TCP] sending SYN  seq=%u\n", seq);
    flen = build_pkt(frame, seq, 0, 0x02, NULL, 0);
    if (sendto(sock, frame, flen, 0,
               (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("sendto SYN"); goto cleanup;
    }
    seq++;   /* SYN consumes one sequence number */

    /* ── 2. Wait for SYN-ACK ────────────────────────────────────────────── */
    while (1) {
        n = recvfrom(sock, rbuf, sizeof(rbuf), 0, NULL, NULL);
        if (n < 0) { perror("recvfrom SYN-ACK"); goto cleanup; }
        if (!is_our_pkt(rbuf, n, &rip, &rtcp, &rdata, &rdlen)) continue;
        if (!rtcp->syn || !rtcp->ack) continue;

        ack = ntohl(rtcp->seq) + 1;   /* server ISN + 1 */
        fprintf(stderr, "[TCP] got SYN-ACK  server_isn=%u  ack=%u\n",
                ntohl(rtcp->seq), ack);
        break;
    }

    /* ── 3. ACK ─────────────────────────────────────────────────────────── */
    flen = build_pkt(frame, seq, ack, 0x10, NULL, 0);
    sendto(sock, frame, flen, 0, (struct sockaddr *)&sll, sizeof(sll));
    fprintf(stderr, "[TCP] sent ACK  (handshake complete)\n");

    /* ── 4. PSH+ACK: HTTP GET ───────────────────────────────────────────── */
    int glen = (int)strlen(HTTP_GET);
    flen = build_pkt(frame, seq, ack, 0x18, HTTP_GET, glen);
    sendto(sock, frame, flen, 0, (struct sockaddr *)&sll, sizeof(sll));
    seq += glen;
    fprintf(stderr, "[TCP] sent PSH+ACK  %d bytes HTTP request\n", glen);

    /* ── 5. Receive data, ACK each segment ──────────────────────────────── */
    while (1) {
        n = recvfrom(sock, rbuf, sizeof(rbuf), 0, NULL, NULL);
        if (n < 0) break;   /* timeout → done */
        if (!is_our_pkt(rbuf, n, &rip, &rtcp, &rdata, &rdlen)) continue;

        if (rdlen > 0) {
            fwrite(rdata, 1, rdlen, stdout);
            fflush(stdout);
            ack = ntohl(rtcp->seq) + rdlen;
            flen = build_pkt(frame, seq, ack, 0x10, NULL, 0);
            sendto(sock, frame, flen, 0, (struct sockaddr *)&sll, sizeof(sll));
            fprintf(stderr, "[TCP] ACKed %d bytes  ack=%u\n", rdlen, ack);
        }

        if (rtcp->fin) {
            ack++;
            /* FIN-ACK */
            flen = build_pkt(frame, seq, ack, 0x11, NULL, 0);
            sendto(sock, frame, flen, 0, (struct sockaddr *)&sll, sizeof(sll));
            fprintf(stderr, "[TCP] got FIN, sent FIN-ACK  (closed)\n");
            break;
        }

        if (rtcp->rst) {
            fprintf(stderr, "[TCP] got RST\n");
            break;
        }
    }

cleanup:
    if (sock >= 0) close(sock);
    system("iptables -D OUTPUT -p tcp --tcp-flags RST RST"
           " -d " DST_IP " --sport " "54321" " -j DROP");
    return 0;
}
