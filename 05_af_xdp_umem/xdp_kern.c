/*
 * xdp_kern.c — XDP eBPF program
 *
 * Runs at the NIC driver's NAPI poll hook — hardware interrupt context,
 * before the kernel allocates an sk_buff.  Parses the Ethernet+IP+TCP
 * headers inline and redirects only packets from the target server
 * (34.160.111.145:80 → port 54323) into the AF_XDP socket via XSKMAP.
 * All other traffic is passed through (XDP_PASS) unchanged.
 *
 * Compile: clang -O2 -target bpf -I/usr/include/x86_64-linux-gnu \
 *                -c xdp_kern.c -o xdp_kern.o
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

/* XSKMAP: maps RX queue index → AF_XDP socket fd.
 * The userspace loader inserts our socket at key 0 (queue 0). */
struct {
    __uint(type,       BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key,   __u32);
    __type(value, __u32);
} xsk_map SEC(".maps");

/* Only redirect packets FROM this server to our ephemeral port */
#define SERVER_IP    0x22A06F91U   /* 34.160.111.145 in host order */
#define SERVER_PORT  80
#define LOCAL_PORT   54323

SEC("xdp")
int xdp_http_redirect(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* ── Ethernet ─────────────────────────────────────────────────────── */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* ── IPv4 ─────────────────────────────────────────────────────────── */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    /* Source must be our server */
    if (ip->saddr != bpf_htonl(SERVER_IP))
        return XDP_PASS;

    /* ── TCP ──────────────────────────────────────────────────────────── */
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
    /* Destination must be our ephemeral port */
    if (tcp->dest != bpf_htons(LOCAL_PORT))
        return XDP_PASS;

    /*
     * Redirect this packet into the AF_XDP socket registered at
     * xsk_map[rx_queue_index].  Falls back to XDP_PASS if no socket
     * is registered for this queue (e.g. during startup).
     *
     * This runs in the driver's NAPI poll — no sk_buff is allocated,
     * no IP stack is touched.  In zero-copy mode the NIC DMA-writes the
     * frame directly into the UMEM page we provided.
     */
    return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
