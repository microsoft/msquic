/* SPDX-License-Identifier: GPL-2.0 */

#include "/home/azureuser/workspace/msquic/submodules/xdp-tools/lib/libbpf/include/uapi/linux/bpf.h"
#include "/home/azureuser/workspace/msquic/submodules/xdp-tools/lib/libbpf/src/bpf_helpers.h"
#include "/home/azureuser/workspace/msquic/submodules/xdp-tools/lib/libbpf/src/bpf_endian.h"

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <stdbool.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 64);
} xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, bool);
    __uint(max_entries, 64);
} port_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, char*);
    __uint(max_entries, 1);
} ifname_map SEC(".maps");

// TODO: dump flag map?
// NOTE: divisible by 4
#define DUMP_PAYLOAD_SIZE 12
char EthDump[128] = {0};
char IpDump[256] = {0};
char UdpHeader[256] = {0};
char UdpDump[256] = {0};

static __always_inline void dump(struct xdp_md *ctx, void *data, void *data_end) {
    int RxIndex = ctx->rx_queue_index;
    char* ifname = NULL;
    ifname = bpf_map_lookup_elem(&ifname_map, &RxIndex);
    bool isTarget = false;

    if (ifname) {
        // bpf_printk("========> To ifacename : [%s], RxQueueID:%d", ifname, RxIndex);
    }

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_printk("\tEth header size violation");
        return;
    }
    char EthSrc[3*ETH_ALEN] = {0};
    char EthDst[3*ETH_ALEN] = {0};
    BPF_SNPRINTF(EthSrc, sizeof(EthSrc), "%02x:%02x:%02x:%02x:%02x:%02x",
        eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    BPF_SNPRINTF(EthDst, sizeof(EthDst), "%02x:%02x:%02x:%02x:%02x:%02x",
        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    BPF_SNPRINTF(EthDump, sizeof(EthDump), "\tEth[%d]\tSRC: %s => DST:%s", data_end - data, EthSrc, EthDst);

    struct iphdr *iph = 0;
    struct ipv6hdr *ip6h = 0;
    struct udphdr *udph = 0;
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        iph = (struct iphdr *)(eth + 1);
        if ((void*)(iph + 1) > data_end) {
            bpf_printk("\t\tipv4 header size violation");
            return;
        }
        __u32 src_ip = bpf_ntohl(iph->saddr);
        __u32 dst_ip = bpf_ntohl(iph->daddr);
        char IP4Src[16] = {0};
        char IP4Dst[16] = {0};
        BPF_SNPRINTF(IP4Src, sizeof(IP4Src), "%d.%d.%d.%d",
            (src_ip >> 24) & 0xff, (src_ip >> 16) & 0xff, (src_ip >> 8) & 0xff, src_ip & 0xff);
        BPF_SNPRINTF(IP4Dst, sizeof(IP4Dst), "%d.%d.%d.%d",
            (dst_ip >> 24) & 0xff, (dst_ip >> 16) & 0xff, (dst_ip >> 8) & 0xff, dst_ip & 0xff);
        BPF_SNPRINTF(IpDump, sizeof(IpDump), "\t\tIpv4 TotalLen:[%d]\tSrc: %s => Dst: %s", bpf_ntohs(iph->tot_len), IP4Src, IP4Dst);

        if (iph->protocol != IPPROTO_UDP) {
            // bpf_printk("\t\t\tnot UDP %d", iph->protocol);
            return;
        }
        udph = (struct udphdr *)(iph + 1);
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        ip6h = (struct ipv6hdr *)(eth + 1);
        if ((void*)(ip6h + 1) > data_end) {
            bpf_printk("\t\t\tipv6 header size violation");
            return;
        }
        char IP6Src[64] = {0};
        char IP6Dst[64] = {0};
        BPF_SNPRINTF(IP6Src, sizeof(IP6Src), "%x:%x:%x:%x:%x:%x:%x:%x",
            bpf_ntohs(ip6h->saddr.s6_addr16[0]), bpf_ntohs(ip6h->saddr.s6_addr16[1]), bpf_ntohs(ip6h->saddr.s6_addr16[2]), bpf_ntohs(ip6h->saddr.s6_addr16[3]),
            bpf_ntohs(ip6h->saddr.s6_addr16[4]), bpf_ntohs(ip6h->saddr.s6_addr16[5]), bpf_ntohs(ip6h->saddr.s6_addr16[6]), bpf_ntohs(ip6h->saddr.s6_addr16[7]));
        BPF_SNPRINTF(IP6Dst, sizeof(IP6Dst), "%x:%x:%x:%x:%x:%x:%x:%x",
            bpf_ntohs(ip6h->daddr.s6_addr16[0]), bpf_ntohs(ip6h->daddr.s6_addr16[1]), bpf_ntohs(ip6h->daddr.s6_addr16[2]), bpf_ntohs(ip6h->daddr.s6_addr16[3]),
            bpf_ntohs(ip6h->daddr.s6_addr16[4]), bpf_ntohs(ip6h->daddr.s6_addr16[5]), bpf_ntohs(ip6h->daddr.s6_addr16[6]), bpf_ntohs(ip6h->daddr.s6_addr16[7]));
        BPF_SNPRINTF(IpDump, sizeof(IpDump), "\t\tIpv6 PayloadLen[%d]\tSrc: %s => Dst: %s", bpf_ntohs(ip6h->payload_len), IP6Src, IP6Dst);

        if (ip6h->nexthdr != IPPROTO_UDP) {
            // bpf_printk("\t\t\tnot UDP %d", ip6h->nexthdr);
            return;
        }
        udph = (struct udphdr *)(ip6h + 1);
    } else {
        bpf_printk("\t\tnot IP");
        return;
    }
    if ((void*)(udph + 1) > data_end) {
        bpf_printk("\t\tUDP header size violation");
        return;
    }
    if ((void*)(udph + 1) <= data_end) {
        unsigned char* payload = (unsigned char*)(udph + 1);
        BPF_SNPRINTF(UdpHeader, sizeof(UdpHeader), "\t\t\tUDP[%d]: SRC: %d DST:%d", data_end - (void*)payload, bpf_htons(udph->source), bpf_htons(udph->dest));
        if ((void*)(payload + DUMP_PAYLOAD_SIZE) <= data_end) {
            BPF_SNPRINTF(UdpDump, sizeof(UdpDump),
                    "\t\t\t\t [%02x %02x %02x %02x %02x %02x "
                              "%02x %02x %02x %02x %02x %02x]",
                          payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                          payload[6], payload[7], payload[8], payload[9], payload[10], payload[11]);
        }
    }

    bool PortMatch = false;
    bool SocketExists = false;
    long Redirection = 0;
    bool *exist = bpf_map_lookup_elem(&port_map, (__u16*)&udph->dest);

    PortMatch = exist && *exist;
    SocketExists = bpf_map_lookup_elem(&xsks_map, &RxIndex) != NULL;
    if (SocketExists) {
        Redirection = bpf_redirect_map(&xsks_map, RxIndex, 0);
    }
    if (PortMatch && SocketExists && Redirection == XDP_REDIRECT) {
        bpf_printk("========> To ifacename : [%s], RxQueueID:%d", ifname, RxIndex);
        bpf_printk("%s", EthDump);
        bpf_printk("%s", IpDump);
        bpf_printk("%s", UdpHeader);
        bpf_printk("%s", UdpDump);
        bpf_printk("\t\t\tRedirect to QUIC service.  PortMatch:%d, SocketExists:%d, Redirection:%d\n", PortMatch, SocketExists, Redirection);
    } else {
        // bpf_printk("\t\t\tPass through packet.       PortMatch:%d, SocketExists:%d, Redirection:%d", PortMatch, SocketExists, Redirection);
    }
}

static __always_inline bool to_quic_service(struct xdp_md *ctx, void *data, void *data_end) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return false;
    }

    struct iphdr *iph = 0;
    struct ipv6hdr *ip6h = 0;
    struct udphdr *udph = 0;
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        iph = (struct iphdr *)(eth + 1);
        if ((void*)(iph + 1) > data_end) {
            return false;
        }

        __u32 src_ip = bpf_ntohl(iph->saddr);
        __u32 dst_ip = bpf_ntohl(iph->daddr);
        if (iph->protocol != IPPROTO_UDP) {
            return false;
        }
        udph = (struct udphdr *)(iph + 1);
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        ip6h = (struct ipv6hdr *)(eth + 1);
        if ((void*)(ip6h + 1) > data_end) {
            return false;
        }

        if (ip6h->nexthdr != IPPROTO_UDP) {
            return false;
        }
        udph = (struct udphdr *)(ip6h + 1);
    } else {
        return false;
    }
    if ((void*)(udph + 1) > data_end) {
        return false;
    }

    bool *exist = bpf_map_lookup_elem(&port_map, (__u16*)&udph->dest); // slow?
    if (exist && *exist) {
        return true;
    }
    return false;
}

SEC("xdp_prog")
int xdp_main(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;
    void *data_end = (void*)(long)ctx->data_end;
    void *data = (void*)(long)ctx->data;
    // dump(ctx, data, data_end);
    if (to_quic_service(ctx, data, data_end)) {
        // bpf_printk("to_quic_service:true, queueIx:%d", index);
        if (bpf_map_lookup_elem(&xsks_map, &index)) {
            return bpf_redirect_map(&xsks_map, index, 0);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
