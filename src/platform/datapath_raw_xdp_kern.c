/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <stdbool.h>

struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 64,  /* Assume netdev has no more than 64 queues */
};

struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(int),
	.value_size  = sizeof(__u32),
	.max_entries = 64,
};

// TODO: set port number from app
#define UDP_SERVER_PORT 8080

static __always_inline bool to_quic_service(struct xdp_md *ctx, void *data, void *data_end) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return false;
    bpf_printk("\tis ether\n");

    struct iphdr *iph = 0;
    struct ipv6hdr *ip6h = 0;
    struct udphdr *udph = 0;
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        bpf_printk("\tis ipv4\n");
        iph = (struct iphdr *)(eth + 1);
        if (iph + 1 > data_end) {
            return false;
        }
        if (iph->protocol != IPPROTO_UDP) {
            return false;
        }
        udph = (struct udphdr *)(iph + 1);
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        bpf_printk("\tis ipv6\n");
        ip6h = (struct ipv6hdr *)(eth + 1);
        if (ip6h + 1 > data_end) {
            return false;
        }
        if (ip6h->nexthdr != IPPROTO_UDP) {
            return false;
        }
        udph = (struct udphdr *)(ip6h + 1);
    } else {
        bpf_printk("\tnot IP\n");
        return false;
    }
    if (udph + 1 > data_end) {
        return false;
    }
    return udph->dest == bpf_htons(UDP_SERVER_PORT);
}

SEC("xdp_prog")
int xdp_main(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;
    __u32 *pkt_count;

    pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &index);
    if (pkt_count) {
        bpf_printk("Packet %d in\n", *pkt_count);
        pkt_count++;
    }

    void *data_end = (void*)(long)ctx->data_end;
    void *data = (void*)(long)ctx->data;
    if (to_quic_service(ctx, data, data_end)) {
        bpf_printk("\tIs UDP:%d\n", UDP_SERVER_PORT);
        if (bpf_map_lookup_elem(&xsks_map, &index)) {
            bpf_printk("\tredirect to service\n");
            return bpf_redirect_map(&xsks_map, index, 0);
        }        
    }

    bpf_printk("\tDo nothing\n");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
