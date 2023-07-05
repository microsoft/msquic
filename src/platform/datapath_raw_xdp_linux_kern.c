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
    .max_entries = 64,  // Assume netdev has no more than 64 queues
};

struct bpf_map_def SEC("maps") port_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u16), // port
    .value_size = sizeof(bool),
    .max_entries = 64,
};

struct bpf_map_def SEC("maps") ifname_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = IFNAMSIZ,
    .max_entries = 1,
};

// TODO: dump flag map?

static __always_inline bool dump(struct xdp_md *ctx, void *data, void *data_end) {
    int index = ctx->rx_queue_index;
    char* ifname = NULL;
    ifname = bpf_map_lookup_elem(&ifname_map, &index);
    if (ifname) {
        bpf_printk("========> To ifacename : %s", ifname);
    }

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return false;
    }

    bpf_printk("\tSRC: %02x:%02x:%02x", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
    bpf_printk("\t     %02x:%02x:%02x", eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    bpf_printk("\tDST: %02x:%02x:%02x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
    bpf_printk("\t     %02x:%02x:%02x", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    bpf_printk("\tEther[%d]", data_end - data);

    struct iphdr *iph = 0;
    struct ipv6hdr *ip6h = 0;
    struct udphdr *udph = 0;
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        iph = (struct iphdr *)(eth + 1);
        if ((void*)(iph + 1) > data_end) {
            bpf_printk("\t\t\tip header violate size");
            return false;
        }

        __u32 src_ip = bpf_ntohl(iph->saddr);
        __u32 dst_ip = bpf_ntohl(iph->daddr);
        bpf_printk("\t\tis ipv4 [%d]", bpf_ntohs(iph->tot_len));
        bpf_printk("\t\t\tsrc: 192.%u.%u.%u",
                (iph->saddr >> 8) & 0xff,
                (iph->saddr >> 16) & 0xff, iph->saddr >> 24);
        bpf_printk("\t\t\tdst: 192.%u.%u.%u",
                (iph->daddr >> 8) & 0xff,
                (iph->daddr >> 16) & 0xff, iph->daddr >> 24);

        if (iph->protocol != IPPROTO_UDP) {
            bpf_printk("\t\t\tnot UDP %d", iph->protocol);
            return false;
        }
        udph = (struct udphdr *)(iph + 1);
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        ip6h = (struct ipv6hdr *)(eth + 1);
        if ((void*)(ip6h + 1) > data_end) {
            bpf_printk("\t\t\tipv6 header violate size");
            return false;
        }
        bpf_printk("\t\tis ipv6");
        bpf_printk("\t\t\tsrc: %x::%x:%x",
            bpf_ntohs(ip6h->saddr.s6_addr16[0]), bpf_ntohs(ip6h->saddr.s6_addr16[6]), bpf_ntohs(ip6h->saddr.s6_addr16[7]));
        bpf_printk("\t\t\tdst: %x::%x:%x",
            bpf_ntohs(ip6h->daddr.s6_addr16[0]), bpf_ntohs(ip6h->daddr.s6_addr16[6]), bpf_ntohs(ip6h->daddr.s6_addr16[7]));

        if (ip6h->nexthdr != IPPROTO_UDP) {
            bpf_printk("\t\t\tnot UDP %d", ip6h->nexthdr);
            return false;
        }
        udph = (struct udphdr *)(ip6h + 1);
    } else {
        bpf_printk("\t\tnot IP");
        return false;
    }
    if ((void*)(udph + 1) > data_end) {
        bpf_printk("\t\tUDP header violate size");
        return false;
    }
    bpf_printk("\t\t\t\tUDP: SRC: %d DST:%d", bpf_htons(udph->source), bpf_htons(udph->dest));
    if ((void*)(udph + 1) <= data_end) {
        unsigned char* payload = (unsigned char*)(udph + 1);
        if ((void*)(payload + 12) <= data_end) {
            bpf_printk("\t\tPaylod[%d]", data_end - (void*)payload);
            for (int i = 0; i < 12; i += 3) {
                bpf_printk("\t\t%02x %02x %02x", payload[i], payload[i+1], payload[i+2]);
            }
        }
    }

    bool *exist = bpf_map_lookup_elem(&port_map, (__u16*)&udph->dest); // slow?
    if (exist && *exist) {
        bpf_printk("\t\t\tport match:%d", bpf_htons(udph->dest));
        bpf_printk("\t\t\t\tredirect to service");
        bpf_printk("");
        return true;
    }
    bpf_printk("========> Pass through\n");

    return false;
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
    if (to_quic_service(ctx, data, data_end)) {
        if (bpf_map_lookup_elem(&xsks_map, &index)) {
            return bpf_redirect_map(&xsks_map, index, 0);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
