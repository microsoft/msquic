/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    eBPF program for Linux XDP Implementation

--*/

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

#include <bpf_helpers.h>
#include <bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 64);
} xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __type(key, __u32);
    __type(value, struct bpf_cpumap_val);
    __uint(max_entries, 8);
} cpu_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, bool);
    __uint(max_entries, 64);
} port_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, char[IFNAMSIZ]);
    __uint(max_entries, 1);
} ifname_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, __u8[16]);
    __uint(max_entries, 2); // 0: ipv4, 1: ipv6
} ip_map SEC(".maps");

static const __u32 ipv4_key = 0;
static const __u32 ipv6_key = 1;
static const int KEYZERO = 0; // just for single element array

#define IS_SHORT_HEADER(x) ((x & 0x80) != 0x80)
#define MAX_CONNECTION_ID_LENGTH 20
#define RX_QUEUE_UNDEFINED 0xff
// TODO: need to be variable len
//       cid_len_map have the len, but __builtin_memcpy seems requiring constant length
#define MSQUIC_FIXED_CONNECTION_ID_LENGTH 9

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, __u8);
    __uint(max_entries, 1);
} cid_len_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8[MAX_CONNECTION_ID_LENGTH]);
    __type(value, __u8);
    __uint(max_entries, 1024); // TODO: more
} cid_queue_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int); // 0: client, 1:server
    __type(value, __u8); // 1 set
    __uint(max_entries, 2);
} role_map SEC(".maps");

#define XDP_FEATURE_CID_MAP_RSS         0x01 // map based RSS (use cid_queue_map)
#define XDP_FEATURE_DROP_PATH_CHALLENGE 0x02
#define XDP_FEATURE_NORMAL_DATAPATH     0x04 // if not set, use XDP datapath
#define XDP_FEATURE_CID_HASH_RSS        0x08 // hash based RSS (use hash function)

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, __u8);
    __uint(max_entries, 1);
} feature_map SEC(".maps");
#define FEATURE_SUPPORT(f) ((*feature & f) == f)

static __always_inline int parse_quic_varint(unsigned char **data, void *data_end, __u64 *value) {
    unsigned char *ptr = *data;
    if (ptr + 1 > data_end)
        return -1;

    __u8 first_byte = ptr[0];
    __u8 prefix = first_byte >> 6; // First 2 bits for prefix
    __u8 varint_len;

    if (prefix == 0) {
        varint_len = 1;
    } else if (prefix == 1) {
        varint_len = 2;
    } else if (prefix == 2) {
        varint_len = 4;
    } else if (prefix == 3) {
        varint_len = 8;
    } else {
        return -1;
    }

    if (ptr + varint_len > data_end)
        return -1;

    if (varint_len == 1) {
        *value = first_byte & 0x3F; // Use only 6 bits
        ptr += 1;
    } else if (varint_len == 2) {
        *value = ((__u16)(first_byte & 0x3F) << 8) | ptr[1];
        ptr += 2;
    } else if (varint_len == 4) {
        *value = ((__u32)(first_byte & 0x3F) << 24) |
                 (ptr[1] << 16) |
                 (ptr[2] << 8) |
                 ptr[3];
        ptr += 4;
    } else if (varint_len == 8) {
        *value = ((__u64)(first_byte & 0x3F) << 56) |
                 ((__u64)ptr[1] << 48) |
                 ((__u64)ptr[2] << 40) |
                 ((__u64)ptr[3] << 32) |
                 ((__u64)ptr[4] << 24) |
                 ((__u64)ptr[5] << 16) |
                 ((__u64)ptr[6] << 8) |
                 ((__u64)ptr[7]);
        ptr += 8;
    } else {
        return -1;
    }

    *data = ptr;
    return 0;
}

static __always_inline unsigned char* get_dest_cid(unsigned char *payload, void *data_end, __u8 *cid_len) {
    if (payload + 1 > data_end)
        return NULL;

    if (IS_SHORT_HEADER(payload[0])) {
        *cid_len = MSQUIC_FIXED_CONNECTION_ID_LENGTH; // TODO: variable length
        if (payload + 1 + *cid_len > data_end)
            return NULL;
        return payload + 1;
    } else {
        unsigned char *ptr = payload + 1;

        // Skip Version field (4 bytes)
        if (ptr + 4 > data_end)
            return NULL;
        ptr += 4;

        // Get Destination Connection ID Length
        __u64 dcid_len = 0;
        if (parse_quic_varint(&ptr, data_end, &dcid_len) < 0)
            return NULL;

        if (dcid_len > MAX_CONNECTION_ID_LENGTH)
            return NULL;

        // get Destination Connection ID
        if (ptr + dcid_len > data_end)
            return NULL;
        unsigned char *dcid = ptr;
        ptr += dcid_len;

        // Source Connection ID

        *cid_len = (__u8)dcid_len;
        return dcid;
    }
}

// #ifdef DEBUG

char EthDump[128] = {0};
char IpDump[256] = {0};
char UdpHeader[256] = {0};
char UdpDump[256] = {0};
char QuicDump[256] = {0};

// This is for debugging purpose
static __always_inline void dump(struct xdp_md *ctx, void *data, void *data_end) {
    int RxIndex = ctx->rx_queue_index;
    char* ifname = bpf_map_lookup_elem(&ifname_map, &KEYZERO);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return;
    }
    char EthSrc[3*ETH_ALEN] = {0};
    char EthDst[3*ETH_ALEN] = {0};
    BPF_SNPRINTF(EthSrc, sizeof(EthSrc), "%02x:%02x:%02x:%02x:%02x:%02x",
        eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    BPF_SNPRINTF(EthDst, sizeof(EthDst), "%02x:%02x:%02x:%02x:%02x:%02x",
        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    BPF_SNPRINTF(EthDump, sizeof(EthDump), "\tEth[%d]\tSRC: %s => DST:%s", data_end - data, EthSrc, EthDst);

    bool IpMatch = true;
    struct iphdr *iph = 0;
    struct ipv6hdr *ip6h = 0;
    struct udphdr *udph = 0;
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        iph = (struct iphdr *)(eth + 1);
        if ((void*)(iph + 1) > data_end) {
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

        __u32 *ipv4_addr = bpf_map_lookup_elem(&ip_map, &ipv4_key);
        IpMatch = ipv4_addr && *ipv4_addr == iph->daddr;

        if (iph->protocol != IPPROTO_UDP) {
            return;
        }
        udph = (struct udphdr *)(iph + 1);
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        ip6h = (struct ipv6hdr *)(eth + 1);
        if ((void*)(ip6h + 1) > data_end) {
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

        __u32 *ipv6_addr = bpf_map_lookup_elem(&ip_map, &ipv6_key);
        if (ipv6_addr) {
            for (int i = 0; i < 4; i++) {
                if (ipv6_addr[i] != ip6h->daddr.s6_addr32[i]) {
                    IpMatch = false;
                    break;
                }
            }
        }

        if (ip6h->nexthdr != IPPROTO_UDP) {
            return;
        }
        udph = (struct udphdr *)(ip6h + 1);
    } else {
        return;
    }
    if ((void*)(udph + 1) > data_end) {
        return;
    }

    bool CIDMatch = false;
    if ((void*)(udph + 1) <= data_end) {
        unsigned char* payload = (unsigned char*)(udph + 1);
        BPF_SNPRINTF(UdpHeader, sizeof(UdpHeader), "\t\t\tUDP[%d]: SRC: %d DST:%d", data_end - (void*)payload, bpf_htons(udph->source), bpf_htons(udph->dest));
        if ((void*)(payload + 1 + MAX_CONNECTION_ID_LENGTH) <= data_end) {
            BPF_SNPRINTF(UdpDump, sizeof(UdpDump),
                    "\t\t\t\t [%02x %02x %02x %02x %02x %02x "
                            "%02x %02x %02x %02x %02x %02x]",
                        payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                        payload[6], payload[7], payload[8], payload[9], payload[10], payload[11]);
            if (IS_SHORT_HEADER(payload[0])) {
                __u8* cid_len = bpf_map_lookup_elem(&cid_len_map, &KEYZERO);
                if (cid_len && *cid_len <= MAX_CONNECTION_ID_LENGTH && (void*)(payload + 1 + *cid_len) <= data_end) {
                    // TODO: This can be global variable and fill 0 once if Dest CID len is fixed in associated process
                    __u8 key[MAX_CONNECTION_ID_LENGTH] = {0};
                    __builtin_memcpy(key, payload + 1, MSQUIC_FIXED_CONNECTION_ID_LENGTH);
                    // __builtin_memcpy(key, payload + 1, *cid_len);
                    __u8 *queue = bpf_map_lookup_elem(&cid_queue_map, key);
                    CIDMatch = queue != NULL;
                }
                BPF_SNPRINTF(QuicDump, sizeof(QuicDump),
                        "\t\t\t\t\t SH Dest CID: [%02x %02x %02x %02x %02x %02x %02x %02x %02x]",
                            payload[1], payload[2], payload[3], payload[4], payload[5],
                            payload[6], payload[7], payload[8], payload[9]);
            } else {
                __u8 cid_len = 0;
                unsigned char* dcid = get_dest_cid(payload, data_end, &cid_len);
                if (dcid && (void*)(dcid + 9) <= data_end) {
                    BPF_SNPRINTF(QuicDump, sizeof(QuicDump),
                        "\t\t\t\t\t LH Dest CID: [%d] [%02x %02x %02x %02x %02x %02x %02x %02x %02x]",
                            cid_len, dcid[0], dcid[1], dcid[2], dcid[3], dcid[4], dcid[5], dcid[6], dcid[7], dcid[8]);                
                }
            }
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
    if (IpMatch /*&& PortMatch*/ && SocketExists && Redirection == XDP_REDIRECT) {
        int roleKey = 1;
        __u8* server = bpf_map_lookup_elem(&role_map, &roleKey);
        roleKey = 0;
        __u8* client = bpf_map_lookup_elem(&role_map, &roleKey);
        if (server && client) {
            bpf_printk("========> To ifacename : [%s], Server:%d Client:%d RxQueueID:%d", ifname, *server, *client, RxIndex);
        } else {
            bpf_printk("========> To ifacename : [%s], Server:? Client:? RxQueueID:%d", ifname, RxIndex);
        }
        bpf_printk("%s", EthDump);
        bpf_printk("%s", IpDump);
        bpf_printk("%s", UdpHeader);
        bpf_printk("%s", UdpDump);
        bpf_printk("%s", QuicDump);
        bpf_printk("\t\t\tRedirect to QUIC service. CIDMatch:%d, IpMatch:%d, PortMatch:%d, SocketExists:%d, Redirection:%d", CIDMatch, IpMatch, PortMatch, SocketExists, Redirection);
    } else {
        // bpf_printk("\t\t\tPass through packet.       IpMatch:%d, PortMatch:%d, SocketExists:%d, Redirection:%d", IpMatch, PortMatch, SocketExists, Redirection);
    }
}

// #endif

// Validates packet whether it is really to user space quic service
// return true if valid Ethernet, IPv4/6, UDP header and destination port
static __always_inline enum xdp_action to_af_xdp(struct xdp_md *ctx, void *data, void *data_end, int *RxIndex, __u8* feature) {
    struct ethhdr *eth = data;
    // boundary check
    if ((void *)(eth + 1) > data_end) {
        return XDP_DROP;
    }

    struct iphdr *iph = 0;
    struct ipv6hdr *ip6h = 0;
    struct udphdr *udph = 0;
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        iph = (struct iphdr *)(eth + 1);
        // boundary check
        if ((void*)(iph + 1) > data_end) {
            return XDP_DROP;
        }

        // check if the destination IP address matches
        __u32 *ipv4_addr = bpf_map_lookup_elem(&ip_map, &ipv4_key);
        if (ipv4_addr && *ipv4_addr != iph->daddr) {
            return XDP_PASS;
        }
        if (iph->protocol != IPPROTO_UDP) {
            return XDP_PASS;
        }
        udph = (struct udphdr *)(iph + 1);
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        ip6h = (struct ipv6hdr *)(eth + 1);
        // boundary check
        if ((void*)(ip6h + 1) > data_end) {
            return XDP_DROP;
        }

        // check if the destination IP address matches
        __u32 *ipv6_addr = bpf_map_lookup_elem(&ip_map, &ipv6_key);
        if (ipv6_addr) {
            for (int i = 0; i < 4; i++) {
                if (ipv6_addr[i] != ip6h->daddr.s6_addr32[i]) {
                    return XDP_PASS;
                }
            }
        }

        if (ip6h->nexthdr != IPPROTO_UDP) {
            return XDP_PASS;
        }
        udph = (struct udphdr *)(ip6h + 1);
    } else {
        return XDP_PASS;
    }
    // boundary check
    if ((void*)(udph + 1) > data_end) {
        return XDP_DROP;
    }

    // hack. catch packet to client
    if (udph->dest == bpf_htons(55555)) {
        if (FEATURE_SUPPORT(XDP_FEATURE_DROP_PATH_CHALLENGE)) {
            int roleKey = 0;
            __u8* client = bpf_map_lookup_elem(&role_map, &roleKey);
            if (client && *client == 1) {
                bpf_printk("Drop PATH_CHALLENGE frame from server to client");
                return XDP_DROP;
            }
        } else {
            // TODO: NAT conversion?, change back to original port
        }
    }

    bool *exist = bpf_map_lookup_elem(&port_map, (__u16*)&udph->dest); // slow?
    if (exist && *exist) {
        // bpf_printk("\t\t\t\t\t [XDP] port found %d", bpf_htons(udph->dest));
        unsigned char* payload = (unsigned char*)(udph + 1);
        if ((void*)(payload + 1 + MAX_CONNECTION_ID_LENGTH) <= data_end && IS_SHORT_HEADER(payload[0])) {
            if (FEATURE_SUPPORT(XDP_FEATURE_CID_MAP_RSS)) {
                __u8* cid_len = bpf_map_lookup_elem(&cid_len_map, &KEYZERO);
                if (cid_len && *cid_len <= MAX_CONNECTION_ID_LENGTH && (void*)(payload + 1 + *cid_len) <= data_end) {
                    // TODO: This can be global variable and fill 0 once if Dest CID len is fixed in associated process
                    __u8 key[MAX_CONNECTION_ID_LENGTH] = {0};
                    __builtin_memcpy(key, payload + 1, MSQUIC_FIXED_CONNECTION_ID_LENGTH);
                    __u8 *queue = bpf_map_lookup_elem(&cid_queue_map, key);
                    if (queue) {
                        if (*queue == RX_QUEUE_UNDEFINED) {
                            bpf_map_update_elem(&cid_queue_map, key, RxIndex, BPF_ANY);
                            bpf_printk("\t\t\t\t\t [XDP] Connection ID found, Set QueueID:%d", *RxIndex);
                        } else {
                            *RxIndex = *queue;
                            bpf_printk("\t\t\t\t\t [XDP] Connection ID found, Redirect from QueueID:%d to QueueID:%d", ctx->rx_queue_index, *queue);
                        }
                    }
                }
            } else if (FEATURE_SUPPORT(XDP_FEATURE_CID_HASH_RSS)) {
                // TODO: hash based RSS
            }
        }
        return XDP_REDIRECT;
    }
    return XDP_PASS;
}

static __always_inline enum xdp_action to_epoll(struct xdp_md *ctx, void *data, void *data_end, int *Cpu, __u8* feature) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_DROP;
    }

    struct iphdr *iph = 0;
    struct ipv6hdr *ip6h = 0;
    struct udphdr *udph = 0;
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        iph = (struct iphdr *)(eth + 1);
        if ((void*)(iph + 1) > data_end) {
            return XDP_DROP;
        }
        if (iph->protocol != IPPROTO_UDP) {
            return XDP_PASS;
        }
        udph = (struct udphdr *)(iph + 1);
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        ip6h = (struct ipv6hdr *)(eth + 1);
        if ((void*)(ip6h + 1) > data_end) {
            return XDP_DROP;
        }
        if (ip6h->nexthdr != IPPROTO_UDP) {
            return XDP_PASS;
        }
        udph = (struct udphdr *)(ip6h + 1);
    } else {
        return XDP_PASS;
    }
    if ((void*)(udph + 1) > data_end) {
        return XDP_DROP;
    }

    unsigned char* payload = (unsigned char*)(udph + 1);
    if ((void*)(payload + 1) <= data_end && IS_SHORT_HEADER(payload[0])) {
        if (FEATURE_SUPPORT(XDP_FEATURE_CID_MAP_RSS)) {
            if ((void*)(payload + 1 + MAX_CONNECTION_ID_LENGTH) <= data_end && IS_SHORT_HEADER(payload[0])) {
                __u8 key[MAX_CONNECTION_ID_LENGTH] = {0};
                __builtin_memcpy(key, payload + 1, MSQUIC_FIXED_CONNECTION_ID_LENGTH);
                __u8 *queue = bpf_map_lookup_elem(&cid_queue_map, key);
                if (queue) {
                    if (*queue == RX_QUEUE_UNDEFINED) {
                        bpf_map_update_elem(&cid_queue_map, key, Cpu, BPF_ANY);
                        // bpf_printk("\t\t\t\t\t [EPOLL] Connection ID found, Set CPU:%d", *Cpu);
                    } else {
                        if (*Cpu != *queue) {
                            // bpf_printk("\t\t\t\t\t [EPOLL] Connection ID found, Redirect from CPU:%d to CPU:%d", *Cpu, *queue);
                            *Cpu = *queue;
                            return XDP_REDIRECT;
                        }
                    }
                }
            }
        }
    }
    else if (FEATURE_SUPPORT(XDP_FEATURE_CID_HASH_RSS)) {
        bpf_printk("\t\t\t\t\t [EPOLL] CID_HASH_RSS");
    }

    return XDP_PASS;
}

static __always_inline enum xdp_action do_xdp_action(struct xdp_md *ctx, void *data, void *data_end, int *RxIndex)
{
    __u8* feature = bpf_map_lookup_elem(&feature_map, &KEYZERO);
    if (!feature) {
        return XDP_PASS;
    }

    enum xdp_action action = XDP_PASS;
    if (FEATURE_SUPPORT(XDP_FEATURE_NORMAL_DATAPATH)) {
        int cpu = bpf_get_smp_processor_id();
        action = to_epoll(ctx, data, data_end, &cpu, feature);
        if (action == XDP_REDIRECT) {
            // bpf_printk("Redirect to cpu:%d", cpu);
            return bpf_redirect_map(&cpu_map, cpu, 0);
        }
    } else {
        action = to_af_xdp(ctx, data, data_end, RxIndex, feature);
        if (action == XDP_REDIRECT) {
            if (bpf_map_lookup_elem(&xsks_map, RxIndex)) {
                // bpf_printk("Redirect to RxQueueID:%d", *RxIndex);
                return bpf_redirect_map(&xsks_map, *RxIndex, 0);
            } else {
                // bpf_printk("Redirect failed. No socket found for RxQueueID:%d", *RxIndex);
            }
        }
    }
    if (action == XDP_DROP) {
        return XDP_DROP;
    }
    return XDP_PASS;
}

SEC("xdp_prog")
int xdp_main(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;
    void *data_end = (void*)(long)ctx->data_end;
    void *data = (void*)(long)ctx->data;
// #ifdef DEBUG
    // dump(ctx, data, data_end);
// #endif
    return do_xdp_action(ctx, data, data_end, &index);
}

char _license[] SEC("license") = "GPL";
