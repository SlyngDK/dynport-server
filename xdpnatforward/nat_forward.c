// +build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_UDP_SIZE 8980
#define MAX_NO_NAT_IPS 10

unsigned int RX_CNT_PROCESSED	= 0;
unsigned int RX_CNT_SOURCE	= 1;
unsigned int RX_CNT_REDIRECT	= 2;
unsigned int RX_CNT_DESTINATION	= 3;


struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(key_size, 1);
	__type(value, __u64);
	__uint(max_entries, 50);
} rx_cnt SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 50);
	__type(key, __be16);
	__type(value, __u64); // packet count
} xdp_stats_proto SEC(".maps");


struct remapping_map {
	int ifindex;
	__u64 smac;
	__be64 dmac;
	__be32 ip;
	__be16 port;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, 4 + 2);// IP + port
	__type(value, struct remapping_map);
	__uint(max_entries, 50);
} destinations SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, 4 + 2);// IP + port
	__type(value, struct remapping_map);
	__uint(max_entries, 50);
} sources SEC(".maps");

struct cidr {
    __be32 ip;
    __be32 netmask;
};

struct settings {
    struct cidr bpf_no_nat_cidr[MAX_NO_NAT_IPS];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, 1);
	__type(value, struct settings);
	__uint(max_entries, 1);
} settings SEC(".maps");

static __always_inline __u16 ip_checksum(unsigned short *buf, int bufsz) {
    unsigned long sum = 0;

    while (bufsz > 1) {
        sum += *buf;
        buf++;
        bufsz -= 2;
    }

    if (bufsz == 1) {
        sum += *(unsigned char *)buf;
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

__attribute__((__always_inline__))
static inline __u16 caludpcsum(struct iphdr *iph, struct udphdr *udph, void *data_end)
{
    __u32 csum_buffer = 0;
    __u16 *buf = (void *)udph;

    // Compute pseudo-header checksum
    csum_buffer += (__u16)iph->saddr;
    csum_buffer += (__u16)(iph->saddr >> 16);
    csum_buffer += (__u16)iph->daddr;
    csum_buffer += (__u16)(iph->daddr >> 16);
    csum_buffer += (__u16)iph->protocol << 8;
    csum_buffer += udph->len;

    // Compute checksum on udp header + payload
    for (int i = 0; i < MAX_UDP_SIZE; i += 2)
    {
        if ((void *)(buf + 1) > data_end)
        {
            break;
        }

        csum_buffer += *buf;
        buf++;
    }

    if ((void *)buf + 1 <= data_end)
    {
        // In case payload is not 2 bytes aligned
        csum_buffer += *(__u8 *)buf;
    }

    __u16 csum = (__u16)csum_buffer + (__u16)(csum_buffer >> 16);
    csum = ~csum;

    return csum;
}

__u8 nat_ip(__be32 addr)
{
    __u8 key = 0;
    struct settings *value = bpf_map_lookup_elem(&settings, &key);
    if(value){
        for(int i = 0; i < MAX_NO_NAT_IPS; i++){
            struct cidr n = value->bpf_no_nat_cidr[i];
            if(n.ip == 0) continue;
            if ((bpf_ntohl(addr) & n.netmask) == (n.ip & n.netmask)){
                return 0;
            }
        }
    }
    return 1;
}

SEC("xdp") int xdp_nat_forward(struct xdp_md *ctx){

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u64 nh_off = sizeof(*eth);
    __be16 h_proto;

    __u64 *processed_count = bpf_map_lookup_elem(&rx_cnt, &RX_CNT_PROCESSED);
    if (!processed_count) {
        __u64 init_count = 1;
        bpf_map_update_elem(&rx_cnt, &RX_CNT_PROCESSED, &init_count, BPF_ANY);
    } else {
        __sync_fetch_and_add(processed_count, 1);
    }

    if (data + nh_off > data_end)
        goto drop;

    __be16 proto = bpf_ntohs(eth->h_proto);
    __u64 *proto_count = bpf_map_lookup_elem(&xdp_stats_proto, &proto);
    if (!proto_count) {
        __u64 init_count = 1;
        bpf_map_update_elem(&xdp_stats_proto, &proto, &init_count, BPF_ANY);
    } else {
        __sync_fetch_and_add(proto_count, 1);
    }

   switch (bpf_ntohs(eth->h_proto)) {
        case ETH_P_IP: {
            struct iphdr *iph = data + nh_off;
            struct destination_map *direct_entry;

            if ((void *)(iph + 1) > data_end)
                goto drop;

            if(iph->protocol == IPPROTO_UDP){
                struct udphdr *udp = (data + nh_off + sizeof(*iph));
                if (data + nh_off + sizeof(*iph) + sizeof(*udp) > data_end)
                    goto drop;

                char key[6];
                key[0] = iph->saddr;
                key[1] = (iph->saddr >> 8);
                key[2] = (iph->saddr >> 16);
                key[3] = (iph->saddr >> 24);
                key[4] = udp->source;
                key[5] = (udp->source >> 8);

                struct remapping_map *value = bpf_map_lookup_elem(&sources, &key);
                if(value && value->dmac && value->smac && value->ip && value->port) {
                    if(nat_ip(iph->daddr)){
                        __u64 *source_count = bpf_map_lookup_elem(&rx_cnt, &RX_CNT_SOURCE);
                        if (!source_count) {
                            __u64 init_count = 1;
                            bpf_map_update_elem(&rx_cnt, &RX_CNT_SOURCE, &init_count, BPF_ANY);
                        } else {
                            __sync_fetch_and_add(source_count, 1);
                        }

                        __builtin_memcpy(eth->h_dest, &value->dmac, ETH_ALEN);
                        __builtin_memcpy(eth->h_source, &value->smac, ETH_ALEN);
                        iph->saddr = value->ip;
                        udp->source = value->port;

                        iph->check = 0;
                        iph->check = ip_checksum((__u16 *)iph, sizeof(struct iphdr));
                        udp->check = 0;
                        udp->check = caludpcsum(iph, udp, data_end);


                        int ret = bpf_redirect(value->ifindex, 0);
                        if (ret == XDP_REDIRECT) {
                            __u64 *redirect_count = bpf_map_lookup_elem(&rx_cnt, &RX_CNT_REDIRECT);
                            if (!redirect_count) {
                                __u64 init_count = 1;
                                bpf_map_update_elem(&rx_cnt, &RX_CNT_REDIRECT, &init_count, BPF_ANY);
                            } else {
                                __sync_fetch_and_add(redirect_count, 1);
                            }
                            return ret;
                        }
                        return ret;
                    }
                } else {
                    char key[6];
                    key[0] = iph->daddr;
                    key[1] = (iph->daddr >> 8);
                    key[2] = (iph->daddr >> 16);
                    key[3] = (iph->daddr >> 24);
                    key[4] = udp->dest;
                    key[5] = (udp->dest >> 8);

                    struct remapping_map *value = bpf_map_lookup_elem(&destinations, &key);
                    if(value && value->dmac && value->smac && value->ip && value->port) {
                        __u64 *destination_count = bpf_map_lookup_elem(&rx_cnt, &RX_CNT_DESTINATION);
                        if (!destination_count) {
                            __u64 init_count = 1;
                            bpf_map_update_elem(&rx_cnt, &RX_CNT_DESTINATION, &init_count, BPF_ANY);
                        } else {
                            __sync_fetch_and_add(destination_count, 1);
                        }

                         __builtin_memcpy(eth->h_dest, &value->dmac, ETH_ALEN);
                        __builtin_memcpy(eth->h_source, &value->smac, ETH_ALEN);
                        iph->daddr = value->ip;
                        udp->dest = value->port;
                        iph->check = 0;
                        iph->check = ip_checksum((__u16 *)iph, sizeof(struct iphdr));
                        udp->check = 0;
                        udp->check = caludpcsum(iph, udp, data_end);


                        int ret = bpf_redirect(value->ifindex, 0);
                        if (ret == XDP_REDIRECT) {
                            __u64 *redirect_count = bpf_map_lookup_elem(&rx_cnt, &RX_CNT_REDIRECT);
                            if (!redirect_count) {
                                __u64 init_count = 1;
                                bpf_map_update_elem(&rx_cnt, &RX_CNT_REDIRECT, &init_count, BPF_ANY);
                            } else {
                                __sync_fetch_and_add(redirect_count, 1);
                            }
                            return ret;
                        }
                        return ret;
                    }
                }
            }
        }
   }
    return XDP_PASS;
 drop:
 	return XDP_DROP;
}
