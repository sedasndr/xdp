#include "vmlinux.h"
// #include <linux/bpf.h> //BPF programlarını yüklemek, çalıştırmak ve yönetmek için gerekli olan temel veri yapılarını, sabitleri, makroları ve fonksiyon prototiplerini içerir.
#include <bpf/bpf_helpers.h> //BPF, Linux çekirdeğinde çalışan ve ağ paketlerini filtreleyen, izleyen veya değiştiren küçük programlar yazmamıza olanak tanıyan bir teknolojidir. 
#include <bpf/bpf_endian.h>
// #include <linux/if_ether.h> //Ethernet çerçeveleriyle çalışmak için
// #include <linux/ip.h> //ip protokolleriyle çalışmak için gerekli 
// #include <linux/tcp.h> //ağ üzerinden güvenli veri iletimi sağlayan protokol

struct icmp_packet_info {
    u32 saddr;
    u32 daddr;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct icmp_packet_info);
    __uint(max_entries, 1024);
} icmp_packets SEC(".maps");

struct tcp_event {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct tcp_event);
    __uint(max_entries, 1024);
} anormal_tcp_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);  //her CPU çekirdeği için ayrı bir hash tutulacak
    __type(key, u32); //map size boyutu
    __type(value, u64); //map value boyutu
    __uint(max_entries, 1024);
} request_count SEC(".maps");


SEC("xdp") //xdp_filter_prog eBPF fonks. bir XDP olarak çalıştırılacak.
int xdp_filter_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data; //ethernet başlığını tut

    if ((void *)eth + sizeof(*eth) <= data_end) { //eth başlığı kadar data var mı, eth header bitiş adresi data_endden küçük/eşitse güvenli erişilebilir
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) <= data_end) {  //ip başlığı kadar data var mı, ip header bitiş adresi data_endden küçük/eşitse güvenli erişilebilir
            
            // ICMP trafiği yakala
            if (ip->protocol == IPPROTO_ICMP) { 
                struct icmp_packet_info pkt_info = {
                    .saddr = ip->saddr,
                    .daddr = ip->daddr,
                };
                u32 key = 0;
                bpf_map_update_elem(&icmp_packets, &key, &pkt_info, BPF_ANY);
                bpf_printk("ICMP trafik bulundu %d -> %d", ip->saddr, ip->daddr);
                return XDP_DROP;

            }

            // TCP paketlerini kontrol et
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
                if ((void *)tcp + sizeof(*tcp) <= data_end) {
                    // HTTP portu dışında port kullanılırsa sıkıntı)
                    if (bpf_ntohs(tcp->dest) != 80) {
                       struct tcp_event event = {
                            .saddr = ip->saddr,
                            .daddr = ip->daddr,
                            .sport = bpf_ntohs(tcp->source),
                            .dport = bpf_ntohs(tcp->dest),
                        };
                        u32 key = 1;
                        bpf_map_update_elem(&anormal_tcp_events, &key, &event, BPF_ANY);
                        bpf_printk("80 dışında port kullanıldı %u -> %u", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));
                        return XDP_DROP;
                    }
                }
            }
            
            // Sık istekleri yakala
            u64 *value, one = 1;
            value = bpf_map_lookup_elem(&request_count, &ip->saddr);
            if (value) {
                (*value)++;
            } else {
                bpf_map_update_elem(&request_count, &ip->saddr, &one, BPF_ANY);
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
