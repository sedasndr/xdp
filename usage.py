from bcc import BPF
import time
import ctypes
import os

b = BPF(src_file="xdp_prog.c")  # eBPF programını yükle
b.attach_xdp("eth0", "xdp_filter_prog")  # Arayüze XDP programını bağla
#bpf = BPF(src_file="xdp_prog.c")

# BPF map'leri al
icmp_packets = bpf.get_table("icmp_packets")
anormal_tcp_events = bpf.get_table("anormal_tcp_events")
request_count = bpf.get_table("request_count")

request_counts = {}
blocked_ips = {}

attack_severity = {
    "ICMP trafik bulundu": ("Orta", 10 * 60),
    "80 dışında port kullanıldı": ("Hafif", 5 * 60),
    "Sık istek": ("Yüksek", 60 * 60)
}

def unblock_ip():
    current_time = time.time()
    for ip, (_, unblock_time) in list(blocked_ips.items()):
        if current_time >= unblock_time:
            print(f"{ip} adresinin engellemesi kaldırıldı.")
            os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
            del blocked_ips[ip]

def block_ip(ip, block_duration):  # IP adresini blockla
    current_time = time.time()
    unblock_time = current_time + block_duration
    blocked_ips[ip] = (current_time, unblock_time)
    print(f"{ip} adresi {block_duration} saniye süreyle engellendi.")
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")


while True:
    # ICMP paketleri
    for key, value in icmp_packets.items():
        print("ICMP trafik bulundu:", value.saddr, "->", value.daddr)
        severity, block_duration = attack_severity["ICMP trafik bulundu"]
        block_ip(value.saddr)

    # Anormal port
    for key, value in anormal_tcp_events.items():
        print("80 dışında port kullanıldı:", value.saddr, "->", value.daddr)
        severity, block_duration = attack_severity["80 dışında port kullanıldı"]
        block_ip(value.saddr)

    # Sık istek
    for key, value in request_count.items():
        if value.value > 10:  # 10dan fazla istek gelmişse
            print("Sık istek:", key.value)
            severity, block_duration = attack_severity["Sık istek"]
            block_ip(key.value)

    unblock_ip()
    time.sleep(10)


########

# from bcc import BPF
# import time
# import ctypes
# import os

# bpf_source = """

# #include "vmlinux.h"
# // #include <linux/bpf.h> //BPF programlarını yüklemek, çalıştırmak ve yönetmek için gerekli olan temel veri yapılarını, sabitleri, makroları ve fonksiyon prototiplerini içerir.
# #include <bpf/bpf_helpers.h> //BPF, Linux çekirdeğinde çalışan ve ağ paketlerini filtreleyen, izleyen veya değiştiren küçük programlar yazmamıza olanak tanıyan bir teknolojidir.
# #include <bpf/bpf_endian.h> //bpf_ntohs() için
# // #include <linux/if_ether.h> //Ethernet çerçeveleriyle çalışmak için
# // #include <linux/ip.h> //ip protokolleriyle çalışmak için gerekli
# // #include <linux/tcp.h> //ağ üzerinden güvenli veri iletimi sağlayan protokol

# struct icmp_packet_info {
#     u32 saddr;
#     u32 daddr;
# };

# struct {
#     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); // map tipi her CPU çekirdeği için ayrı bir array tutulacak
#     __type(key, u32); //map size boyutu
#     __type(value, struct icmp_packet_info); //map value boyutu
#     __uint(max_entries, 1024);
# } icmp_packets SEC(".maps");

# struct tcp_event {
#     u32 saddr;
#     u32 daddr;
#     u16 sport;
#     u16 dport;
# };

# struct {
#     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); //map tipi her CPU çekirdeği için ayrı bir array tutulacak
#     __type(key, u32); //map size boyutu
#     __type(value, struct tcp_event); //map value boyutu
#     __uint(max_entries, 1024);
# } anormal_tcp_events SEC(".maps");

# struct {
#     __uint(type, BPF_MAP_TYPE_PERCPU_HASH);  //map tipi her CPU çekirdeği için ayrı bir hash tutulacak
#     __type(key, u32); //map size boyutu
#     __type(value, u64); //map value boyutu
#     __uint(max_entries, 1024);
# } request_count SEC(".maps");

# SEC("xdp") //xdp_filter_prog eBPF fonks. bir XDP olarak çalıştırılacak.
# //Eth ve IP başlıklarının geçerli olup olmadığını kontrol et.
# int xdp_filter_prog(struct xdp_md *ctx) { //xdp_md(metadata) tipinde ctx alır
#     void *data = (void *)(long)ctx->data; //başlanıgıç .paketin ilk baytı pointera atar
#     void *data_end = (void *)(long)ctx->data_end; //paket içeriğinin sonu. paketin sonundan sonraki byte
#     struct ethhdr *eth = data; //okuyabilmek için ethernet header paketin başına atılır

#     if ((void *)eth + sizeof(*eth) <= data_end) { //paketin eth başlığı içerip içermediğini , eth header bitiş adresi
#                                                     //data_endden küçük/eşitse güvenli erişilebilir
#         struct iphdr *ip = data + sizeof(*eth); //ethten ip başlangıcına geçmek için
#         if ((void *)ip + sizeof(*ip) <= data_end) {  //paket içinde ip başlığı içeriyor mu, ip header bitiş adresi
#                                                      //data_endden küçük/eşitse güvenli erişilebilir
#             // ICMP trafiği yakala
#             if (ip->protocol == IPPROTO_ICMP) { //ip headerdaki protokolun kontr
#                 struct icmp_packet_info pkt_info = {
#                     .saddr = ip->saddr,
#                     .daddr = ip->daddr,
#                 };
#                 u32 key = 0;
#                 bpf_map_update_elem(&icmp_packets, &key, &pkt_info, BPF_ANY); //BPF_any key ile varsa bile güncelle.
#                 bpf_printk("ICMP trafik bulundu %d -> %d", ip->saddr, ip->daddr);
#                 return XDP_DROP;

#             }
#             // TCP paketlerini kontrol et
#             if (ip->protocol == IPPROTO_TCP) {
#                 struct tcphdr *tcp = (struct tcphdr *)(ip + 1); // +1 ip den hemen sonra gelen TCP başlığı, IP headerin boyutunu geç,
#                                                                 //TCP başlangıcına gel.
#                 if ((void *)tcp + sizeof(*tcp) <= data_end) { //paketin sonuna kadar güvenli ifade ediliyor mu
#                     // HTTP portu dışında port kullanılırsa sıkıntı)
#                     if (bpf_ntohs(tcp->dest) != 80) { //bpf_ntohs ağ sırasındaki bayt düzenini, hostun anlayabileceği sıralamaya dönüştürür.
#                        struct tcp_event event = {
#                             .saddr = ip->saddr,
#                             .daddr = ip->daddr,
#                             .sport = bpf_ntohs(tcp->source),
#                             .dport = bpf_ntohs(tcp->dest),
#                         };
#                         u32 key = 1;
#                         bpf_map_update_elem(&anormal_tcp_events, &key, &event, BPF_ANY);
#                         bpf_printk("80 dışında port kullanıldı %u -> %u", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));
#                         return XDP_DROP;
#                     }
#                 }
#             }
#             // Sık istekleri yakala
#             u64 *value, one = 1; //her bir ip için count 1den başlasın
#             value = bpf_map_lookup_elem(&request_count, &ip->saddr); //mapte o ipye ait count var mı
#             if (value) {
#                 (*value)++;
#             } else {
#                 bpf_map_update_elem(&request_count, &ip->saddr, &one, BPF_ANY);
#             }
#         }
#     }
#     return XDP_PASS;
# }
# char _license[] SEC("license") = "GPL";

# """

# # BPF programını derle
# bpf = BPF(text=bpf_source)
# bpf.attach_xdp("eth0", "xdp_filter_prog")  # Arayüze XDP programını bağla

# # BPF map'leri al
# icmp_packets = bpf.get_table("icmp_packets")
# anormal_tcp_events = bpf.get_table("anormal_tcp_events")
# request_count = bpf.get_table("request_count")

# request_counts = {}
# blocked_ips = {}

# attack_severity = {
#     "ICMP trafik bulundu": ("Orta", 10 * 60),
#     "80 dışında port kullanıldı": ("Hafif", 5 * 60),
#     "Sık istek": ("Yüksek", 60 * 60)
# }

# def unblock_ip():
#     current_time = time.time()
#     for ip, (_, unblock_time) in list(blocked_ips.items()):
#         if current_time >= unblock_time:
#             print(f"{ip} adresinin engellemesi kaldırıldı.")
#             os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
#             del blocked_ips[ip]

# def block_ip(ip, block_duration):  # IP adresini blockla
#     current_time = time.time()
#     unblock_time = current_time + block_duration
#     blocked_ips[ip] = (current_time, unblock_time)
#     print(f"{ip} adresi {block_duration} saniye süreyle engellendi")

# while True:
#     # ICMP paketleri
#     for key, value in icmp_packets.items():
#         print("ICMP trafik bulundu:", value.saddr, "->", value.daddr)
#         severity, block_duration = attack_severity["ICMP trafik bulundu"]
#         block_ip(value.saddr)

#     # Anormal port
#     for key, value in anormal_tcp_events.items():
#         print("80 dışında port kullanıldı:", value.saddr, "->", value.daddr)
#         severity, block_duration = attack_severity["80 dışında port kullanıldı"]
#         block_ip(value.saddr)

#     # Sık istek
#     for key, value in request_count.items():
#         if value.value > 10:  # 10dan fazla istek gelmişse
#             print("Sık istek:", key.value)
#             severity, block_duration = attack_severity["Sık istek"]
#             block_ip(key.value)

#     unblock_ip()
#     time.sleep(10)
