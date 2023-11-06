from bcc import BPF
import time
import ctypes
import os

device = "lo"
bpf = BPF(src_file="xdp_prog.c")
fn = b.load_func("xdp_filter_prog", BPF.XDP)
bpf.attach_xdp(device, fn, 0)
# b = BPF(src_file="xdp_prog.c")  # eBPF programını yükle
# b.attach_xdp("eth0", "xdp_filter_prog")  # Arayüze XDP programını bağla
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




