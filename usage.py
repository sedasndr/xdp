from bcc import BPF
import time
import ctypes
import os
import sys
import socket



#interface = "eth0"
#print("binding socket to '%s'" % interface)
#bpf = BPF(src_file="xdp_prog.c", debug=0)
#function_http_filter = bpf.load_func("xdp_filter_prog", BPF.SOCKET_FILTER)
#BPF.attach_raw_socket(function_http_filter, interface)
#socket_fd = function_http_filter.sock
#sock = socket.fromfd(socket_fd, socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
#sock.setblocking(True)
# b = BPF(src_file="xdp_prog.c")  # eBPF programını yükle
# b.attach_xdp("eth0", "xdp_filter_prog")  # Arayüze XDP programını bağla
bpf = BPF(src_file="xdp_prog.c")

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




