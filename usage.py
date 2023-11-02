from bcc import BPF
import time

b = BPF(src_file="xdp_prog.c")  # eBPF programını yükle
b.attach_xdp("eth0", "xdp_filter_prog")  # Arayüze XDP programını bağla

request_counts = {}  # IP adresleri için istek sayacı
blocked_ips = {}  # Engellenen IP adresleri

attack_severity = {
    "ICMP trafik bulundu": ("Orta", 10 * 60),
    "80 dışında port kullanıldı": ("Hafif", 5 * 60),
    "Sık istek": ("Yüksek", 60 * 60)
}

def check_blocked_ips():  # Engellenen IP adreslerini kontrol et
    current_time = time.time()
    for ip, (block_time, unblock_time) in list(blocked_ips.items()):
        if current_time > unblock_time:
            print(f"{ip} adresinin engellemesi kaldırıldı")
            del blocked_ips[ip]

def check_frequent_requests():  # Sık istekleri kontrol et
    threshold = 10  # Maksimum izin verilen istek sayısı
    for ip, count in list(request_counts.items()):
        if count > threshold:
            severity, block_duration = attack_severity['Sık istek']
            print(f"Sık istek tespit edildi: {ip} -> {count} istek/saniye, Ciddiyet: {severity}")
            block_ip(ip, block_duration)
            del request_counts[ip]

def block_ip(ip, block_duration):  # IP adresini engelle
    current_time = time.time()
    unblock_time = current_time + block_duration
    blocked_ips[ip] = (current_time, unblock_time)
    print(f"{ip} adresi {block_duration} saniye süreyle engellendi")

trace_pattern = "%s %s %s"  # Beklenen mesaj

while True:
    try:
        msg = b.trace_fields(nonblocking=True)
        if msg:
            (_, _, _, _, ts, msg) = msg
            ts = "%-18.9f" % ts #zaman formatı
            msg = msg.decode('utf-8', 'replace') #UTF8e çevir

            src_ip, dst_ip, attack_type = [x.strip() for x in msg.split(" ", 2)] #mesajdan kaynak ip hedef ip saldırı türü
            severity, block_duration = attack_severity.get(attack_type, ("Bilinmiyor", 0))
            
            block_ip(src_ip, block_duration) #bas engeli

            log_msg = f"{ts} {src_ip} {dst_ip} - - {attack_type} Zararlı trafik tespit edildi - Ciddiyet: {severity}"
            print(log_msg)

            # Sık istekleri kontrol et
            if src_ip in request_counts:
                request_counts[src_ip] += 1
            else:
                request_counts[src_ip] = 1
            check_frequent_requests()

        check_blocked_ips()

    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
