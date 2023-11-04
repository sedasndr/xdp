# SedaSendur
Proje, Linux üzerinde çalışan eBPF ve XDP teknolojilerini kullanarak zararlı ve şüpheli ağ trafiğini etkili bir şekilde yakalayıp analiz etmek ve tespit edilen zararlı trafik durumunda saldırganı belirli bir süre boyunca engellemek amacıyla tasarlanmıştır. Proje, ağ güvenliğini artırarak, kötü amaçlı saldırıların ve zararlı trafiğin sistem üzerindeki etkilerini minimize etmeyi hedeflemektedir.
Modül, gelen ağ paketlerini gerçek zamanlı olarak analiz eder. Her bir paket kriterlere göre değerlendirilir ve tespit edilmesi için verilen zararlı işaretli üç örnek kategoriden birine  giriyorsa ilgili trafik zararlı kategorinin tehlike derecesine göre 1,5 ya da 60 dakika engellenir.


<img src="https://github.com/DevelopmentHiring/SedaSendur/blob/main/screenshots/XDP.png" width="320" height="180">
**XDP**
Ağ paketlerini çok düşük gecikme ile işlememize ve gerekirse hızlı bir şekilde reddetmemize olanak tanıyan bir eBPF programı türüdür.
XDP_PASS
XDP_DROP
XDP_TX
XDP_ABORTED

<img src="https://github.com/DevelopmentHiring/SedaSendur/blob/main/screenshots/ebpf.png" width="320" height="180">
**eBPF**
Linux çekirdeğinde güvenli ve etkili bir şekilde çalışan programlar yazmamıza olanak tanıyan bir teknolojidir. eBPF, ağ paketlerini filtrelemek, izlemek ve analiz etmek için kullanılır.

ICMP Trafik Analizi: Modül, tüm ICMP paketlerini yakalar ve analiz eder. Bu tür trafik genellikle ağ teşhis amacıyla kullanılır, ancak kötü amaçlı kullanımları da olabilir.
Anormal TCP Port Kullanımı: 80 dışında, özellikle bilinen zararlı yazılımların kullandığı portlar üzerinden gelen trafiği tespit eder ve engeller.
Sık İstek Gönderimi: Aynı IP adresinden çok sayıda istek gelmesi durumunda bu IP adresini engeller.

**xdp_prog.c**
Genel olarak ağ trafiğini analiz eder, belirlenen 3 türdeki trafiği yakalar ve bu trafiği filtreleyerek user space alanına bilgi gönderir. Bu sayede, sistem performansını etkilemeden ağ trafiği üzerinde detaylı analiz, izleme yapmak ve aksiyon almak mümkün hale gelir.

#include "vmlinux.h" // Linux çekirdeği veri yapıları ve sabitlerine erişmesi için gerekli olan başlık dosyalarını içerir. 
#include <bpf/bpf_helpers.h> //BPF, Linux çekirdeğinde çalışan ve ağ paketlerini filtreleyen, izleyen veya değiştiren küçük programlar yazmamıza olanak tanıyan bir teknolojidir. 
#include <bpf/bpf_endian.h>

//ağ paketlerinden elde edilen bilgileri tutmak için kullanılır.
struct icmp_packet_info { ... };   
struct tcp_event { ... };

//Map'ler, kernel ve user spaceı arasında veri paylaşmak için kullanılır.
struct icmp_packets SEC(".maps");
struct anormal_tcp_events SEC(".maps");
struct request_count SEC(".maps");

//Bu fonksiyon, her bir ağ paketi için çağrılan XDP programıdır. Paketin içeriğine göre kontroller yapar ve belirlenen 3 kriterdeki pakete göre filtreleme yapar.

SEC("xdp")
int xdp_filter_prog(struct xdp_md *ctx) { ... }

ICMP trafiğini yakalar ve engeller.
80 numaralı port dışındaki TCP trafiğini yakalar ve engeller.
Sık istekleri takip eder.

**usage.py**
Zararlı trafik tespit edildiğinde saldırganın IP adresini türüne göre 1,5, 60 dakika engelleyebilir.

from bcc import BPF // eBPF prog yüklemek ve çalıştırmak için
import time
import ctypes // c kütüph ve fonk için
import os

request_counts // IP adresleri ve karşılık gelen istek sayıları
blocked_ips //Engellenen IP adresleri
attack_severity  //Tespit edilen saldırı türlerine göre ciddiyet derecesi ve engelleme süresi

unblock_ip(): // vakti dolan iplerin engelini kaldırır
block_ip(ip, block_duration) // Belirtilen IP adresini belirtilen süre boyunca engeller.


**Localde çalıştırma denemeleri**
M1 işlemci Macte VMbox, Paralells ve UTM ile Ubuntu kuruldu.
Win’de VM ile Ubuntu kuruldu.
M1 Macte UTM ile Kali kuruldu.
Ardından öneriyle (https://medium.com/@harry-touloupas/when-mac-m1-m2-met-ebpf-a-tale-of-compatibility-6b9a6bc53f3e) Lima kuruldu. Ubuntu.yaml ile ayağa kaldırıldı. Gerekli toollar yüklendi, kernel güncellendi. PyCharm üzerinden Limaya ssh ile bağlanıldı, python interpreter oluşturuldu.

**Kalide:**
make vmlinux.h to (generate the header for system)
make all (build xdp object file)
Make clean && make all
Mkdir -p pf-maps
to load:
mount bpffs bpf-maps -t bpf
xdp_prog.c olan yere git ( yoksa Mkdir -p pf-maps) 
sudo mount bpffs bpf-maps -t bpf
sudo bpftool prog load /home/sedasendur1/Downloads/ars_iv_v2/xdp_prog.o bpf-maps/xdp_prog pinmaps bpf-maps/xdp_prog_maps
to attach into ethernet:
sudo bpftool net attach xdp pinned bpf-maps/xdp_prog dev eth1 — 1 çalışmadı 0 yaptım

**Denemek için:**
Vmde nc -l 9999
Lokalde nc -vm ip- 9999
sudo bpftool map dump pinned bpf-maps/xdp_prog_maps/anormal_tcp_events
sudo bpftool map lookup pinned bpf-maps/xdp_prog_maps/anormal_tcp_events key 01 00 00 00
<img src="https://github.com/DevelopmentHiring/SedaSendur/blob/main/screenshots/anormal-tcp.png" width="320" height="180">

Localden vm ipsine ifconfig ping
sudo bpftool map dump pinned bpf-maps/xdp_prog_maps/icmp_packets
sudo bpftool map lookup pinned bpf-maps/xdp_prog_maps/icmp_packets key 00 00 00 00
<img src="https://github.com/DevelopmentHiring/SedaSendur/blob/main/screenshots/icmp-packets.png" width="320" height="180">

sudo bpftool map dump pinned bpf-maps/xdp_prog_maps/request_count
<img src="https://github.com/DevelopmentHiring/SedaSendur/blob/main/screenshots/request-count1.png" width="320" height="180">
<img src="https://github.com/DevelopmentHiring/SedaSendur/blob/main/screenshots/request-count2.png" width="320" height="180">

to detache:
sudo bpftool net detach xdp dev eth1
to unload:
sudo umount bpf-maps



