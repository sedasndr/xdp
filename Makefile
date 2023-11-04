.PHONY: all clean distclean

LLC = llc
CC = clang
CXX = clang++
CLANG = clang
CFLAGS := $(CFLAGS) -Wall -Werror -O2 -g

SRCDIR = $(CURDIR)
LIBBPF_INC_DIR = $(SRCDIR)/includes/usr/include
BPF_VMLINUX ?= /sys/kernel/btf/vmlinux
BPF_CFLAGS := $(BPF_CFLAGS) \
              -Wall \
              -Wno-unused-value \
              -Wno-pointer-sign \
              -Wno-compare-distinct-pointer-types \
              -Werror \
              -MMD -MP

BPF_CFLAGS += -I$(LIBBPF_INC_DIR) -I$(CURDIR)

# BPF_CFLAGS += -D __BPF_TRACING__

SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)
HDRS = $(wildcard *.h)

all: $(OBJS)

%.o: %.c $(HDRS)
	$(CLANG) -S -target bpf \
	      $(BPF_CFLAGS) \
	      -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -mattr=dwarfris -filetype=obj -o $@ ${@:.o=.ll}

vmlinux.h:
	bpftool btf dump file $(BPF_VMLINUX) format c > vmlinux.h

clean:
	rm -rf *.o *.ll *.d

distclean: clean
	rm -rf vmlinux.h

-include $(wildcard *.d)


# .PHONY bildirimi, all, clean ve distclean hedeflerinin dosya adı olmadığını ve her zaman çalıştırılması gerektiğini belirtir.

# Derleme için kullanılacak araçlar tanımlanıyor:

# LLC LLVM'nin düşük seviye derleyicisi.
# CC C derleyicisi.
# CXX C++ derleyicisi.
# CLANG genellikle CC ve CXX ile aynı olacak olan Clang derleyicisini temsil eder.
# CFLAGS ve BPF_CFLAGS değişkenleri, derleme sürecinde kullanılacak olan bayrakları (flags) tanımlar:

# -Wall ve -Werror tüm uyarıları etkinleştirir ve uyarıları hata olarak işler.
# -O2 ve -g optimizasyon ve hata ayıklama bilgileri ekler.
# Diğer bayraklar eBPF derlemesi için özgü özellikleri ve hataları kontrol eder.
# SRCDIR, LIBBPF_INC_DIR ve BPF_VMLINUX çeşitli dosya yollarını tanımlar.

# SRCS, OBJS ve HDRS değişkenleri, kaynak .c dosyalarını, nesne .o dosyalarını ve başlık .h dosyalarını sırasıyla tanımlar.

# all hedefi, tüm nesne dosyalarını yapmak için varsayılan hedef olarak tanımlanır.

# %.o: %.c $(HDRS) kuralı, her bir C kaynak dosyasını (%.c) LLVM ara diline (%.ll) ve ardından BPF nesne dosyasına (%.o) nasıl derleyeceğini tanımlar.

# vmlinux.h hedefi, sistemin BTF (BPF Type Format) dosyasını okuyarak C başlık dosyası formatında döküm yapar.

# clean hedefi, derleme tarafından oluşturulan tüm ara dosyaları temizler.

# distclean hedefi, clean hedefini yürütür ve ek olarak vmlinux.h dosyasını da temizler.

# -include $(wildcard *.d) satırı, derleyicinin oluşturduğu .d dosyalarını içerir. Bu dosyalar, dosya bağımlılıklarını içerir, böylece make değişiklik yapıldığında hangi dosyaların yeniden derlenmesi gerektiğini bilir.