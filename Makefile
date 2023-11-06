.PHONY: all clean distclean #hedeflerinin dosya adı olmadığını ve make denildiğinde her zaman çalıştırılması gerektiğini belirtir.

LLC = llc #LLVM'nin düşük seviye derleyicisi.
CC = clang # c derleyicisi
CXX = clang++ # c++ derleyicisi
CLANG = clang 
CFLAGS := $(CFLAGS) -Wall -Werror -O2 -g #derleyiciye flag tanımlar tüm uyarıları etkinleştirir ve uyarıları hata olarak işler.-02 -g optimizasyon ve hata ayıklama bilgileri ekler.

SRCDIR = $(CURDIR) #kaynak dosyaların ve kütüphanelerin konumlarını ve BPF için sistemin BTF dosyasının yerini tanımlar.
LIBBPF_INC_DIR = $(SRCDIR)/includes/usr/include
BPF_VMLINUX ?= /sys/kernel/btf/vmlinux
BPF_CFLAGS := $(BPF_CFLAGS) \
              -Wall \
              -Wno-unused-value \
              -Wno-pointer-sign \
              -Wno-compare-distinct-pointer-types \
              -Werror \
              -MMD -MP
"2"
BPF_CFLAGS += -I$(LIBBPF_INC_DIR) -I$(CURDIR) #özel derleyici seçenekleri

# BPF_CFLAGS += -D __BPF_TRACING__

SRCS = $(wildcard *.c) #kaynak
OBJS = $(SRCS:.c=.o) #nesne
HDRS = $(wildcard *.h) #başlık dosyaları

all: $(OBJS) #üm nesne dosyalarını derlemek için varsayılan hedef olarak tanımlanır.

%.o: %.c $(HDRS)  #her bir .cyi LLVM ara diline .ll ve .o derle
	$(CLANG) -S -target bpf \
	      $(BPF_CFLAGS) \
	      -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -mattr=dwarfris -filetype=obj -o $@ ${@:.o=.ll}

vmlinux.h: # BTF dosyasını okuyarak C olarak getirir
	bpftool btf dump file $(BPF_VMLINUX) format c > vmlinux.h

clean: #derleme tarafından oluşturulan tüm ara dosyaları temizler.
	rm -rf *.o *.ll *.d

distclean: clean #clean hedefini yürütür ve ek olarak vmlinux.h dosyasını da temizler.
	rm -rf vmlinux.h

-include $(wildcard *.d) #derleyicinin oluşturduğu .d dosyalarını içerir. dosya bağımlılıklarını içerir, böylece make değişiklik yapıldığında hangi dosyaların yeniden derlenmesi gerektiğini bilir.
