# all common objects that need to be build for all targets except for windows version
common_objs := flaggedarrayset.o utils.o relayprocess.o p2pclient.o connection.o ./crypto/sha2.o
native_objs :=

MINGW_PREFIX := i686-w64-mingw32

CXX ?= c++

COMMON_CXXFLAGS := -I. -g
NATIVE_CXXFLAGS := -I/usr/include

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

LE := N
ifeq ($(UNAME_M),amd64)
  LE := Y
endif
ifeq ($(UNAME_M),x86_64)
  LE := Y
endif
ifeq ($(UNAME_M),x86)
  LE := Y
endif

ifeq ($(LE),Y)
  COMMON_CXXFLAGS += -DFORCE_LE
endif

variant ?= production
ifneq (,$(findstring test,$(variant)))
  COMMON_CXXFLAGS += -DFOR_TEST -DTEST_DATA
  NATIVE_CXXFLAGS += -DFOR_VALGRIND
  ifeq ($(variant),fasttest)
    COMMON_CXXFLAGS += -O3
  endif
else
  ifeq ($(variant),bench)
    COMMON_CXXFLAGS += -DBENCH -DTEST_DATA
  else
    ifeq ($(variant),precise_bench)
      COMMON_CXXFLAGS += -DBENCH -DPRECISE_BENCH -DTEST_DATA
    endif
  endif
  COMMON_CXXFLAGS += -DNDEBUG -O3
  ifneq ($(variant),generic)
    # In my tests O3/march made quite a big difference
    COMMON_CXXFLAGS += -march=native -mtune=native
  endif
endif

ifeq ($(UNAME_S),Linux)
  ifneq ($(variant),test)
    COMMON_CXXFLAGS += -flto
  endif
  LDFLAGS += -Wl,--no-as-needed
  ifneq ($(variant),generic)
    ifneq (,$(findstring avx2,$(shell cat /proc/cpuinfo)))
      NATIVE_CXXFLAGS += -DSHA256=sha256_rorx
      native_objs += crypto/sha256_code_release/sha256_avx2_rorx2.a
    else
      ifneq (,$(findstring avx,$(shell cat /proc/cpuinfo)))
        NATIVE_CXXFLAGS += -DSHA256=sha256_avx
        native_objs += crypto/sha256_code_release/sha256_avx1.a
      else
        ifneq (,$(findstring sse4_1,$(shell cat /proc/cpuinfo)))
          NATIVE_CXXFLAGS += -DSHA256=sha256_sse4
          native_objs += crypto/sha256_code_release/sha256_sse4.a
        endif
      endif
    endif
  endif
endif
ifeq ($(UNAME_S),Darwin)
  ifneq ($(variant),test)
    COMMON_CXXFLAGS += -flto
  endif
  COMMON_CXXFLAGS += -DX86_BSD
endif
ifeq ($(UNAME_S),FreeBSD)
ifeq ($(LE),Y)
  COMMON_CXXFLAGS += -DX86_BSD
  LDFLAGS += -Wl,--no-as-needed
endif
endif

COMMON_CXXFLAGS += -std=c++11 -Wall

CXXFLAGS += $(COMMON_CXXFLAGS) $(NATIVE_CXXFLAGS) $(CUSTOM_CXXFLAGS)
LDFLAGS += -pthread -lresolv $(CUSTOM_LDFLAGS)

# list of all targets
NATIVE_TARGETS = $(addprefix relaynetwork,client proxy server mempoolserver test)
WINDOWS_TARGETS = relaynetworkclient.exe

%.a: %.asm
	yasm -f x64 -f elf64 -X gnu -g dwarf2 -D LINUX -o $@ $<

all: relaynetworkclient

all-targets: $(NATIVE_TARGETS) $(WINDOWS_TARGETS)

server-targets: $(NATIVE_TARGETS)

relaynetworkclient: $(native_objs) $(common_objs) client.o

relaynetworkclient.exe: $(patsubst %.o,%.cpp,$(common_objs) client.o)
	$(MINGW_PREFIX)-g++ $(COMMON_CXXFLAGS) -DWIN32 -DFD_SETSIZE=1024 -mno-ms-bitfields -static -static-libgcc $^ -lwsock32 -lmingwthrd -lws2_32 -o $@

relaynetworkserver: $(native_objs) $(common_objs) server.o

relaynetworkmempoolserver: $(native_objs) $(common_objs) rpcclient.o mempoolserver.o

relaynetworkproxy: $(native_objs) $(common_objs) relayproxy.o

relaynetworktest: $(native_objs) $(common_objs) test.o

relaynetwork%:
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

install: relaynetworkclient relaynetworkclient.exe
	install -s relaynetworkclient ../client/
	install -s --strip-program=$(MINGW_PREFIX)-strip relaynetworkclient.exe ../client/

clean:
	rm -f *.o crypto/*.o crypto/sha256_code_release/*.a crypto/*~ *~ *.exe $(NATIVE_TARGETS) $(WINDOWS_TARGETS)
