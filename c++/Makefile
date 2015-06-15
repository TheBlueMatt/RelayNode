# all common objects that need to be build for all targets except for windows version
common_objs := flaggedarrayset.o utils.o relayprocess.o p2pclient.o ./crypto/sha2.o

MINGW_PREFIX := i686-w64-mingw32

CXX ?= c++

COMMON_CXXFLAGS := -I.

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

LE := N
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
ifeq ($(variant),test)
  COMMON_CXXFLAGS += -DFOR_VALGRIND -g
else
  ifeq ($(variant),bench)
    COMMON_CXXFLAGS += -DBENCH
  endif
  COMMON_CXXFLAGS += -DNDEBUG -O3
  ifneq ($(variant),generic)
    # In my tests O3/march made quite a big difference
    COMMON_CXXFLAGS += -march=native -mtune=native
  endif
endif

ifeq ($(UNAME_S),Linux)
  COMMON_CXXFLAGS += -flto
endif
ifeq ($(UNAME_S),Darwin)
  COMMON_CXXFLAGS += -flto -DX86_BSD
endif
ifeq ($(UNAME_S),FreeBSD)
# Maybe these conditions can be rewritten :p
ifeq ($(LE),Y)
  COMMON_CXXFLAGS += -DX86_BSD
endif
endif

COMMON_CXXFLAGS += -std=c++11 -Wall
UNIX_CXXFLAGS := -I/usr/include

CXXFLAGS += $(COMMON_CXXFLAGS) $(UNIX_CXXFLAGS)
LDFLAGS += -pthread -Wl,--no-as-needed

# list of all targets
NATIVE_TARGETS = $(addprefix relaynetwork,client terminator proxy outbound server test)
WINDOWS_TARGETS = relaynetworkclient.exe

all: relaynetworkclient

all-targets: $(NATIVE_TARGETS) $(WINDOWS_TARGETS)

server-targets: $(NATIVE_TARGETS)

relaynetworkclient: $(common_objs) client.o

relaynetworkclient.exe: $(patsubst %.o,%.cpp,$(common_objs) client.o)
	$(MINGW_PREFIX)-g++ $(COMMON_CXXFLAGS) -DWIN32 -mno-ms-bitfields -static -static-libgcc $^ -lwsock32 -lmingwthrd -lws2_32 -o $@

relaynetworkserver: $(common_objs) server.o

relaynetworkterminator: $(common_objs) bitcoindterminator.o

relaynetworkproxy: $(common_objs) relayproxy.o

relaynetworkoutbound: $(common_objs) p2poutbound.o

relaynetworktest: $(common_objs) test.o

relaynetwork%:
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

install: relaynetworkclient relaynetworkclient.exe
	install -s relaynetworkclient ../client/
	install -s --strip-program=$(MINGW_PREFIX)-strip relaynetworkclient.exe ../client/

clean:
	rm -f *.o crypto/*.o crypto/*~ *~ *.exe $(NATIVE_TARGETS) $(WINDOWS_TARGETS)
