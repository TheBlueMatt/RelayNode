# all common objects that need to be build for all targets except for windows version
common_objs := flaggedarrayset.o utils.o p2pclient.o ./crypto/sha2.o

MINGW_PREFIX := i686-w64-mingw32

COMMON_CXXFLAGS := -I.

variant ?= production
ifeq ($(variant),test)
  COMMON_CXXFLAGS += -DFOR_VALGRIND -g
else
  COMMON_CXXFLAGS += -DNDEBUG -O2 -flto
endif

platform ?= linux
ifeq ($(platform),bsd)
  COMMON_CXXFLAGS += -DX86_BSD
endif

COMMON_CXXFLAGS += -std=c++11 -Wall
UNIX_CXXFLAGS := -I/usr/include

CXXFLAGS += $(COMMON_CXXFLAGS) $(UNIX_CXXFLAGS)
LDFLAGS += -pthread -Wl,--no-as-needed

# list of all targets
NATIVE_TARGETS = $(addprefix relaynetwork,client terminator proxy outbound server)
WINDOWS_TARGETS = relaynetworkclient.exe

all: relaynetworkclient

all-targets: $(NATIVE_TARGETS) $(WINDOWS_TARGETS)

server-targets: $(NATIVE_TARGETS)

relaynetworkclient: $(common_objs) client.o

relaynetworkclient.exe: $(patsubst %.o,%.cpp,$(common_objs) client.o)
	$(MINGW_PREFIX)-g++ $(COMMON_CXXFLAGS) -DWIN32 -mno-ms-bitfields -static -static-libgcc $^ -lwsock32 -lmingwthrd -lws2_32 -o $@

relaynetworkserver: $(common_objs) blocks.o server.o

relaynetworkterminator: $(common_objs) bitcoindterminator.o

relaynetworkproxy: $(common_objs) relayproxy.o

relaynetworkoutbound: $(common_objs) p2poutbound.o

relaynetwork%:
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

install: relaynetworkclient relaynetworkclient.exe
	install -s relaynetworkclient ../client/
	install -s --strip-program=$(MINGW_PREFIX)-strip relaynetworkclient.exe ../client/

clean:
	rm -f *.o crypto/*.o crypto/*~ *~ *.exe $(NATIVE_TARGETS) $(WINDOWS_TARGETS)
