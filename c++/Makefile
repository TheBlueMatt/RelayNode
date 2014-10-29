# all common objects that need to be build for all targets except for windows version
common_objs := flaggedarrayset.o utils.o p2pclient.o ./crypto/sha2.o

CXX=c++

MINGW_CXX = i686-w64-mingw32-g++

COMMON_CXXFLAGS := -I.

UNAME_S := $(shell uname -s)

variant ?= production
ifeq ($(variant),test)
  COMMON_CXXFLAGS += -DFOR_VALGRIND -g
else
  COMMON_CXXFLAGS += -DNDEBUG -O2
endif

platform ?= linux
ifeq ($(UNAME_S),Linux)
  COMMON_CXXFLAGS += -flto
endif
ifeq ($(UNAME_S),Darwin)
  COMMON_CXXFLAGS += -flto -DX86_BSD
endif
ifeq ($(UNAME_S),FreeBSD)
  COMMON_CXXFLAGS += -DX86_BSD
endif

COMMON_CXXFLAGS += -std=c++11 -Wall
UNIX_CXXFLAGS := -I/usr/include

CXXFLAGS += $(COMMON_CXXFLAGS) $(UNIX_CXXFLAGS)
LDFLAGS += -pthread

# list of all targets
targets = $(addprefix relaynetwork,client terminator proxy outbound) relaynetworkclient.exe

all: $(filter %client,$(targets))

all-targets: $(targets)

relaynetworkclient: $(common_objs) client.o

relaynetworkclient.exe: $(patsubst %.o,%.cpp,$(common_objs) client.o)
	$(MINGW_CXX) $(COMMON_CXXFLAGS) -DWIN32 -mno-ms-bitfields -static -static-libgcc $^ -lwsock32 -lmingwthrd -lws2_32 -o $@

relaynetworkserver: $(common_objs) server.o

relaynetworkterminator: $(common_objs) bitcoindterminator.o

relaynetworkproxy: $(common_objs) relayproxy.o

relaynetworkoutbound: $(common_objs) p2poutbound.o

relaynetwork%:
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

clean:
	rm -f *.o crypto/*.o crypto/*~ *~ *.exe $(targets)
