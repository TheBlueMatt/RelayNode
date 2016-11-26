#include "preinclude.h"

#include <vector>

#ifdef WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
#else // WIN32
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <netinet/tcp.h>
	#include <netdb.h>
	#include <fcntl.h>
#endif // !WIN32

#define BITCOIN_UA_LENGTH 22
#define BITCOIN_UA {'/', 'F', 'I', 'B', 'R', 'E', 'N', 'e', 't', 'w', 'o', 'r', 'k', 'P', 'i', 'p', 'e', ':', '4', '2', '/', '\0'}

#include "p2ppipe.h"

class P2PClient : public P2PPipe {
public:
	P2PClient(const char* serverHostIn, uint16_t serverPortIn,
				const std::function<void (std::vector<unsigned char>&)>& provide_msg_in) :
			P2PPipe(serverHostIn, serverPortIn, 10000, provide_msg_in)
		{ construction_done(); }

private:
	std::vector<unsigned char> generate_version() {
		struct bitcoin_version_with_header version_msg;
		version_msg.version.start.timestamp = htole64(time(0));
		version_msg.version.start.user_agent_length = BITCOIN_UA_LENGTH; // Work around apparent gcc bug
		return std::vector<unsigned char>((unsigned char*)&version_msg, (unsigned char*)&version_msg + sizeof(version_msg));
	}
};

int main(int argc, char** argv) {
	if (argc < 5) {
		printf("USAGE: %s BITCOIND_1_ADDRESS BITCOIND_1_PORT BITCOIND_2_ADDRESS BITCOIND_2_PORT\n", argv[0]);
		printf("Pipes two bitcoinds together, getting around the broken addnode behavior in Bitcoin Core\n");
		printf("  by utilizing inbound connection slots instead of outbound ones\n");
		return -1;
	}

#ifdef WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2,2), &wsaData))
		return -1;
#endif

	P2PClient* one = NULL;

	P2PClient two(argv[3], std::stoul(argv[4]),
			[&one](std::vector<unsigned char>& msg) { while (!one) {}; one->send_hashed_message(msg.data(), msg.size()); });

	one = new P2PClient(argv[1], std::stoul(argv[2]),
			[&two](std::vector<unsigned char>& msg) { two.send_hashed_message(msg.data(), msg.size()); });

	while (true) { sleep(1000); }
}
