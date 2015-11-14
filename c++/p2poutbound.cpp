#include "preinclude.h"

#include <map>
#include <vector>
#include <thread>
#include <mutex>

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#ifdef WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
#else // WIN32
	#include <netinet/tcp.h>
	#include <netdb.h>
	#include <fcntl.h>
#endif // !WIN32

#define BITCOIN_UA_LENGTH 22
#define BITCOIN_UA {'/', 'R', 'e', 'l', 'a', 'y', 'N', 'e', 't', 'w', 'o', 'r', 'k', 'O', 'u', 't', 'b', 'o', 'u', 'n', 'd', '/'}

#include "crypto/sha2.h"
#include "utils.h"
#include "p2pclient.h"




class P2PClient : public P2PRelayer {
public:
	P2PClient(const char* serverHostIn, uint16_t serverPortIn,
				const std::function<void (std::vector<unsigned char>&, const std::chrono::system_clock::time_point&)>& provide_block_in,
				const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)>& provide_transaction_in) :
			P2PRelayer(serverHostIn, serverPortIn, 30000, provide_block_in, provide_transaction_in)
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
	if (argc != 4) {
		printf("USAGE: %s BITCOIND_ADDRESS BITCOIND_PORT LOCAL_ADDRESS\n", argv[0]);
		return -1;
	}

#ifdef WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2,2), &wsaData))
		return -1;
#endif

	struct sockaddr_in6 addr;
	if (!lookup_address(argv[1], &addr)) {
		printf("Failed to lookup hostname\n");
		return -1;
	}
	std::string host(gethostname(&addr));

	P2PClient* inbound;
	P2PClient outbound(argv[1], std::stoul(argv[2]),
					[&](std::vector<unsigned char>& bytes, const std::chrono::system_clock::time_point&) {
						struct timeval tv;
						gettimeofday(&tv, NULL);
						inbound->receive_block(bytes);

						std::vector<unsigned char> fullhash(32);
						getblockhash(fullhash, bytes, sizeof(struct bitcoin_msg_header));
						for (unsigned int i = 0; i < fullhash.size(); i++)
							printf("%02x", fullhash[fullhash.size() - i - 1]);
						printf(" recv'd %s %lu\n", argv[1], uint64_t(tv.tv_sec)*1000 + uint64_t(tv.tv_usec)/1000);
					},
					[&](std::shared_ptr<std::vector<unsigned char> >& bytes) { inbound->receive_transaction(bytes); });
	inbound = new P2PClient(argv[3], 8334,
					[&](std::vector<unsigned char>& bytes, const std::chrono::system_clock::time_point&) { outbound.receive_block(bytes); },
					[&](std::shared_ptr<std::vector<unsigned char> >& bytes) { });

	while (true) { sleep(1000); }
}
