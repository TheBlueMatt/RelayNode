#include "preinclude.h"

#include <map>
#include <vector>
#include <thread>
#include <mutex>

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

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

#define BITCOIN_UA_LENGTH 24
#define BITCOIN_UA {'/', 'R', 'e', 'l', 'a', 'y', 'N', 'e', 't', 'w', 'o', 'r', 'k', 'C', 'l', 'i', 'e', 'n', 't', ':', '4', '2', '/', '\0'}

#include "crypto/sha2.h"
#include "flaggedarrayset.h"
#include "relayprocess.h"
#include "utils.h"
#include "p2pclient.h"
#include "relayconnection.h"





/***********************************************
 **** Relay network client processing class ****
 ***********************************************/
class RelayNetworkClient : public KeepaliveOutboundPersistentConnection, public RelayConnectionProcessor {
private:
	const std::function<void (std::vector<unsigned char>&)> provide_block;
	const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)> provide_transaction;
	const std::function<bool ()> bitcoind_connected;

	DECLARE_ATOMIC(bool, connected);

public:
	RelayNetworkClient(const char* serverHostIn,
						const std::function<void (std::vector<unsigned char>&)>& provide_block_in,
						const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)>& provide_transaction_in,
						const std::function<bool ()>& bitcoind_connected_in)
		// Ping time(out) is 40 seconds (5000000/250*2 msec) - first ping will only happen, at the quickest, at half that
			: KeepaliveOutboundPersistentConnection(serverHostIn, 8336, MAX_FAS_TOTAL_SIZE / OUTBOUND_THROTTLE_BYTES_PER_MS * 2),
			provide_block(provide_block_in), provide_transaction(provide_transaction_in), bitcoind_connected(bitcoind_connected_in), connected(false) {
		construction_done();
	}

private:
	void on_disconnect() {
		connected = false;
		reset_read_state();
	}

	bool readable() { return true; }

	const char* handle_peer_version(const std::string& peer_version) {
		if (peer_version != std::string(VERSION_STRING))
			return "unknown version string";
		else {
			STAMPOUT();
			printf("Connected to relay node with protocol version %s\n", VERSION_STRING);
		}
		return NULL;
	}

	const char* handle_max_version(const std::string& max_version) {
		if (max_version != std::string(VERSION_STRING))
			printf("Relay network is using a later version (PLEASE UPGRADE)\n");
		else
			return "got MAX_VERSION of same version as us";
		return NULL;
	}

	const char* handle_sponsor(const std::string& sponsor) {
		printf("This node sponsored by: %s\n", sponsor.c_str());
		return NULL;
	}

	void handle_pong(uint64_t nonce) {
		pong_received(nonce);
	}

	void handle_block(RelayNodeCompressor::DecompressState& block,
			std::chrono::system_clock::time_point& read_end_time,
			std::chrono::steady_clock::time_point& read_end,
			std::chrono::steady_clock::time_point& read_start) {
		provide_block(*block.get_block_data());

		STAMPOUT();
		printf(HASH_FORMAT" recv'd, size %u with %u bytes on the wire\n", HASH_PRINT(&(*block.fullhashptr)[0]), block.block_bytes, block.wire_bytes);
	}

	void handle_transaction(std::shared_ptr<std::vector<unsigned char> >& tx) {
		if (bitcoind_connected())
			printf("Received transaction of size %lu from relay server\n", (unsigned long)tx->size());
		else
			printf("ERROR: bitcoind is not (yet) connected!\n");

		provide_transaction(tx);
	}

	void disconnect(const char* reason) {
		KeepaliveOutboundPersistentConnection::disconnect(reason);
	}

	void do_send_bytes(const char *buf, size_t nbyte) {
		maybe_do_send_bytes(buf, nbyte);
	}

	void on_connect() {
		compressor.reset();

		relay_msg_header version_header = { RELAY_MAGIC_BYTES, VERSION_TYPE, htonl(strlen(VERSION_STRING)) };
		maybe_do_send_bytes((char*)&version_header, sizeof(version_header));
		maybe_do_send_bytes(VERSION_STRING, strlen(VERSION_STRING));

		connected = true;
	}

	void recv_bytes(char* buf, size_t len) {
		RelayConnectionProcessor::recv_bytes(buf, len);
	}

protected:
	void send_ping(uint64_t nonce) {
		relay_msg_header pong_msg_header = { RELAY_MAGIC_BYTES, PING_TYPE, htonl(8) };
		std::vector<unsigned char> *msg = new std::vector<unsigned char>((unsigned char*)&pong_msg_header, ((unsigned char*)&pong_msg_header) + sizeof(pong_msg_header));
		msg->resize(msg->size() + 8);
		memcpy(&(*msg)[sizeof(pong_msg_header)], &nonce, 8);
		maybe_do_send_bytes(std::shared_ptr<std::vector<unsigned char> >(msg));
	}

public:
	void receive_transaction(const std::shared_ptr<std::vector<unsigned char> >& tx, bool send_oob) {
		if (!connected)
			return;

		std::shared_ptr<std::vector<unsigned char> > msgptr;
		if (send_oob)
			msgptr = compressor.tx_to_msg(tx, true);
		else
			msgptr = compressor.get_relay_transaction(tx);
		if (!msgptr.use_count())
			return;

		auto& msg = *msgptr.get();

		maybe_do_send_bytes((char*)&msg[0], msg.size());
		if (bitcoind_connected())
			printf("Sent transaction of size %lu%s to relay server\n", (unsigned long)tx->size(), send_oob ? " (out-of-band)" : "");
	}

	void receive_block(const std::vector<unsigned char>& block) {
		if (!connected)
			return;

		std::vector<unsigned char> fullhash(32);
		getblockhash(fullhash, block, sizeof(struct bitcoin_msg_header));

		auto tuple = compressor.maybe_compress_block(fullhash, block, false);
		if (std::get<1>(tuple)) {
			printf("Failed to process block from bitcoind (%s)\n", std::get<1>(tuple));
			return;
		}

		int token = get_send_mutex();
		auto compressed_block = std::get<0>(tuple);
		maybe_do_send_bytes((char*)&(*compressed_block)[0], compressed_block->size(), token);

		struct relay_msg_header header = { RELAY_MAGIC_BYTES, END_BLOCK_TYPE, 0 };
		maybe_do_send_bytes((char*)&header, sizeof(header), token);
		release_send_mutex(token);

		STAMPOUT();
		printf(HASH_FORMAT" sent, size %lu with %lu bytes on the wire\n", HASH_PRINT(&fullhash[0]), (unsigned long)block.size(), (unsigned long)compressed_block->size());
	}
};

class P2PClient : public P2PRelayer {
public:
	P2PClient(const char* serverHostIn, uint16_t serverPortIn,
				const std::function<void (std::vector<unsigned char>&, const std::chrono::system_clock::time_point&)>& provide_block_in,
				const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)>& provide_transaction_in) :
			P2PRelayer(serverHostIn, serverPortIn, 10000, provide_block_in, provide_transaction_in)
		{ construction_done(); }

private:
	std::vector<unsigned char> generate_version() {
		struct bitcoin_version_with_header version_msg;
		version_msg.version.start.timestamp = htole64(time(0));
		version_msg.version.start.user_agent_length = BITCOIN_UA_LENGTH; // Work around apparent gcc bug
		return std::vector<unsigned char>((unsigned char*)&version_msg, (unsigned char*)&version_msg + sizeof(version_msg));
	}
};


#define HOSTNAMES_TO_TEST 20
#define CONNECT_TESTS 20
std::chrono::milliseconds connect_durations[HOSTNAMES_TO_TEST];
void test_node(int node) {
	const char* relay = "public.%02d.relay.mattcorallo.com";
	char host[strlen(relay)];
	sprintf(host, relay, node);
	sockaddr_in6 addr;
	if (!lookup_address(host, &addr) ||
			(addr.sin6_addr.s6_addr[15] == 0 && addr.sin6_addr.s6_addr[14] == 0 && addr.sin6_addr.s6_addr[13] == 0 && addr.sin6_addr.s6_addr[12] == 0)) {
		connect_durations[node] = std::chrono::milliseconds::max();
		return;
	}

	addr.sin6_port = htons(8336);

	auto start = std::chrono::steady_clock::now();
	for (int i = 0; i < CONNECT_TESTS; i++) {
		int sock = socket(AF_INET6, SOCK_STREAM, 0);
		ALWAYS_ASSERT(sock > 0);

		int v6only = 0;
		setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&v6only, sizeof(v6only));

		connect(sock, (struct sockaddr*)&addr, sizeof(addr));
		close(sock);
	}
	connect_durations[node] = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
}



int main(int argc, char** argv) {
	if (argc < 2) {
		printf("USAGE: %s [relay server] [full|pool]:BITCOIND_ADDRESS:BITCOIND_PORT*\n", argv[0]);
		printf("Relay server is automatically selected by pinging available servers, unless one is specified\n");
		printf("Each client to connect to should either be a Bitcoin Core instance (and be prefixed with \"full:\")\n");
		printf(" or be a connection to a pool server using the Bitcoin P2P protocol (and be prefixed with \"pool:\")\n");
		printf("You should use one relay network client per location/datacenter and connect it to as many servers as neccessary\n");
		return -1;
	}

#ifdef WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2,2), &wsaData))
		return -1;
#endif

	bool pickServer = strlen(argv[1]) < 5 || argv[1][4] == ':';
	const char* relay = "public.%02d.relay.mattcorallo.com";
	char host[(pickServer ? strlen(relay) : strlen(argv[1])) + 1];
	if (pickServer) {
		while (true) {
			std::list<std::thread> threads;
			for (int i = 0; i < HOSTNAMES_TO_TEST; i++)
				threads.emplace_back(test_node, i);
			for (int i = 0; i < HOSTNAMES_TO_TEST; i++) {
				threads.front().join();
				threads.pop_front();
			}

			int min = -1; std::chrono::milliseconds min_duration(std::chrono::milliseconds::max());
			for (int i = 0; i < HOSTNAMES_TO_TEST; i++) {
				if (connect_durations[i] != std::chrono::milliseconds::max()) {
					std::string aka;
					sprintf(host, relay, i);
					printf("Server %d (%s) took %lld ms to respond %d times.\n", i, lookup_cname(host, aka) ? aka.c_str() : "", (long long int)connect_durations[i].count(), CONNECT_TESTS);
				}
				if (connect_durations[i] < min_duration) {
					min_duration = connect_durations[i];
					min = i;
				}
			}

			std::this_thread::sleep_for(std::chrono::seconds(10)); // Wait for server to open up our slot again
			if (min == -1) {
				printf("No servers responded\n");
				continue;
			}

			sprintf(host, relay, min);
			break;
		}
	} else
		memcpy(host, argv[1], strlen(argv[1]) + 1);
	STAMPOUT();
	printf("Using server %s\n", host);

	DECLARE_NON_ATOMIC_PTR(RelayNetworkClient, relayClient);
	std::vector<P2PClient*> fullServers;
	std::vector<P2PClient*> nonFullServers;
	for (int i = pickServer ? 1 : 2; i < argc; i++) {
		std::string cmdline(argv[i]);
		unsigned long port = std::stoul(cmdline.substr(cmdline.find_last_of(":")+1));
		if (port == 8332)
			printf("You specified port 8332, which is generally bitcoind RPC, you probably meant 8333\n");
		argv[i][cmdline.find_last_of(":")] = '\0';
		P2PClient* client = new P2PClient(argv[i] + 5, port,
					[&](std::vector<unsigned char>& bytes, const std::chrono::system_clock::time_point&) { ((RelayNetworkClient*)relayClient)->receive_block(bytes); },
					[&](std::shared_ptr<std::vector<unsigned char> >& bytes) {
						//TODO: Re-enable (see issue #11): ((RelayNetworkClient*)relayClient)->receive_transaction(bytes);
					});
		if (!strncmp(argv[i], "full:", strlen("full:")))
			fullServers.push_back(client);
		else if (!strncmp(argv[i], "pool:", strlen("pool:")))
			nonFullServers.push_back(client);
		else {
			printf("Clients must either be \"full:\" (ie Bitcoin Core) or \"pool:\" (ie a Pool server)\n");
			return -1;
		}
	}

	relayClient = new RelayNetworkClient(argv[1],
										[&](std::vector<unsigned char>& bytes) {
											for (P2PClient* r : fullServers)
												r->receive_block(bytes);
										},
										[&](std::shared_ptr<std::vector<unsigned char> >& bytes) {
											for (P2PRelayer* r : fullServers)
												r->receive_transaction(bytes);
											((RelayNetworkClient*)relayClient)->receive_transaction(bytes, false);
										},
										[&]() { return fullServers.empty() || fullServers[0]->is_connected(); });

	while (true) { sleep(1000); }
}
