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





/***********************************************
 **** Relay network client processing class ****
 ***********************************************/
class RelayNetworkClient : public KeepaliveOutboundPersistentConnection {
private:
	RELAY_DECLARE_CLASS_VARS

	const std::function<void (std::vector<unsigned char>&)> provide_block;
	const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)> provide_transaction;
	const std::function<bool ()> bitcoind_connected;

	DECLARE_ATOMIC(bool, connected);

	RelayNodeCompressor compressor;

public:
	RelayNetworkClient(const char* serverHostIn,
						const std::function<void (std::vector<unsigned char>&)>& provide_block_in,
						const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)>& provide_transaction_in,
						const std::function<bool ()>& bitcoind_connected_in)
		// Ping time(out) is 40 seconds (5000000/250*2 msec) - first ping will only happen, at the quickest, at half that
			: KeepaliveOutboundPersistentConnection(serverHostIn, 8336, MAX_FAS_TOTAL_SIZE / OUTBOUND_THROTTLE_BYTES_PER_MS * 2), RELAY_DECLARE_CONSTRUCTOR_EXTENDS,
			provide_block(provide_block_in), provide_transaction(provide_transaction_in), bitcoind_connected(bitcoind_connected_in), connected(false), compressor(false) {
		construction_done();
	}

private:
	void on_disconnect() {
		connected = false;
	}

	void net_process(const std::function<void(std::string)>& disconnect) {
		compressor.reset();

		relay_msg_header version_header = { RELAY_MAGIC_BYTES, VERSION_TYPE, htonl(strlen(VERSION_STRING)) };
		maybe_do_send_bytes((char*)&version_header, sizeof(version_header));
		maybe_do_send_bytes(VERSION_STRING, strlen(VERSION_STRING));

		connected = true;

		while (true) {
			relay_msg_header header;
			if (read_all((char*)&header, 4*3) != 4*3)
				return disconnect("failed to read message header");

			if (header.magic != RELAY_MAGIC_BYTES)
				return disconnect("invalid magic bytes");

			uint32_t message_size = ntohl(header.length);

			if (message_size > 1000000)
				return disconnect("got message too large");

			if (header.type == VERSION_TYPE) {
				char data[message_size];
				if (read_all(data, message_size) < (int64_t)(message_size))
					return disconnect("failed to read version message");

				if (strncmp(VERSION_STRING, data, std::min(sizeof(VERSION_STRING), size_t(message_size))))
					return disconnect("unknown version string");
				else {
					STAMPOUT();
					printf("Connected to relay node with protocol version %s\n", VERSION_STRING);
				}
			} else if (header.type == SPONSOR_TYPE) {
				char data[message_size];
				if (read_all(data, message_size) < (int64_t)(message_size))
					return disconnect("failed to read sponsor string");

				printf("This node sponsored by: %s\n", asciifyString(std::string(data, data + message_size)).c_str());
			} else if (header.type == MAX_VERSION_TYPE) {
				char data[message_size];
				if (read_all(data, message_size) < (int64_t)(message_size))
					return disconnect("failed to read max_version string");

				if (strncmp(VERSION_STRING, data, std::min(sizeof(VERSION_STRING), size_t(message_size))))
					printf("Relay network is using a later version (PLEASE UPGRADE)\n");
				else
					return disconnect("got MAX_VERSION of same version as us");
			} else if (header.type == BLOCK_TYPE) {
				std::function<ssize_t(char*, size_t)> do_read = [&](char* buf, size_t count) { return this->read_all(buf, count); };
				auto res = compressor.decompress_relay_block(do_read, message_size, false);
				if (std::get<2>(res))
					return disconnect(std::get<2>(res));

				provide_block(*std::get<1>(res));

				auto fullhash = *std::get<3>(res).get();
				STAMPOUT();
				printf(HASH_FORMAT" recv'd, size %lu with %u bytes on the wire\n", HASH_PRINT(&fullhash[0]), (unsigned long)std::get<1>(res)->size() - sizeof(bitcoin_msg_header), std::get<0>(res));
			} else if (header.type == END_BLOCK_TYPE) {
			} else if (header.type == TRANSACTION_TYPE) {
				if (!compressor.maybe_recv_tx_of_size(message_size, true))
					return disconnect("got freely relayed transaction too large");

				auto tx = std::make_shared<std::vector<unsigned char> > (message_size);
				if (read_all((char*)&(*tx)[0], message_size) < (int64_t)(message_size))
					return disconnect("failed to read loose transaction data");

				if (bitcoind_connected())
					printf("Received transaction of size %u from relay server\n", message_size);
				else
					printf("ERROR: bitcoind is not (yet) connected!\n");

				compressor.recv_tx(tx);
				provide_transaction(tx);
			} else if (header.type == PING_TYPE) {
				char data[8 + sizeof(relay_msg_header)];
				if (message_size != 8 || read_all(&data[sizeof(relay_msg_header)], 8) < 8)
					return disconnect("failed to read 8 byte ping message");

				relay_msg_header pong_msg_header = { RELAY_MAGIC_BYTES, PONG_TYPE, htonl(8) };
				memcpy(data, &pong_msg_header, sizeof(pong_msg_header));
				maybe_do_send_bytes(data, 8 + sizeof(relay_msg_header));
			} else if (header.type == PONG_TYPE) {
				uint64_t nonce;
				if (message_size != 8 || read_all((char*)&nonce, 8) < 8)
					return disconnect("failed to read 8 byte ping message");

				pong_received(nonce);
			} else
				return disconnect("got unknown message type");
		}
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
		auto compressed_block = std::get<0>(tuple);

		struct relay_msg_header header = { RELAY_MAGIC_BYTES, END_BLOCK_TYPE, 0 };
		compressed_block->resize(compressed_block->size() + sizeof(header));
		memcpy(&(*compressed_block)[compressed_block->size() - sizeof(header)], &header, sizeof(header));
		maybe_do_send_bytes((char*)&(*compressed_block)[0], compressed_block->size());

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
	bool validPort = false;
	try { std::stoul(argv[2]); validPort = true; } catch (std::exception& e) {}
	if ((argc != 3 && argc != 4) || !validPort) {
		printf("USAGE: %s BITCOIND_ADDRESS BITCOIND_PORT [ server ]\n", argv[0]);
		printf("Relay server is automatically selected by pinging available servers, unless one is specified\n");
		return -1;
	}

#ifdef WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2,2), &wsaData))
		return -1;
#endif

	const char* relay = "public.%02d.relay.mattcorallo.com";
	char host[std::max(argc == 3 ? 0 : strlen(argv[3]), strlen(relay))];
	if (argc == 3) {
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
		memcpy(host, argv[3], strlen(argv[3]) + 1);
	STAMPOUT();
	printf("Using server %s\n", host);

	RelayNetworkClient* relayClient;
	P2PClient p2p(argv[1], std::stoul(argv[2]),
					[&](std::vector<unsigned char>& bytes, const std::chrono::system_clock::time_point&) { relayClient->receive_block(bytes); },
					[&](std::shared_ptr<std::vector<unsigned char> >& bytes) {
						//TODO: Re-enable (see issue #11): relayClient->receive_transaction(bytes, true);
					});
	relayClient = new RelayNetworkClient(host,
										[&](std::vector<unsigned char>& bytes) { p2p.receive_block(bytes); },
										[&](std::shared_ptr<std::vector<unsigned char> >& bytes) {
											p2p.receive_transaction(bytes);
											relayClient->receive_transaction(bytes, false);
										},
										[&]() { return p2p.is_connected(); });

	while (true) { sleep(1000); }
}
