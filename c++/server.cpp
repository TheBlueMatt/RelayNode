#include <map>
#include <vector>
#include <thread>
#include <chrono>
#include <mutex>

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>

#define BITCOIN_UA_LENGTH 23
#define BITCOIN_UA {'/', 'R', 'e', 'l', 'a', 'y', 'N', 'e', 't', 'w', 'o', 'r', 'k', 'S', 'e', 'r', 'v', 'e', 'r', ':', '4', '2', '/'}

#include "crypto/sha2.h"
#include "flaggedarrayset.h"
#include "relayprocess.h"
#include "utils.h"
#include "p2pclient.h"
#include "serverprocess.h"





/***********************************************
 **** Relay network client processing class ****
 ***********************************************/
class RelayNetworkClient {
	//TODO: Accept old versions too
private:
	const std::function<struct timeval* (RelayNetworkClient*, std::shared_ptr<std::vector<unsigned char> >&)> provide_block;
	const std::function<void (RelayNetworkClient*, std::shared_ptr<std::vector<unsigned char> >&)> provide_transaction;
	const std::function<void (RelayNetworkClient*)> connected_callback;

	RELAY_DECLARE_CLASS_VARS

	SERVER_DECLARE_CLASS_VARS

	RelayNodeCompressor compressor;

public:
	time_t lastDupConnect = 0;

	RelayNetworkClient(int sockIn, std::string hostIn,
						const std::function<struct timeval* (RelayNetworkClient*, std::shared_ptr<std::vector<unsigned char> >&)>& provide_block_in,
						const std::function<void (RelayNetworkClient*, std::shared_ptr<std::vector<unsigned char> >&)>& provide_transaction_in,
						const std::function<void (RelayNetworkClient*)>& connected_callback_in)
			: provide_block(provide_block_in), provide_transaction(provide_transaction_in), connected_callback(connected_callback_in),
			RELAY_DECLARE_CONSTRUCTOR_EXTENDS,
		SERVER_DECLARE_CONSTRUCTOR_EXTENDS_AND_BODY
	}

	~RelayNetworkClient() {
		SERVER_DECLARE_DESTRUCTOR
	}

	SERVER_DECLARE_FUNCTIONS(RelayNetworkClient)

private:
	void net_process() {
		compressor.reset();

		while (true) {
			relay_msg_header header;
			if (read_all(sock, (char*)&header, 4*3) != 4*3)
				return disconnect("failed to read message header");

			if (header.magic != RELAY_MAGIC_BYTES)
				return disconnect("invalid magic bytes");

			uint32_t message_size = ntohl(header.length);

			if (message_size > 1000000)
				return disconnect("got message too large");

			if (header.type == VERSION_TYPE) {
				char data[message_size];
				if (read_all(sock, data, message_size) < (int64_t)(message_size))
					return disconnect("failed to read version message");

				if (strncmp(VERSION_STRING, data, std::min(sizeof(VERSION_STRING), size_t(message_size)))) {
					relay_msg_header version_header = { RELAY_MAGIC_BYTES, MAX_VERSION_TYPE, htonl(strlen(VERSION_STRING)) };
					if (send_all(sock, (char*)&version_header, sizeof(version_header)) != sizeof(version_header))
						return disconnect("failed to write max version header");
					if (send_all(sock, VERSION_STRING, strlen(VERSION_STRING)) != strlen(VERSION_STRING))
						return disconnect("failed to write max version string");

					return disconnect("unknown version string");
				}

				relay_msg_header version_header = { RELAY_MAGIC_BYTES, VERSION_TYPE, htonl(strlen(VERSION_STRING)) };
				if (send_all(sock, (char*)&version_header, sizeof(version_header)) != sizeof(version_header))
					return disconnect("failed to write version header");
				if (send_all(sock, VERSION_STRING, strlen(VERSION_STRING)) != strlen(VERSION_STRING))
					return disconnect("failed to write version string");

				printf("%s Connected to relay node with protocol version %s\n", host.c_str(), VERSION_STRING);
				connected = 2;
				connected_callback(this); // Called unlocked
			} else if (connected != 2) {
				return disconnect("got non-version before version");
			} else if (header.type == MAX_VERSION_TYPE) {
				char data[message_size];
				if (read_all(sock, data, message_size) < (int64_t)(message_size))
					return disconnect("failed to read max_version string");

				if (strncmp(VERSION_STRING, data, std::min(sizeof(VERSION_STRING), size_t(message_size))))
					printf("%s peer sent us a MAX_VERSION message\n", host.c_str());
				else
					return disconnect("got MAX_VERSION of same version as us");
			} else if (header.type == BLOCK_TYPE) {
				struct timeval start, finish_read;

				gettimeofday(&start, NULL);
				auto res = compressor.decompress_relay_block(sock, message_size);
				if (std::get<2>(res))
					return disconnect(std::get<2>(res));
				gettimeofday(&finish_read, NULL);

				struct timeval *finish_send = provide_block(this, std::get<1>(res));

				if (finish_send) {
					std::vector<unsigned char>& fullhash = *std::get<3>(res).get();
					for (unsigned int i = 0; i < fullhash.size(); i++)
						printf("%02x", fullhash[fullhash.size() - i - 1]);

					printf(" BLOCK %lu %s UNTRUSTEDRELAY %u / %u TIMES: %ld %ld\n", uint64_t(finish_read.tv_sec)*1000 + uint64_t(finish_read.tv_usec)/1000, host.c_str(),
													(unsigned)std::get<0>(res), (unsigned)std::get<1>(res)->size(),
													int64_t(finish_read.tv_sec - start.tv_sec)*1000 + (int64_t(finish_read.tv_usec) - start.tv_usec)/1000,
													int64_t(finish_send->tv_sec - finish_read.tv_sec)*1000 + (int64_t(finish_send->tv_usec) - finish_read.tv_usec)/1000);
					delete finish_send;
				}
			} else if (header.type == END_BLOCK_TYPE) {
			} else if (header.type == TRANSACTION_TYPE) {
				if (!compressor.maybe_recv_tx_of_size(message_size, false))
					return disconnect("got freely relayed transaction too large");

				auto tx = std::make_shared<std::vector<unsigned char> > (message_size);
				if (read_all(sock, (char*)&(*tx)[0], message_size) < (int64_t)(message_size))
					return disconnect("failed to read loose transaction data");

				compressor.recv_tx(tx);
				provide_transaction(this, tx);
			} else
				return disconnect("got unknown message type");
		}
	}

	bool in_initial_txn = false;
public:
	void receive_transaction(const std::shared_ptr<std::vector<unsigned char> >& tx) {
		if (connected != 2)
			return;

		if (!in_initial_txn)
			send_mutex.lock();

		if (total_waiting_size > 4000000) {
			if (!in_initial_txn)
				send_mutex.unlock();
			return disconnect_from_outside("total_waiting_size blew up :(");;
		}

		outbound_primary_queue.push_back(tx); // Have to strictly order all messages
		total_waiting_size += tx->size();

		if (!in_initial_txn) {
			cv.notify_all();
			send_mutex.unlock();
		}
	}

	void initial_txn_start() {
		send_mutex.lock();
		in_initial_txn = true;
	}

	void initial_txn_done() {
		initial_outbound_throttle = true;
		in_initial_txn = false;
		send_mutex.unlock();
	}

	void receive_block(const std::shared_ptr<std::vector<unsigned char> >& block) {
		if (connected != 2)
			return;

		std::lock_guard<std::mutex> lock(send_mutex);
		if (total_waiting_size > 4000000)
			return disconnect_from_outside("total_waiting_size blew up :(");;

		outbound_primary_queue.push_back(block);
		struct relay_msg_header header = { RELAY_MAGIC_BYTES, END_BLOCK_TYPE, 0 };
		outbound_primary_queue.push_back(std::make_shared<std::vector<unsigned char> >((unsigned char*)&header, ((unsigned char*)&header) + sizeof(header)));

		total_waiting_size += block->size() + sizeof(header);
		cv.notify_all();
	}
};

class RelayNetworkCompressor : public RelayNodeCompressor {
public:
	void relay_node_connected(RelayNetworkClient* client) {
		client->initial_txn_start();
		for_each_sent_tx([&] (std::shared_ptr<std::vector<unsigned char> > tx) {
			client->receive_transaction(tx_to_msg(tx));
		});
		client->initial_txn_done();
	}
};

class P2PClient : public P2PRelayer {
public:
	P2PClient(const char* serverHostIn, uint16_t serverPortIn,
				const std::function<void (std::vector<unsigned char>&, struct timeval)>& provide_block_in,
				const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)>& provide_transaction_in,
				const header_func_type *provide_header_in=NULL, bool requestAfterSend=false) :
			P2PRelayer(serverHostIn, serverPortIn, provide_block_in, provide_transaction_in, provide_header_in, requestAfterSend) {};

private:
	bool send_version() {
		struct bitcoin_version_with_header version_msg;
		version_msg.version.start.timestamp = htole64(time(0));
		version_msg.version.start.user_agent_length = BITCOIN_UA_LENGTH; // Work around apparent gcc bug
		return send_message("version", (unsigned char*)&version_msg, sizeof(version_msg.version));
	}
};




RelayNetworkCompressor compressor;

int main(int argc, char** argv) {
	if (argc != 3 && argc != 4) {
		printf("USAGE: %s trusted_host trusted_port [::ffff:whitelisted prefix string]\n", argv[0]);
		return -1;
	}

	int listen_fd;
	struct sockaddr_in6 addr;

	if ((listen_fd = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
		printf("Failed to create socket\n");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_any;
	addr.sin6_port = htons(8336);

	int reuse = 1;
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) ||
			bind(listen_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
			listen(listen_fd, 3) < 0) {
		printf("Failed to bind 8336: %s\n", strerror(errno));
		return -1;
	}

	std::mutex map_mutex;
	std::map<std::string, RelayNetworkClient*> clientMap;
	P2PClient *trustedP2P, *localP2P;

	// You'll notice in the below callbacks that we have to do some header adding/removing
	// This is because the things are setup for the relay <-> p2p case (both to optimize
	// the client and because that is the case we want to optimize for)

	trustedP2P = new P2PClient(argv[1], std::stoul(argv[2]),
					[&](std::vector<unsigned char>& bytes, struct timeval read_start) {
						struct timeval send_start, send_end;
						gettimeofday(&send_start, NULL);

						if (bytes.size() < sizeof(struct bitcoin_msg_header) + 80)
							return;
						std::vector<unsigned char> fullhash(32);
						getblockhash(fullhash, bytes, sizeof(struct bitcoin_msg_header));

						auto tuple = compressor.maybe_compress_block(fullhash, bytes, false);
						if (!std::get<1>(tuple)) {
							std::lock_guard<std::mutex> lock(map_mutex);
							auto block = std::get<0>(tuple);
							for (const auto& client : clientMap) {
								if (!client.second->disconnectFlags)
									client.second->receive_block(block);
							}
						}
						localP2P->receive_block(bytes);

						gettimeofday(&send_end, NULL);

						for (unsigned int i = 0; i < fullhash.size(); i++)
							printf("%02x", fullhash[fullhash.size() - i - 1]);

						printf(" BLOCK %lu %s TRUSTEDP2P %lu / %lu TIMES: %ld %ld\n", uint64_t(send_end.tv_sec)*1000 + uint64_t(send_end.tv_usec)/1000, argv[1],
														bytes.size(), bytes.size(),
														int64_t(send_start.tv_sec - read_start.tv_sec)*1000 + (int64_t(send_start.tv_usec) - read_start.tv_usec)/1000,
														int64_t(send_end.tv_sec - send_start.tv_sec)*1000 + (int64_t(send_end.tv_usec) - send_start.tv_usec)/1000);
					},
					[&](std::shared_ptr<std::vector<unsigned char> >& bytes) {
						auto tx = compressor.get_relay_transaction(bytes);
						if (tx.use_count()) {
							std::lock_guard<std::mutex> lock(map_mutex);
							for (const auto& client : clientMap) {
								if (!client.second->disconnectFlags)
									client.second->receive_transaction(tx);
							}
							localP2P->receive_transaction(bytes);
						}
					},
					[&](std::vector<unsigned char>& headers) {
						bool wasUseful = false;
						try {
							std::vector<unsigned char>::const_iterator it = headers.begin();
							uint64_t count = read_varint(it, headers.end());

							for (uint64_t i = 0; i < count; i++) {
								move_forward(it, 81, headers.end());

								if (*(it - 1) != 0)
									return wasUseful;

								std::vector<unsigned char> fullhash(32);
								getblockhash(fullhash, headers, it - 81 - headers.begin());
								wasUseful |= compressor.block_sent(fullhash);
							}

							printf("Added headers from trusted peers, seen %u blocks\n", compressor.blocks_sent());
						} catch (read_exception) { }
						return wasUseful;
					}, true);

	localP2P = new P2PClient("127.0.0.1", 8335,
					[&](std::vector<unsigned char>& bytes, struct timeval read_start) {
						if (bytes.size() < sizeof(struct bitcoin_msg_header) + 80)
							return;

						struct timeval send_start, send_end;
						gettimeofday(&send_start, NULL);

						std::vector<unsigned char> fullhash(32);
						getblockhash(fullhash, bytes, sizeof(struct bitcoin_msg_header));

						auto tuple = compressor.maybe_compress_block(fullhash, bytes, true);
						if (std::get<1>(tuple)) {
							for (unsigned int i = 0; i < fullhash.size(); i++)
								printf("%02x", fullhash[fullhash.size() - i - 1]);
							printf(" INSANE %s LOCALP2P\n", std::get<1>(tuple));
							return;
						} else {
							auto block = std::get<0>(tuple);
							std::lock_guard<std::mutex> lock(map_mutex);
							for (const auto& client : clientMap) {
								if (!client.second->disconnectFlags)
									client.second->receive_block(block);
							}
						}
						localP2P->receive_block(bytes);
						gettimeofday(&send_end, NULL);
						trustedP2P->receive_block(bytes);

						for (unsigned int i = 0; i < fullhash.size(); i++)
							printf("%02x", fullhash[fullhash.size() - i - 1]);
						printf(" BLOCK %lu %s LOCALP2P %lu / %lu TIMES: %ld %ld\n", uint64_t(send_start.tv_sec)*1000 + uint64_t(send_start.tv_usec)/1000, "127.0.0.1",
														bytes.size(), bytes.size(),
														int64_t(send_start.tv_sec - read_start.tv_sec)*1000 + (int64_t(send_start.tv_usec) - read_start.tv_usec)/1000,
														int64_t(send_end.tv_sec - send_start.tv_sec)*1000 + (int64_t(send_end.tv_usec) - send_start.tv_usec)/1000);
					},
					[&](std::shared_ptr<std::vector<unsigned char> >& bytes) {
						trustedP2P->receive_transaction(bytes);
					});

	std::function<struct timeval* (RelayNetworkClient*, std::shared_ptr<std::vector<unsigned char> >&)> relayBlock =
		[&](RelayNetworkClient* from, std::shared_ptr<std::vector<unsigned char>> & bytes) {
			if (bytes->size() < sizeof(struct bitcoin_msg_header) + 80)
				return (struct timeval*)NULL;
			std::vector<unsigned char> fullhash(32);
			getblockhash(fullhash, *bytes, sizeof(struct bitcoin_msg_header));

			auto tuple = compressor.maybe_compress_block(fullhash, *bytes, true);
			if (std::get<1>(tuple)) {
				for (unsigned int i = 0; i < fullhash.size(); i++)
					printf("%02x", fullhash[fullhash.size() - i - 1]);
				printf(" INSANE %s UNTRUSTEDRELAY %s\n", std::get<1>(tuple), from->host.c_str());
				return (struct timeval*)NULL;
			} else {
				std::lock_guard<std::mutex> lock(map_mutex);
				auto block = std::get<0>(tuple);
				for (const auto& client : clientMap) {
					if (!client.second->disconnectFlags)
						client.second->receive_block(block);
				}
			}

			localP2P->receive_block(*bytes);

			struct timeval *tv = new struct timeval;
			gettimeofday(tv, NULL);

			trustedP2P->receive_block(*bytes);

			return tv;
		};

	std::function<void (RelayNetworkClient*, std::shared_ptr<std::vector<unsigned char> >&)> relayTx =
		[&](RelayNetworkClient* from, std::shared_ptr<std::vector<unsigned char>> & bytes) {
			trustedP2P->receive_transaction(bytes);
		};

	std::function<void (RelayNetworkClient*)> connected =
		[&](RelayNetworkClient* client) {
			compressor.relay_node_connected(client);
		};

	std::thread([&](void) {
		while (true) {
			std::this_thread::sleep_for(std::chrono::seconds(10)); // Implicit new-connection rate-limit
			{
				std::lock_guard<std::mutex> lock(map_mutex);
				for (auto it = clientMap.begin(); it != clientMap.end();) {
					if (it->second->disconnectFlags & DISCONNECT_COMPLETE) {
						fprintf(stderr, "%lld: Culled %s, have %lu relay clients\n", (long long) time(NULL), it->first.c_str(), clientMap.size() - 1);
						delete it->second;
						clientMap.erase(it++);
					} else
						it++;
				}
			}
		}
	}).detach();

	std::string droppostfix(".uptimerobot.com");
	std::string whitelistprefix("NOT AN ADDRESS");
	if (argc == 4)
		whitelistprefix = argv[3];
	socklen_t addr_size = sizeof(addr);
	while (true) {
		int new_fd;
		if ((new_fd = accept(listen_fd, (struct sockaddr *) &addr, &addr_size)) < 0) {
			printf("Failed to select (%d: %s)\n", new_fd, strerror(errno));
			return -1;
		}

		std::string host = gethostname(&addr);
		std::lock_guard<std::mutex> lock(map_mutex);
		if ((clientMap.count(host) && host.compare(0, whitelistprefix.length(), whitelistprefix) != 0) ||
				(host.length() > droppostfix.length() && !host.compare(host.length() - droppostfix.length(), droppostfix.length(), droppostfix))) {
			if (clientMap.count(host)) {
				const auto& client = clientMap[host];
				if (client->lastDupConnect < (time(NULL) - 60)) {
					client->lastDupConnect = time(NULL);
					fprintf(stderr, "%lld: Got duplicate connection from %s (original's disconnect status: %d)\n", (long long) time(NULL), host.c_str(), client->disconnectFlags.load());
				}
			}
			close(new_fd);
		} else {
			assert(clientMap.count(host) == 0);
			clientMap[host] = new RelayNetworkClient(new_fd, host, relayBlock, relayTx, connected);
			fprintf(stderr, "%lld: New connection from %s, have %lu relay clients\n", (long long) time(NULL), host.c_str(), clientMap.size());
		}
	}
}
