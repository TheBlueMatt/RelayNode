#include "preinclude.h"

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
#include "connection.h"
#include "rpcclient.h"




static const char* HOST_SPONSOR;


static const std::map<std::string, int16_t> compressor_types = {{std::string("sponsor printer"), 1}, {std::string("spammy memeater"), 0}, {std::string("the blocksize"), 1}};


/***********************************************
 **** Relay network client processing class ****
 ***********************************************/
class RelayNetworkClient : public ThreadedConnection {
private:
	DECLARE_ATOMIC_INT(int, connected);
	bool sendSponsor = false;
	uint8_t tx_sent = 0;

	const std::function<size_t (RelayNetworkClient*, std::shared_ptr<std::vector<unsigned char> >&, const std::vector<unsigned char>&)> provide_block;
	const std::function<void (RelayNetworkClient*, std::shared_ptr<std::vector<unsigned char> >&)> provide_transaction;
	const std::function<void (RelayNetworkClient*, int)> connected_callback;

	RELAY_DECLARE_CLASS_VARS

	RelayNodeCompressor compressor;

public:
	time_t lastDupConnect = 0;
	DECLARE_ATOMIC_INT(int16_t, compressor_type);

	RelayNetworkClient(int sockIn, std::string hostIn,
						const std::function<size_t (RelayNetworkClient*, std::shared_ptr<std::vector<unsigned char> >&, const std::vector<unsigned char>&)>& provide_block_in,
						const std::function<void (RelayNetworkClient*, std::shared_ptr<std::vector<unsigned char> >&)>& provide_transaction_in,
						const std::function<void (RelayNetworkClient*, int)>& connected_callback_in)
			: ThreadedConnection(sockIn, hostIn, NULL), connected(0),
			provide_block(provide_block_in), provide_transaction(provide_transaction_in), connected_callback(connected_callback_in),
			RELAY_DECLARE_CONSTRUCTOR_EXTENDS, compressor(false), compressor_type(-1) // compressor is always replaced in VERSION_TYPE recv
	{ construction_done(); }

private:
	void send_sponsor(int token=0) {
		if (!sendSponsor || tx_sent != 0)
			return;
		relay_msg_header sponsor_header = { RELAY_MAGIC_BYTES, SPONSOR_TYPE, htonl(strlen(HOST_SPONSOR)) };
		do_send_bytes((char*)&sponsor_header, sizeof(sponsor_header), token);
		do_send_bytes(HOST_SPONSOR, strlen(HOST_SPONSOR), token);
	}

	void net_process(const std::function<void(std::string)>& disconnect) {
		compressor.reset();

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
				char data[message_size + 1];
				if (read_all(data, message_size) < (int64_t)(message_size))
					return disconnect("failed to read version message");

				for (uint32_t i = 0; i < message_size; i++)
					if (data[i] > 'z' && data[i] < 'a' && data[i] != ' ')
						return disconnect("bogus version string");
				data[message_size] = 0;

				std::string their_version(data);

				if (their_version != VERSION_STRING) {
					relay_msg_header version_header = { RELAY_MAGIC_BYTES, MAX_VERSION_TYPE, htonl(strlen(VERSION_STRING)) };
					do_send_bytes((char*)&version_header, sizeof(version_header));
					do_send_bytes(VERSION_STRING, strlen(VERSION_STRING));
				}

				std::map<std::string, int16_t>::const_iterator it = compressor_types.find(their_version);
				if (it == compressor_types.end())
					return disconnect("unknown version string");

				compressor_type = it->second;

				if (their_version == "spammy memeater")
					compressor = RelayNodeCompressor(false);
				else
					compressor = RelayNodeCompressor(true);

				if (their_version != "the blocksize")
					sendSponsor = true;

				relay_msg_header version_header = { RELAY_MAGIC_BYTES, VERSION_TYPE, htonl(message_size) };
				do_send_bytes((char*)&version_header, sizeof(version_header));
				do_send_bytes(data, message_size);

				printf("%s Connected to relay node with protocol version %s\n", host.c_str(), data);
				int token = get_send_mutex();
				connected = 2;
				do_throttle_outbound();
				connected_callback(this, token); // Called with send_mutex!
				release_send_mutex(token);
			} else if (connected != 2) {
				return disconnect("got non-version before version");
			} else if (header.type == MAX_VERSION_TYPE) {
				char data[message_size];
				if (read_all(data, message_size) < (int64_t)(message_size))
					return disconnect("failed to read max_version string");

				if (strncmp(VERSION_STRING, data, std::min(sizeof(VERSION_STRING), size_t(message_size))))
					printf("%s peer sent us a MAX_VERSION message\n", host.c_str());
				else
					return disconnect("got MAX_VERSION of same version as us");
			} else if (header.type == SPONSOR_TYPE) {
				char data[message_size];
				if (read_all(data, message_size) < (int64_t)(message_size))
					return disconnect("failed to read sponsor string");
			} else if (header.type == BLOCK_TYPE) {
				std::chrono::system_clock::time_point read_start(std::chrono::system_clock::now());
				std::function<ssize_t(char*, size_t)> do_read = [&](char* buf, size_t count) { return read_all(buf, count); };
				auto res = compressor.decompress_relay_block(do_read, message_size, true);
				if (std::get<2>(res))
					return disconnect(std::get<2>(res));
				std::chrono::system_clock::time_point read_finish(std::chrono::system_clock::now());

				const std::vector<unsigned char>& fullhash = *std::get<3>(res).get();
				size_t bytes_sent = provide_block(this, std::get<1>(res), fullhash);
				std::chrono::system_clock::time_point send_queued(std::chrono::system_clock::now());

				if (bytes_sent) {
					printf(HASH_FORMAT" BLOCK %lu %s UNTRUSTEDRELAY %u / %lu / %u TIMES: %lf %lf\n", HASH_PRINT(&fullhash[0]),
													epoch_millis_lu(read_finish), host.c_str(),
													(unsigned)std::get<0>(res), bytes_sent, (unsigned)std::get<1>(res)->size(),
													to_millis_double(read_finish - read_start), to_millis_double(send_queued - read_finish));
				}
			} else if (header.type == END_BLOCK_TYPE) {
			} else if (header.type == TRANSACTION_TYPE) {
				if (!compressor.maybe_recv_tx_of_size(message_size, false))
					return disconnect("got freely relayed transaction too large");

				auto tx = std::make_shared<std::vector<unsigned char> > (message_size);
				if (read_all((char*)&(*tx)[0], message_size) < (int64_t)(message_size))
					return disconnect("failed to read loose transaction data");

				compressor.recv_tx(tx);
				provide_transaction(this, tx);
			} else if (header.type == OOB_TRANSACTION_TYPE) {
				if (message_size > 1000000)
					return disconnect("got oob transaction too large");

				auto tx = std::make_shared<std::vector<unsigned char> > (message_size);
				if (read_all((char*)&(*tx)[0], message_size) < (int64_t)(message_size))
					return disconnect("failed to read oob transaction data");

				provide_transaction(this, tx);
			} else if (header.type == PING_TYPE) {
				char data[8];
				if (message_size != 8 || read_all(data, 8) < 8)
					return disconnect("failed to read 8 byte ping message");

				relay_msg_header pong_msg_header = { RELAY_MAGIC_BYTES, PONG_TYPE, htonl(8) };

				int token = get_send_mutex();
				do_send_bytes((char*)&pong_msg_header, sizeof(pong_msg_header), token);
				do_send_bytes(data, 8, token);
				release_send_mutex(token);
			} else
				return disconnect("got unknown message type");
		}
	}

public:
	void receive_transaction(const std::shared_ptr<std::vector<unsigned char> >& tx, int token=0) {
		if (connected != 2)
			return;

		do_send_bytes(tx, token);
		tx_sent++;
		if (!token)
			send_sponsor(token);
	}

	void receive_block(const std::shared_ptr<std::vector<unsigned char> >& block) {
		if (connected != 2)
			return;

		int token = get_send_mutex();
		do_send_bytes(block, token);
		struct relay_msg_header header = { RELAY_MAGIC_BYTES, END_BLOCK_TYPE, 0 };
		do_send_bytes((char*)&header, sizeof(header), token);
		release_send_mutex(token);
	}
};

class P2PClient : public P2PRelayer {
public:
	P2PClient(const char* serverHostIn, uint16_t serverPortIn,
				const std::function<void (std::vector<unsigned char>&, const std::chrono::system_clock::time_point&)>& provide_block_in,
				const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)>& provide_transaction_in,
				const std::function<void (std::vector<unsigned char>&)>& provide_headers_in,
				bool check_block_msghash_in) :
			P2PRelayer(serverHostIn, serverPortIn, 10000, provide_block_in, provide_transaction_in, provide_headers_in, check_block_msghash_in)
		{ construction_done(); }

private:
	std::vector<unsigned char> generate_version() {
		struct bitcoin_version_with_header version_msg;
		version_msg.version.start.timestamp = htole64(time(0));
		version_msg.version.start.user_agent_length = BITCOIN_UA_LENGTH; // Work around apparent gcc bug
		return std::vector<unsigned char>((unsigned char*)&version_msg, (unsigned char*)&version_msg + sizeof(version_msg));
	}
};


class RelayNetworkCompressor : public RelayNodeCompressor {
public:
	RelayNetworkCompressor() : RelayNodeCompressor(false) {}
	RelayNetworkCompressor(bool useFlagsAndSmallerMax) : RelayNodeCompressor(useFlagsAndSmallerMax) {}

	void relay_node_connected(RelayNetworkClient* client, int token) {
		for_each_sent_tx([&] (const std::shared_ptr<std::vector<unsigned char> >& tx) {
			client->receive_transaction(tx_to_msg(tx, false, false), token);
			client->receive_transaction(tx, token);
		});
	}
};

#define COMPRESSOR_TYPES 2
static RelayNetworkCompressor compressors[COMPRESSOR_TYPES];
class CompressorInit {
public:
	CompressorInit() {
		compressors[0] = RelayNetworkCompressor(false);
		compressors[1] = RelayNetworkCompressor(true);
	}
};
static CompressorInit init;


class MempoolClient : public OutboundPersistentConnection {
private:
	std::function<void(std::vector<unsigned char>)> on_hash;
public:
	MempoolClient(std::string serverHostIn, uint16_t serverPortIn, std::function<void(std::vector<unsigned char>)> on_hash_in)
		: OutboundPersistentConnection(serverHostIn, serverPortIn), on_hash(on_hash_in) { construction_done(); }

	void on_disconnect() {}

	void net_process(const std::function<void(std::string)>& disconnect) {
		while (true) {
			std::vector<unsigned char> hash(32);
			if (read_all((char*)&hash[0], 32, std::chrono::seconds(10)) != 32)
				return disconnect("Failed to read next hash");
			on_hash(hash);
		}
	}

	void keep_alive_ping() {
		char byte = 0x42;
		maybe_do_send_bytes(&byte, 1);
	}
};





int main(const int argc, const char** argv) {
	if (argc < 5) {
		printf("USAGE: %s trusted_host trusted_port trusted_port_2 \"Sponsor String\" (::ffff:whitelisted prefix string)*\n", argv[0]);
		return -1;
	}

	HOST_SPONSOR = argv[4];

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

	std::mutex txn_mutex;
	vectormruset txnWaitingToBroadcast(MAX_FAS_TOTAL_SIZE);

	const std::function<std::pair<const char*, size_t> (const std::vector<unsigned char>&, const std::vector<unsigned char>&, bool)> do_relay =
		[&](const std::vector<unsigned char>& fullhash, const std::vector<unsigned char>& bytes, bool checkMerkle) {
			std::lock_guard<std::mutex> lock(map_mutex);
			size_t ret;
			for (uint16_t i = 0; i < COMPRESSOR_TYPES; i++) {
				auto tuple = compressors[i].maybe_compress_block(fullhash, bytes, checkMerkle);
				const char* insane = std::get<1>(tuple);
				if (!insane) {
					auto block = std::get<0>(tuple);
					for (const auto& client : clientMap) {
						if (!client.second->getDisconnectFlags() && client.second->compressor_type == i)
							client.second->receive_block(block);
					}
					if (i == 0)
						ret = block->size();
				} else
					return std::make_pair(insane, (size_t)0);
			}
			return std::make_pair((const char*)0, ret);
		};

	trustedP2P = new P2PClient(argv[1], std::stoul(argv[2]),
					[&](std::vector<unsigned char>& bytes,  const std::chrono::system_clock::time_point& read_start) {
						if (bytes.size() < sizeof(struct bitcoin_msg_header) + 80)
							return;

						std::chrono::system_clock::time_point send_start(std::chrono::system_clock::now());

						std::vector<unsigned char> fullhash(32);
						getblockhash(fullhash, bytes, sizeof(struct bitcoin_msg_header));

						std::pair<const char*, size_t> relay_res = do_relay(fullhash, bytes, false);
						if (relay_res.first) {
							printf(HASH_FORMAT" INSANE %s TRUSTEDP2P\n", HASH_PRINT(&fullhash[0]), relay_res.first);
							return;
						} else
							localP2P->receive_block(bytes);

						std::chrono::system_clock::time_point send_end(std::chrono::system_clock::now());
						printf(HASH_FORMAT" BLOCK %lu %s TRUSTEDP2P %lu / %lu / %lu TIMES: %lf %lf\n", HASH_PRINT(&fullhash[0]), epoch_millis_lu(send_start), argv[1],
														bytes.size(), relay_res.second, bytes.size(),
														to_millis_double(send_start - read_start), to_millis_double(send_end - send_start));
					},
					[&](std::shared_ptr<std::vector<unsigned char> >& bytes) {
						std::vector<unsigned char> hash(32);
						double_sha256(&(*bytes)[0], &hash[0], bytes->size());
						{
							std::lock_guard<std::mutex> lock(txn_mutex);
							if (txnWaitingToBroadcast.find(hash) == txnWaitingToBroadcast.end())
								return;
						}
						std::lock_guard<std::mutex> lock(map_mutex);
						bool sentToLocal = false;
						for (uint16_t i = 0; i < COMPRESSOR_TYPES; i++) {
							auto tx = compressors[i].get_relay_transaction(bytes);
							if (tx.use_count()) {
								for (const auto& client : clientMap) {
									if (!client.second->getDisconnectFlags() && client.second->compressor_type == i)
										client.second->receive_transaction(tx);
								}
								if (!sentToLocal) {
									localP2P->receive_transaction(bytes);
									sentToLocal = true;
								}
							}
						}
					},
					[&](std::vector<unsigned char>& headers) {
						try {
							std::vector<unsigned char>::const_iterator it = headers.begin();
							uint64_t count = read_varint(it, headers.end());

							for (uint64_t i = 0; i < count; i++) {
								move_forward(it, 81, headers.end());

								if (*(it - 1) != 0)
									return;

								std::vector<unsigned char> fullhash(32);
								getblockhash(fullhash, headers, it - 81 - headers.begin());
								compressors[0].block_sent(fullhash);
							}

							printf("Added headers from trusted peers, seen %u blocks\n", compressors[0].blocks_sent());
						} catch (read_exception) { }
					}, true);

	MempoolClient mempoolClient(argv[1], std::stoul(argv[3]),
					[&](std::vector<unsigned char> txn) {
						std::lock_guard<std::mutex> lock(map_mutex);
						if (!compressors[0].was_tx_sent(&txn[0])) {
							std::lock_guard<std::mutex> lock(txn_mutex);
							txnWaitingToBroadcast.insert(txn);
							trustedP2P->request_transaction(txn);
						}
					});

	localP2P = new P2PClient("127.0.0.1", 8335,
					[&](std::vector<unsigned char>& bytes, const std::chrono::system_clock::time_point& read_start) {
						if (bytes.size() < sizeof(struct bitcoin_msg_header) + 80)
							return;

						std::chrono::system_clock::time_point send_start(std::chrono::system_clock::now());

						std::vector<unsigned char> fullhash(32);
						getblockhash(fullhash, bytes, sizeof(struct bitcoin_msg_header));

						std::pair<const char*, size_t> relay_res = do_relay(fullhash, bytes, true);
						if (relay_res.first) {
							printf(HASH_FORMAT" INSANE %s LOCALP2P\n", HASH_PRINT(&fullhash[0]), relay_res.first);
							return;
						} else
							localP2P->receive_block(bytes);

						trustedP2P->receive_block(bytes);

						std::chrono::system_clock::time_point send_end(std::chrono::system_clock::now());
						printf(HASH_FORMAT" BLOCK %lu %s LOCALP2P %lu / %lu / %lu TIMES: %lf %lf\n", HASH_PRINT(&fullhash[0]),
														epoch_millis_lu(send_start), "127.0.0.1",
														bytes.size(), relay_res.second, bytes.size(),
														to_millis_double(send_start - read_start), to_millis_double(send_end - send_start));
					},
					[&](std::shared_ptr<std::vector<unsigned char> >& bytes) {
						trustedP2P->receive_transaction(bytes);
					}, NULL, false);

	std::function<size_t (RelayNetworkClient*, std::shared_ptr<std::vector<unsigned char> >&, const std::vector<unsigned char>&)> relayBlock =
		[&](RelayNetworkClient* from, std::shared_ptr<std::vector<unsigned char>> & bytes, const std::vector<unsigned char>& fullhash) {
			if (bytes->size() < sizeof(struct bitcoin_msg_header) + 80)
				return (size_t)0;

			std::pair<const char*, size_t> relay_res = do_relay(fullhash, *bytes, false);
			if (relay_res.first) {
				printf(HASH_FORMAT" INSANE %s UNTRUSTEDRELAY %s\n", HASH_PRINT(&fullhash[0]), relay_res.first, from->host.c_str());
				return relay_res.second;
			} else
				localP2P->receive_block(*bytes);

			trustedP2P->receive_block(*bytes);

			return relay_res.second;
		};

	std::function<void (RelayNetworkClient*, std::shared_ptr<std::vector<unsigned char> >&)> relayTx =
		[&](RelayNetworkClient* from, std::shared_ptr<std::vector<unsigned char>> & bytes) {
			trustedP2P->receive_transaction(bytes);
		};

	std::function<void (RelayNetworkClient*, int token)> connected =
		[&](RelayNetworkClient* client, int token) {
			assert(client->compressor_type >= 0 && client->compressor_type < COMPRESSOR_TYPES);
			compressors[client->compressor_type].relay_node_connected(client, token);
		};

	std::thread([&](void) {
		while (true) {
			std::this_thread::sleep_for(std::chrono::seconds(10)); // Implicit new-connection rate-limit
			{
				std::lock_guard<std::mutex> lock(map_mutex);
				for (auto it = clientMap.begin(); it != clientMap.end();) {
					if (it->second->getDisconnectFlags() & DISCONNECT_COMPLETE) {
						fprintf(stderr, "%lld: Culled %s, have %lu relay clients\n", (long long) time(NULL), it->first.c_str(), clientMap.size() - 1);
						delete it->second;
						clientMap.erase(it++);
					} else
						it++;
				}
			}
			mempoolClient.keep_alive_ping();
		}
	}).detach();

	std::string droppostfix(".uptimerobot.com");
	std::vector<std::string> whitelistprefix;
	for (int i = 5; i < argc; i++)
		whitelistprefix.push_back(argv[i]);
	socklen_t addr_size = sizeof(addr);
	while (true) {
		int new_fd;
		if ((new_fd = accept(listen_fd, (struct sockaddr *) &addr, &addr_size)) < 0) {
			printf("Failed to select (%d: %s)\n", new_fd, strerror(errno));
			return -1;
		}

		std::string host = gethostname(&addr);
		std::lock_guard<std::mutex> lock(map_mutex);

		bool whitelist = false;
		for (const std::string& s : whitelistprefix)
			if (host.compare(0, s.length(), s) == 0)
				whitelist = true;

		if ((clientMap.count(host) && !whitelist) ||
				(host.length() > droppostfix.length() && !host.compare(host.length() - droppostfix.length(), droppostfix.length(), droppostfix))) {
			if (clientMap.count(host)) {
				const auto& client = clientMap[host];
				if (client->lastDupConnect < (time(NULL) - 60)) {
					client->lastDupConnect = time(NULL);
					fprintf(stderr, "%lld: Got duplicate connection from %s (original's disconnect status: %d)\n", (long long) time(NULL), host.c_str(), client->getDisconnectFlags());
				}
			}
			close(new_fd);
		} else {
			if (whitelist)
				host += ":" + std::to_string(addr.sin6_port);
			assert(clientMap.count(host) == 0);
			clientMap[host] = new RelayNetworkClient(new_fd, host, relayBlock, relayTx, connected);
			fprintf(stderr, "%lld: New connection from %s, have %lu relay clients\n", (long long) time(NULL), host.c_str(), clientMap.size());
		}
	}
}
