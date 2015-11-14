#include "preinclude.h"

#include <map>
#include <vector>
#include <thread>
#include <chrono>
#include <mutex>
#include <set>

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>

#include "mruset.h"
#include "utils.h"
#include "connection.h"
#include "rpcclient.h"



class MempoolClient : public ThreadedConnection {
public:
	MempoolClient(int fd_in, std::string hostIn) : ThreadedConnection(fd_in, hostIn, NULL) { construction_done(); }
	void send_pool(std::set<std::vector<unsigned char> >::const_iterator mempool_begin, const std::set<std::vector<unsigned char> >::const_iterator mempool_end, int send_mutex=0) {
		while (mempool_begin != mempool_end) {
			assert(mempool_begin->size() == 32);
			do_send_bytes((const char*) &(*mempool_begin)[0], 32, send_mutex);
			mempool_begin++;
		}
	}
private:
	void net_process(const std::function<void(std::string)>& disconnect) {
		char buf[42];
		while (true) {
			ssize_t res = read_all(buf, 42);
			if (res != 42)
				return disconnect("Socket error reading bytes from mempool client");
		}
	}
};

int main(int argc, char** argv) {
	if (argc != 3 && argc != 4) {
		printf("USAGE: %s listen_port local_port [::ffff:whitelisted prefix string]\n", argv[0]);
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
	addr.sin6_port = htons(std::stoul(argv[1]));

	int reuse = 1;
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) ||
			bind(listen_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
			listen(listen_fd, 3) < 0) {
		printf("Failed to bind port: %s\n", strerror(errno));
		return -1;
	}

	std::mutex map_mutex;
	std::map<std::string, MempoolClient*> clientMap;

	std::mutex mempool_mutex;
	std::chrono::steady_clock::time_point last_mempool_request(std::chrono::steady_clock::time_point::min());
	vectormruset mempool(MAX_FAS_TOTAL_SIZE);

	uint8_t i = 0;
	uint64_t bytes_sent = 0;
	uint32_t txn_sent = 0;
	std::chrono::steady_clock::time_point last_mempool_print(std::chrono::steady_clock::now());
	RPCClient rpcTrustedP2P("127.0.0.1", std::stoul(argv[2]),
					[&](std::vector<std::pair<std::vector<unsigned char>, size_t> >& txn_list, size_t total_mempool_size) {
						std::set<std::vector<unsigned char> > new_txn;
						{
							std::lock_guard<std::mutex> lock(mempool_mutex);

							// 62500 bytes per sec == 500Kbps
							uint64_t size_gathered = 0, size_to_gather = 62500*to_millis_lu(std::chrono::steady_clock::now() - last_mempool_request)/1000;
							last_mempool_request = std::chrono::steady_clock::now();

							for (const auto& txn : txn_list) {
								if (mempool.insert(txn.first).second) {
									new_txn.insert(txn.first);
									size_gathered += txn.second;
									bytes_sent += txn.second;
									txn_sent++;
								}
								if (size_gathered >= size_to_gather)
									break;
							}
						}

						if (++i == 0) {
							printf("Sent %u (%lu bytes) txn over the past %lf ms, current total mempool size %lu\n", txn_sent, bytes_sent, to_millis_double(std::chrono::steady_clock::now() - last_mempool_print), total_mempool_size);
							last_mempool_print = std::chrono::steady_clock::now();
							bytes_sent = 0;
							txn_sent = 0;
						}

						std::lock_guard<std::mutex> lock(map_mutex);
						for (auto it = clientMap.begin(); it != clientMap.end(); it++) {
							if (!it->second->getDisconnectFlags())
								it->second->send_pool(new_txn.begin(), new_txn.end());
						}
					});

	std::thread([&](void) {
		while (true) {
			std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Implicit new-connection rate-limit
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
			rpcTrustedP2P.maybe_get_txn_for_block();
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
				fprintf(stderr, "%lld: Got duplicate connection from %s (original's disconnect status: %d)\n", (long long) time(NULL), host.c_str(), client->getDisconnectFlags());
			}
			close(new_fd);
		} else {
			if (host.compare(0, whitelistprefix.length(), whitelistprefix) == 0)
				host += ":" + std::to_string(addr.sin6_port);
			assert(clientMap.count(host) == 0);

			MempoolClient* client = new MempoolClient(new_fd, host);
			clientMap[host] = client;
			fprintf(stderr, "%lld: New connection from %s, have %lu relay clients\n", (long long) time(NULL), host.c_str(), clientMap.size());

			int send_mutex = client->get_send_mutex();
			{
				std::lock_guard<std::mutex> lock(mempool_mutex);
				client->send_pool(mempool.begin(), mempool.end(), send_mutex);
			}
			client->release_send_mutex(send_mutex);
		}
	}
}
