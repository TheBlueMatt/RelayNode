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

#include "lzmaconnection.h"



int main(int argc, char** argv) {
	if (argc != 3 && argc != 4) {
		printf("USAGE: %s listen_port local_port [whitelist prefix]\n", argv[0]);
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
		printf("Failed to bind listen port: %s\n", strerror(errno));
		return -1;
	}

	std::mutex map_mutex;
	std::map<std::string, LZMAConnection*> clientMap;

	std::thread([&](void) {
		while (true) {
			std::this_thread::sleep_for(std::chrono::seconds(10)); // Implicit new-connection rate-limit
			{
				std::lock_guard<std::mutex> lock(map_mutex);
				for (auto it = clientMap.begin(); it != clientMap.end();) {
					if (it->second->getDisconnectFlags() & DISCONNECT_COMPLETE) {
						fprintf(stderr, "%lld: Culled %s, have %lu clients\n", (long long) time(NULL), it->first.c_str(), clientMap.size() - 1);
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
				fprintf(stderr, "%lld: Got duplicate connection from %s (original's disconnect status: %d)\n", (long long) time(NULL), host.c_str(), client->getDisconnectFlags());
			}
			close(new_fd);
		} else {
			if (host.compare(0, whitelistprefix.length(), whitelistprefix) == 0)
				host += ":" + std::to_string(addr.sin6_port);
			assert(clientMap.count(host) == 0);

			std::string error_string;
			int out_fd = create_connect_socket("127.0.0.1", std::stoul(argv[2]), error_string);
			if (out_fd <= 0) {
				fprintf(stderr, "Failed to make local connection: %s (%s)\n", error_string.c_str(), strerror(errno));
				close(new_fd);
			} else {
				clientMap[host] = new LZMAConnection(new_fd, host, out_fd);
				fprintf(stderr, "%lld: New connection from %s, have %lu clients\n", (long long) time(NULL), host.c_str(), clientMap.size());
			}
		}
	}
}
