#include <list>
#include <set>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>

#include <assert.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/time.h>

#include "crypto/sha2.h"



/*************************
 **** Message structs ****
 *************************/
#define BITCOIN_MAGIC htonl(0xf9beb4d9)
struct __attribute__((packed)) bitcoin_msg_header {
	uint32_t magic;
	char command[12];
	uint32_t length;
	unsigned char checksum[4];
};
static_assert(sizeof(struct bitcoin_msg_header) == 4 + 12 + 4 + 4, "__attribute__((packed)) must work");

char* location;
struct __attribute__((packed)) bitcoin_version_start {
	uint32_t protocol_version = 70000;
	uint64_t services = 0;
	uint64_t timestamp;
	unsigned char addr_recv[26] = {0};
	unsigned char addr_from[26] = {0};
	uint64_t nonce = 0xDEADBEEF;
	uint8_t user_agent_length = 27 + 9;
};
static_assert(sizeof(struct bitcoin_version_start) == 4 + 8 + 8 + 26 + 26 + 8 + 1, "__attribute__((packed)) must work");

struct __attribute__((packed)) bitcoin_version_end {
	// Begins with what is (usually) the UA
	char user_agent[27] = {'/', 'R', 'e', 'l', 'a', 'y', 'N', 'e', 't', 'w', 'o', 'r', 'k', 'T', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'o', 'r', ':', '4', '2', '/'};
	char location[9] = {0, 0, 0, 0, 0, 0, 0, '/', '0'};
	int32_t start_height = 0;
};
static_assert(sizeof(struct bitcoin_version_end) == 36 + 4, "__attribute__((packed)) must work");

struct __attribute__((packed)) bitcoin_version_with_header{
	struct bitcoin_msg_header header;
	struct bitcoin_version_start start;
	struct bitcoin_version_end end;
};
static_assert(sizeof(struct bitcoin_version_with_header) == (4 + 12 + 4 + 4) + (4 + 8 + 8 + 26 + 26 + 8 + 1) + (36 + 4), "__attribute__((packed)) must work");




/***********************
 **** Network utils ****
 ***********************/
ssize_t read_all(int filedes, char *buf, size_t nbyte) {
	if (nbyte <= 0)
		return 0;

	ssize_t count = 0;
	size_t total = 0;
	while (total < nbyte && (count = recv(filedes, buf + total, nbyte-total, 0)) > 0)
		total += count;
	if (count <= 0)
		return count;
	else
		return total;
}

ssize_t send_all(int filedes, const char *buf, size_t nbyte) {
	ssize_t count = 0;
	size_t total = 0;
	while (total < nbyte && (count = send(filedes, buf + total, nbyte-total, MSG_NOSIGNAL)) > 0)
		total += count;
	if (count <= 0)
		return count;
	else
		return total;
}

std::string gethostname(struct sockaddr_in6 *addr) {
	char hbuf[NI_MAXHOST];
	if (getnameinfo((struct sockaddr*) addr, sizeof(*addr), hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST))
		return "Unknown host";

	std::string res(hbuf);
	res += "/";
	if (getnameinfo((struct sockaddr*) addr, sizeof(*addr), hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD))
		return res;
	else
		return res + std::string(hbuf);
}




/***********************
 **** Network utils ****
 ***********************/
class P2PRelayer {
private:
	const std::string host;

	const std::function<void (P2PRelayer*, std::shared_ptr<std::vector<unsigned char> >&)> provide_block;
	const std::function<void (P2PRelayer*, std::shared_ptr<std::vector<unsigned char> >&)> provide_transaction;

	const int sock;
	std::mutex send_mutex;
	int connected;

	std::condition_variable cv;
	std::list<std::shared_ptr<std::vector<unsigned char> > > outbound_tx_queue;
	std::list<std::shared_ptr<std::vector<unsigned char> > > outbound_block_queue;
	uint32_t total_waiting_size;

	std::thread *read_thread, *write_thread;

public:
	std::atomic<int> disconnectFlags;

	P2PRelayer(int sockIn, std::string hostIn,
				const std::function<void (P2PRelayer*, std::shared_ptr<std::vector<unsigned char> >&)>& provide_block_in,
				const std::function<void (P2PRelayer*, std::shared_ptr<std::vector<unsigned char> >&)>& provide_transaction_in)
			: host(hostIn), provide_block(provide_block_in), provide_transaction(provide_transaction_in),
			sock(sockIn), connected(0), total_waiting_size(0), disconnectFlags(0) {
		send_mutex.lock();
		read_thread = new std::thread(do_setup_and_read, this);
		write_thread = new std::thread(do_write, this);
		send_mutex.unlock();
	}

	~P2PRelayer() {
		if (disconnectFlags & 4)
			write_thread->join();
		else
			read_thread->join();
		delete read_thread;
		delete write_thread;
	}

private:
	void disconnect(const char* reason) {
		if (disconnectFlags.fetch_or(1) & 1)
			return;

		printf("%s Disconnect: %s (%s)\n", host.c_str(), reason, strerror(errno));

		close(sock);

		if (std::this_thread::get_id() != read_thread->get_id()) {
			read_thread->join();
			disconnectFlags |= 4;
		} else {
			if (connected == 2)
				send_mutex.lock();

			outbound_tx_queue.push_back(std::make_shared<std::vector<unsigned char> >(1));
			cv.notify_all();
			send_mutex.unlock();

			write_thread->join();
		}

		outbound_tx_queue.clear();
		outbound_block_queue.clear();

		disconnectFlags |= 2;
	}

	static void do_setup_and_read(P2PRelayer* me) {
		me->send_mutex.lock();

		fcntl(me->sock, F_SETFL, fcntl(me->sock, F_GETFL) & ~O_NONBLOCK);

		int nodelay = 1;
		setsockopt(me->sock, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));

		if (errno)
			return me->disconnect("error during connect");

		me->net_process();
	}

	void prepare_message(const char* command, unsigned char* data, size_t datalen) {
		struct bitcoin_msg_header *header = (struct bitcoin_msg_header*)data;

		memset(header->command, 0, sizeof(header->command));
		strcpy(header->command, command);

		header->length = htole32(datalen);
		header->magic = BITCOIN_MAGIC;

		unsigned char fullhash[32];
		CSHA256 hash; // Probably not BE-safe
		hash.Write(data + sizeof(struct bitcoin_msg_header), datalen).Finalize(fullhash);
		hash.Reset().Write(fullhash, sizeof(fullhash)).Finalize(fullhash);
		memcpy(header->checksum, fullhash, sizeof(header->checksum));
	}

	void net_process() {
		while (true) {
			struct bitcoin_msg_header header;
			if (read_all(sock, (char*)&header, sizeof(header)) != sizeof(header))
				return disconnect("failed to read message header");

			if (header.magic != BITCOIN_MAGIC)
				return disconnect("invalid magic bytes");

			header.length = le32toh(header.length);
			if (header.length > 5000000)
				return disconnect("got message too large");

			auto msg = std::make_shared<std::vector<unsigned char> > (sizeof(struct bitcoin_msg_header) + uint32_t(header.length));
			if (read_all(sock, (char*)&(*msg)[sizeof(struct bitcoin_msg_header)], header.length) != int(header.length))
				return disconnect("failed to read message");

			unsigned char fullhash[32];
			CSHA256 hash;
			hash.Write(&(*msg)[sizeof(struct bitcoin_msg_header)], header.length).Finalize(fullhash);
			hash.Reset().Write(fullhash, sizeof(fullhash)).Finalize(fullhash);
			if (memcmp((char*)fullhash, header.checksum, sizeof(header.checksum)))
				return disconnect("got invalid message checksum");

			if (!strncmp(header.command, "version", strlen("version"))) {
				if (connected != 0)
					return disconnect("got invalid version");
				connected = 1;

				if (header.length < sizeof(struct bitcoin_version_start))
					return disconnect("got short version");
				struct bitcoin_version_start *their_version = (struct bitcoin_version_start*) &(*msg)[sizeof(struct bitcoin_msg_header)];

				printf("%s Protocol version %u\n", host.c_str(), le32toh(their_version->protocol_version));

				struct bitcoin_version_with_header version_msg;
				version_msg.start.timestamp = htole64(time(0));
				memcpy(&version_msg.end.location, location, 7);
				if (!strncmp("/BitCoinJ:0.12-SNAPSHOT/RelayNode:", (char*) &(*msg)[sizeof(struct bitcoin_msg_header) + sizeof(struct bitcoin_version_start)],
						std::min(header.length - sizeof(struct bitcoin_version_start), strlen("/BitCoinJ:0.12-SNAPSHOT/RelayNode:")))) {
					version_msg.start.services = htole64(1);
					version_msg.end.start_height = 1;
				}

				prepare_message("version", (unsigned char*)&version_msg, sizeof(struct bitcoin_version_start) + sizeof(struct bitcoin_version_end));
				if (send_all(sock, (char*)&version_msg, sizeof(struct bitcoin_version_with_header)) != sizeof(struct bitcoin_version_with_header))
					return disconnect("failed to send version message");

				struct bitcoin_msg_header verack_header;
				prepare_message("verack", (unsigned char*)&verack_header, 0);
				if (send_all(sock, (char*)&verack_header, sizeof(struct bitcoin_msg_header)) != sizeof(struct bitcoin_msg_header))
					return disconnect("failed to send verack");

				continue;
			} else if (!strncmp(header.command, "verack", strlen("verack"))) {
				if (connected != 1)
					return disconnect("got invalid verack");
				connected = 2;
				send_mutex.unlock();

				continue;
			}

			if (!strncmp(header.command, "ping", strlen("ping"))) {
				memcpy(&header.command, "pong", sizeof("pong"));
				memcpy(&(*msg)[0], &header, sizeof(struct bitcoin_msg_header));
				if (send_all(sock, (char*)&(*msg)[0], sizeof(struct bitcoin_msg_header) + header.length) != int64_t(sizeof(struct bitcoin_msg_header) + header.length))
					return disconnect("failed to send pong");
				continue;
			} else if (!strncmp(header.command, "inv", strlen("inv"))) {
				memcpy(&header.command, "getdata", sizeof("getdata"));
				memcpy(&(*msg)[0], &header, sizeof(struct bitcoin_msg_header));
				if (send_all(sock, (char*)&(*msg)[0], sizeof(struct bitcoin_msg_header) + header.length) != int64_t(sizeof(struct bitcoin_msg_header) + header.length))
					return disconnect("failed to send pong");
				continue;
			}

			memcpy(&(*msg)[0], &header, sizeof(struct bitcoin_msg_header));
			if (!strncmp(header.command, "block", strlen("block"))) {
				struct timeval tv;
				gettimeofday(&tv, NULL);
				printf("%s BLOCK %lu\n", host.c_str(), uint64_t(tv.tv_sec) * 1000 + uint64_t(tv.tv_usec) / 1000);
				provide_block(this, msg);
			} else if (!strncmp(header.command, "tx", strlen("tx"))) {
				provide_transaction(this, msg);
			}
		}
	}

private:
	static void do_write(P2PRelayer* me) {
		me->net_write();
	}

	void net_write() {
		while (true) {
			std::shared_ptr<std::vector<unsigned char> > msg;
			{
				std::unique_lock<std::mutex> write_lock(send_mutex);
				while (!outbound_tx_queue.size() && !outbound_block_queue.size())
					cv.wait(write_lock);

				if (outbound_block_queue.size()) {
					msg = outbound_block_queue.front();
					outbound_block_queue.pop_front();
				} else {
					msg = outbound_tx_queue.front();
					outbound_tx_queue.pop_front();
				}
			}
			if (send_all(sock, (char*)&(*msg)[0], msg->size()) != int64_t(msg->size()))
				return disconnect("failed to send msg");
		}
	}

public:
	void receive_transaction(const std::shared_ptr<std::vector<unsigned char> >& tx) {
		#ifndef FOR_VALGRIND
			if (!send_mutex.try_lock())
				return;
		#else
			send_mutex.lock();
		#endif

		if (total_waiting_size >= 1500000)
			return;
		outbound_tx_queue.push_back(tx);
		total_waiting_size += tx->size();
		cv.notify_all();
		send_mutex.unlock();
	}

	void receive_block(const std::shared_ptr<std::vector<unsigned char> >& block) {
		send_mutex.lock();
		if (total_waiting_size >= 3000000)
			return;

		outbound_block_queue.push_back(block);
		total_waiting_size += block->size();
		cv.notify_all();
		send_mutex.unlock();
	}
};

int blockonly_fd, txes_fd;
void handle_death(int param) {
	close(blockonly_fd);
	close(txes_fd);
	exit(1);
}

int main(int argc, char** argv) {
	if (argc != 2 || strlen(argv[1]) != 7) {
		printf("USAGE %s 7-char-LOCATION\n", argv[0]);
		return -1;
	}
	location = argv[1];

	int new_fd;
	struct sockaddr_in6 addr;

	fd_set twofds;
	FD_ZERO(&twofds);

	signal(SIGINT, handle_death);

	if ((blockonly_fd = socket(AF_INET6, SOCK_STREAM, 0)) < 0 ||
		     (txes_fd = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
		printf("Failed to create socket\n");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_any;
	addr.sin6_port = htons(8334);

	if (bind(blockonly_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
			listen(blockonly_fd, 3) < 0) {
		printf("Failed to bind 8334: %s\n", strerror(errno));
		return -1;
	}

	addr.sin6_port = htons(8335);
	if (bind(txes_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
			listen(txes_fd, 3) < 0) {
		printf("Failed to bind 8335: %s\n", strerror(errno));
		return -1;
	}

	std::mutex list_mutex;
	std::set<P2PRelayer*> blockSet;
	std::set<P2PRelayer*> txesSet;
	std::set<P2PRelayer*> localSet;

	std::function<void (P2PRelayer*, std::shared_ptr<std::vector<unsigned char> >&)> relayBlock =
		[&](P2PRelayer* from, std::shared_ptr<std::vector<unsigned char>> & bytes) {
			std::unique_lock<std::mutex> lock(list_mutex);
			std::set<P2PRelayer*> *set;
			if (localSet.count(from))
				set = &blockSet;
			else
				set = &localSet;
			for (auto it = set->begin(); it != set->end(); it++) {
				if (!(*it)->disconnectFlags)
					(*it)->receive_transaction(bytes);
			}
		};
	std::function<void (P2PRelayer*, std::shared_ptr<std::vector<unsigned char> >&)> relayTx =
		[&](P2PRelayer* from, std::shared_ptr<std::vector<unsigned char> >& bytes) {
			std::unique_lock<std::mutex> lock(list_mutex);
			std::set<P2PRelayer*> *set;
			if (localSet.count(from))
				set = &txesSet;
			else
				set = &localSet;
			for (auto it = set->begin(); it != set->end(); it++) {
				if (!(*it)->disconnectFlags)
					(*it)->receive_transaction(bytes);
			}
		};

	printf("Awaiting connections\n");

	while (true) {
		FD_SET(blockonly_fd, &twofds);
		FD_SET(txes_fd, &twofds);
		struct timeval timeout;
		timeout.tv_sec = 30;
		timeout.tv_usec = 0;

		if (select(FD_SETSIZE, &twofds, NULL, NULL, &timeout) < 0) {
			printf("Failed to select\n");
			return -1;
		}

		socklen_t addr_size = sizeof(addr);
		std::string localhost("::ffff:127.0.0.1");
		std::string droppostfix(".uptimerobot.com");
		if (FD_ISSET(blockonly_fd, &twofds)) {
			if ((new_fd = accept(blockonly_fd, (struct sockaddr *) &addr, &addr_size)) < 0) {
				printf("Failed to accept\n");
				return -1;
			}

			std::string host = gethostname(&addr);
			if (host.length() > droppostfix.length() && !host.compare(host.length() - droppostfix.length(), droppostfix.length(), droppostfix))
				close(new_fd);
			else {
				std::unique_lock<std::mutex> lock(list_mutex);
				P2PRelayer *relay = new P2PRelayer(new_fd, host, relayBlock, relayTx);
				if (!host.compare(0, localhost.size(), localhost))
					localSet.insert(relay);
				else
					blockSet.insert(relay);
			}
		}
		if (FD_ISSET(txes_fd, &twofds)) {
			if ((new_fd = accept(txes_fd, (struct sockaddr *) &addr, &addr_size)) < 0) {
				printf("Failed to accept\n");
				return -1;
			}

			std::string host = gethostname(&addr);
			if (host.length() > droppostfix.length() && !host.compare(host.length() - droppostfix.length(), droppostfix.length(), droppostfix))
				close(new_fd);
			else {
				std::unique_lock<std::mutex> lock(list_mutex);
				P2PRelayer *relay = new P2PRelayer(new_fd, host, relayBlock, relayTx);
				if (!host.compare(0, localhost.size(), localhost))
					localSet.insert(relay);
				else {
					blockSet.insert(relay);
					txesSet.insert(relay);
				}
			}
		}

		std::unique_lock<std::mutex> lock(list_mutex);
		for (auto it = blockSet.begin(); it != blockSet.end();) {
			if ((*it)->disconnectFlags & 2) {
				auto rm = it++; auto item = *rm;
				txesSet.erase(item);
				blockSet.erase(rm);
				delete item;
			} else
				it++;
		}
		for (auto it = localSet.begin(); it != localSet.end();) {
			if ((*it)->disconnectFlags & 2) {
				auto rm = it++; auto item = *rm;
				localSet.erase(rm);
				delete item;
			} else
				it++;
		}
		fprintf(stderr, "Have %lu local connection(s), %lu block connection(s) and %lu txes conenction(s)\n", localSet.size(), blockSet.size() - txesSet.size(), txesSet.size());
	}
}
