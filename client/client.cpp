#include <map>
#include <vector>
#include <thread>
#include <mutex>

#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "crypto/sha2.h"

#ifdef WIN32
	#include <winsock.h>
	#undef errno
	#define errno WSAGetLastError()

	#define MSG_NOSIGNAL 0

	// Windows is LE-only anyway...
	#define htole16(val) (val)
	#define htole32(val) (val)
	#define htole64(val) (val)
	#define le64toh(val) (val)
	#define le32toh(val) (val)
	#define le16toh(val) (val)
#else
	#include <netinet/tcp.h>
	#include <netdb.h>
	#include <fcntl.h>
	#include <endian.h>
#endif




/******************************
 **** FlaggedArraySet util ****
 ******************************/
struct ElemAndFlag {
	bool flag;
	std::shared_ptr<std::vector<unsigned char> > elem;
	ElemAndFlag(const std::shared_ptr<std::vector<unsigned char>>& elemIn, bool flagIn) : flag(flagIn), elem(elemIn) {}
	ElemAndFlag() {}
	bool operator <(const ElemAndFlag& o) const { return *elem < *o.elem; }
};

class FlaggedArraySet {
private:
	unsigned int maxSize, flag_count;
	uint64_t total, offset;
	std::map<ElemAndFlag, uint64_t> backingMap;
	std::map<uint64_t, ElemAndFlag> backingReverseMap;

public:
	FlaggedArraySet(unsigned int maxSizeIn) : maxSize(maxSizeIn) {}

	size_t size() { return backingMap.size(); }
	size_t flagCount() { return flag_count; }
	bool contains(const std::shared_ptr<std::vector<unsigned char> >& e) { return backingMap.count(ElemAndFlag(e, false)); }

private:
	void removed(uint64_t index) {
		if (index != offset) {
			auto start = backingReverseMap.find(index - 1);
			assert(start != backingReverseMap.end());
			auto it = std::map<uint64_t, ElemAndFlag>::reverse_iterator(start);
			it--;
			assert(it != backingReverseMap.rend() && it->first == start->first);

			for (; it != backingReverseMap.rend(); it++) {
				backingMap[it->second] = it->first + 1;
				backingReverseMap[it->first + 1] = it->second;
			}
			backingReverseMap.erase(offset);
		}
		offset++;
	}

	void remove(std::map<ElemAndFlag, uint64_t>::iterator it) {
		uint64_t index = it->second;
		if (it->first.flag)
			flag_count--;

		backingReverseMap.erase(it->second);
		backingMap.erase(it);

		removed(index);
	}

	void remove(std::map<uint64_t, ElemAndFlag>::iterator it) {
		uint64_t index = it->first;
		if (it->second.flag)
			flag_count--;

		backingMap.erase(it->second);
		backingReverseMap.erase(it);
		removed(index);
	}

public:
	void add(const std::shared_ptr<std::vector<unsigned char> >& e, bool flag) {
		if (contains(e))
			return;

		while (size() >= maxSize)
			remove(backingReverseMap.begin());

		backingMap[ElemAndFlag(e, flag)] = total;
		backingReverseMap[total++] = ElemAndFlag(e, flag);

		if (flag)
			flag_count++;
	}

	int remove(const std::shared_ptr<std::vector<unsigned char> >& e) {
		auto it = backingMap.find(ElemAndFlag(e, false));
		if (it == backingMap.end())
			return -1;

		int res = it->second - offset;
		remove(it);
		return res;
	}

	std::shared_ptr<std::vector<unsigned char> > remove(int index) {
		auto it = backingReverseMap.find(index + offset);
		if (it == backingReverseMap.end())
			return std::make_shared<std::vector<unsigned char> >();

		std::shared_ptr<std::vector<unsigned char> > e = it->second.elem;
		remove(it);
		return e;
	}

	void clear() {
		flag_count = 0; total = 0; offset = 0;
		backingMap.clear(); backingReverseMap.clear();
	}
};




/***************************
 **** Varint processing ****
 ***************************/
class read_exception : std::exception {};

inline void move_forward(std::vector<unsigned char>::const_iterator& it, size_t i, const std::vector<unsigned char>::const_iterator& end) {
	if (it > end-i)
		throw read_exception();
	std::advance(it, i);
}

inline uint64_t read_varint(std::vector<unsigned char>::const_iterator& it, const std::vector<unsigned char>::const_iterator& end) {
	move_forward(it, 1, end);
	uint8_t first = *(it-1);
	if (first < 0xfd)
		return first;
	else if (first == 0xfd) {
		move_forward(it, 2, end);
		return le16toh((*(it-1) << 8) | *(it-2));
	} else if (first == 0xfe) {
		move_forward(it, 4, end);
		return le32toh((*(it-1) << 24) | (*(it-2) << 16) | (*(it-3) << 8) | *(it-4));
	} else {
		move_forward(it, 8, end);
		return  le64toh((uint64_t(*(it-1)) << 56) |
						(uint64_t(*(it-2)) << 48) |
						(uint64_t(*(it-3)) << 40) |
						(uint64_t(*(it-4)) << 32) |
						(uint64_t(*(it-5)) << 24) |
						(uint64_t(*(it-6)) << 16) |
						(uint64_t(*(it-7)) << 8) |
						 uint64_t(*(it-8)));
	}
}

std::vector<unsigned char> varint(uint32_t size) {
	if (size < 0xfd) {
		uint8_t lesize = size;
		return std::vector<unsigned char>(&lesize, &lesize + sizeof(lesize));
	} else {
		std::vector<unsigned char> res;
		if (size <= 0xffff) {
			res.push_back(0xfd);
			uint16_t lesize = htole16(size);
			res.insert(res.end(), (unsigned char*)&lesize, ((unsigned char*)&lesize) + sizeof(lesize));
		} else if (size <= 0xffffffff) {
			res.push_back(0xfe);
			uint32_t lesize = htole32(size);
			res.insert(res.end(), (unsigned char*)&lesize, ((unsigned char*)&lesize) + sizeof(lesize));
		} else {
			res.push_back(0xff);
			uint64_t lesize = htole64(size);
			res.insert(res.end(), (unsigned char*)&lesize, ((unsigned char*)&lesize) + sizeof(lesize));
		}
		return res;
	}
}




/*************************
 **** Message structs ****
 *************************/
struct relay_msg_header {
	uint32_t magic, type, length;
};

#define RELAY_MAGIC_BYTES htonl(0xF2BEEF42)
#define VERSION_STRING "toucan twink"
#define MAX_RELAY_TRANSACTION_BYTES 10000
#define MAX_RELAY_OVERSIZE_TRANSACTION_BYTES 200000
#define MAX_EXTRA_OVERSIZE_TRANSACTIONS 25


#define BITCOIN_MAGIC htonl(0xf9beb4d9)
struct __attribute__((packed)) bitcoin_msg_header {
	uint32_t magic;
	char command[12];
	uint32_t length;
	unsigned char checksum[4];
};
static_assert(sizeof(struct bitcoin_msg_header) == 4 + 12 + 4 + 4, "__attribute__((packed)) must work");

struct __attribute__((packed)) bitcoin_version {
	uint32_t protocol_version = 70000;
	uint64_t services = 0;
	uint64_t timestamp;
	unsigned char addr_recv[26] = {0};
	unsigned char addr_from[26] = {0};
	uint64_t nonce = 0xDEADBEEF;
	char user_agent[1] = {0};
	int32_t start_height = 0;
};
static_assert(sizeof(struct bitcoin_version) == 4 + 8 + 8 + 26 + 26 + 8 + 1 + 4, "__attribute__((packed)) must work");

struct __attribute__((packed)) bitcoin_version_with_header{
	struct bitcoin_msg_header header;
	struct bitcoin_version version;
};
static_assert(sizeof(struct bitcoin_version_with_header) == (4 + 12 + 4 + 4) + (4 + 8 + 8 + 26 + 26 + 8 + 1 + 4), "__attribute__((packed)) must work");

#define RELAY_PASSED_BLOCK_PREFIX_SIZE sizeof(bitcoin_msg_header)





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

bool lookup_address(const char* addr, struct sockaddr_in* res) {
	struct hostent *server = gethostbyname(addr); // <-- memleak
	if (!server || !server->h_length)
		return false;

	memset((void*)res, 0, sizeof(*res));
	res->sin_family = AF_INET;
	memcpy((void*)&res->sin_addr, server->h_addr_list[0], sizeof(res->sin_addr));
	return true;
}




/***********************************************
 **** Relay network client processing class ****
 ***********************************************/
class RelayNetworkClient {
private:
	enum {
		VERSION_TYPE = 0,
		BLOCK_TYPE = 1,
		TRANSACTION_TYPE = 2,
		END_BLOCK_TYPE = 3,
		MAX_VERSION_TYPE = 4,
	};
	const char* server_host;

	const std::function<void (std::vector<unsigned char>&)> provide_block;
	const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)> provide_transaction;

	FlaggedArraySet recv_tx_cache, send_tx_cache;

	int sock;
	std::mutex send_mutex;
	std::thread* net_thread, *new_thread;

public:
	RelayNetworkClient(const char* serverHostIn,
						const std::function<void (std::vector<unsigned char>&)>& provide_block_in,
						const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)>& provide_transaction_in)
			: server_host(serverHostIn), provide_block(provide_block_in), provide_transaction(provide_transaction_in),
			recv_tx_cache(1525), send_tx_cache(1525), sock(0), net_thread(NULL), new_thread(NULL) {
		send_mutex.lock();
		new_thread = new std::thread(do_connect, this);
		send_mutex.unlock();
	}

	RelayNetworkClient() : recv_tx_cache(0), send_tx_cache(0) {} // Fake...

private:
	void reconnect(std::string disconnectReason, bool alreadyLocked=false) {
		if (!alreadyLocked)
			send_mutex.lock();

		if (sock) {
			printf("Closing relay socket, %s (%i: %s)\n", disconnectReason.c_str(), errno, errno ? strerror(errno) : "");
			#ifndef WIN32
				errno = 0;
			#endif
			close(sock);
		}

		sleep(1);

		new_thread = new std::thread(do_connect, this);
		send_mutex.unlock();
	}

	static void do_connect(RelayNetworkClient* me) {
		me->send_mutex.lock();

		if (me->net_thread)
			me->net_thread->join();
		me->net_thread = me->new_thread;

		me->sock = socket(AF_INET, SOCK_STREAM, 0);
		if (me->sock <= 0)
			return me->reconnect("unable to create socket", true);

		sockaddr_in addr;
		if (!lookup_address(me->server_host, &addr))
			return me->reconnect("unable to lookup host", true);

		addr.sin_port = htons(8336);
		if (connect(me->sock, (struct sockaddr*)&addr, sizeof(addr)))
			return me->reconnect("failed to connect()", true);

		#ifdef WIN32
			unsigned long nonblocking = 0;
			ioctlsocket(me->sock, FIONBIO, &nonblocking);
		#else
			fcntl(me->sock, F_SETFL, fcntl(me->sock, F_GETFL) & ~O_NONBLOCK);
		#endif

		me->net_process();
	}

	void net_process() {
		recv_tx_cache.clear();
		send_tx_cache.clear();

		relay_msg_header version_header = { RELAY_MAGIC_BYTES, htonl(VERSION_TYPE), htonl(strlen(VERSION_STRING)) };
		if (send_all(sock, (char*)&version_header, sizeof(version_header)) != sizeof(version_header))
			return reconnect("failed to write version header", true);
		if (send_all(sock, VERSION_STRING, strlen(VERSION_STRING)) != strlen(VERSION_STRING))
			return reconnect("failed to write version string", true);

		int nodelay = 1;
		setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));

		if (errno)
			return reconnect("error during connect", true);

		send_mutex.unlock();

		while (true) {
			relay_msg_header header;
			if (read_all(sock, (char*)&header, 4*3) != 4*3)
				return reconnect("failed to read message header");

			if (header.magic != RELAY_MAGIC_BYTES)
				return reconnect("invalid magic bytes");

			uint32_t message_size = ntohl(header.length);

			if (message_size > 1000000)
				return reconnect("got message too large");

			switch(ntohl(header.type)) {
			case VERSION_TYPE:
			{
				char data[message_size];
				if (read_all(sock, data, message_size) < (int64_t)(message_size))
					return reconnect("failed to read version message");

				if (strncmp(VERSION_STRING, data, std::min(sizeof(VERSION_STRING), size_t(message_size))))
					return reconnect("unknown version string");
				else
					printf("Connected to relay node with protocol version %s\n", VERSION_STRING);
			}
			break;

			case MAX_VERSION_TYPE:
			{
				char data[message_size];
				if (read_all(sock, data, message_size) < (int64_t)(message_size))
					return reconnect("failed to read max_version string");

				if (strncmp(VERSION_STRING, data, std::min(sizeof(VERSION_STRING), size_t(message_size))))
					return reconnect("relay network is using a later version (PLEASE UPGRADE)");
				else
					return reconnect("got MAX_VERSION of same version as us");
			}
			break;

			case BLOCK_TYPE:
			{
				if (message_size > 10000)
					return reconnect("got a BLOCK message with far too many transactions");

				unsigned int wire_bytes = 4*3;

				std::vector<unsigned char> block(RELAY_PASSED_BLOCK_PREFIX_SIZE + 80);
				block.reserve(1000000);

				if (read_all(sock, (char*)&block[RELAY_PASSED_BLOCK_PREFIX_SIZE], 80) != 80)
					return reconnect("failed to read block header");

				auto vartxcount = varint(message_size);
				block.insert(block.end(), vartxcount.begin(), vartxcount.end());

				for (uint32_t i = 0; i < message_size; i++) {
					uint16_t index;
					if (read_all(sock, (char*)&index, 2) != 2)
						return reconnect("failed to read tx index");
					index = ntohs(index);
					wire_bytes += 2;

					if (index == 0xffff) {
						union intbyte {
							uint32_t i;
							char c[4];
						} tx_size {0};

						if (read_all(sock, tx_size.c + 1, 3) != 3)
							return reconnect("failed to read tx length");
						tx_size.i = ntohl(tx_size.i);

						if (tx_size.i > 1000000)
							return reconnect("got unreasonably large tx ");

						block.insert(block.end(), tx_size.i, 0);
						if (read_all(sock, (char*)&block[block.size() - tx_size.i], tx_size.i) != int64_t(tx_size.i))
							return reconnect("failed to read transaction data");
						wire_bytes += 3 + tx_size.i;
					} else {
						std::shared_ptr<std::vector<unsigned char> > transaction_data = recv_tx_cache.remove(index);
						if (!transaction_data->size())
							return reconnect("failed to find referenced transaction");
						block.insert(block.end(), transaction_data->begin(), transaction_data->end());
					}
				}

				provide_block(block);
				printf("Got block of length %lu with %u bytes on the wire\n", (unsigned long)block.size(), wire_bytes);
			}
			break;

			case END_BLOCK_TYPE:
			break;

			case TRANSACTION_TYPE:
			{
				if (message_size > MAX_RELAY_TRANSACTION_BYTES && (recv_tx_cache.flagCount() >= MAX_EXTRA_OVERSIZE_TRANSACTIONS || message_size > MAX_RELAY_OVERSIZE_TRANSACTION_BYTES))
					return reconnect("got freely relayed transaction too large");

				auto tx = std::make_shared<std::vector<unsigned char> > (message_size);
				if (read_all(sock, (char*)&(*tx)[0], message_size) < (int64_t)(message_size))
					return reconnect("failed to read loose transaction data");

				recv_tx_cache.add(tx, message_size > MAX_RELAY_TRANSACTION_BYTES);
				provide_transaction(tx);
				printf("Received transaction of size %u from relay server\n", message_size);
			}
			break;

			default:
				return reconnect("got unknown message type");

			}
		}
	}

public:
	void receive_transaction(const std::shared_ptr<std::vector<unsigned char> >& tx) {
		if (!send_mutex.try_lock())
			return;

		if (send_tx_cache.contains(tx) ||
				(tx->size() > MAX_RELAY_TRANSACTION_BYTES &&
					(send_tx_cache.flagCount() >= MAX_EXTRA_OVERSIZE_TRANSACTIONS || tx->size() > MAX_RELAY_OVERSIZE_TRANSACTION_BYTES))) {
			send_mutex.unlock();
			return;
		}

		std::vector<unsigned char> msg(sizeof(struct relay_msg_header));
		struct relay_msg_header *header = (struct relay_msg_header*)&msg[0];
		header->magic = RELAY_MAGIC_BYTES;
		header->type = htonl(TRANSACTION_TYPE);
		header->length = htonl(tx->size());
		msg.insert(msg.end(), tx->begin(), tx->end());
		if (send_all(sock, (char*)&msg[0], msg.size()) != int(msg.size()))
			printf("Error sending transaction to relay server\n");
		else {
			send_tx_cache.add(tx, tx->size() > MAX_RELAY_OVERSIZE_TRANSACTION_BYTES);
			printf("Sent transaction of size %lu to relay server\n", (unsigned long)tx->size());
		}

		send_mutex.unlock();
	}

private:


public:
	void receive_block(const std::vector<unsigned char>& block) {
		if (!send_mutex.try_lock())
			return;

		std::vector<unsigned char> compressed_block;
		compressed_block.reserve(1100000);
		struct relay_msg_header header;

		try {
			std::vector<unsigned char>::const_iterator readit = block.begin();
			move_forward(readit, 80, block.end());
			uint32_t txcount = read_varint(readit, block.end());

			header.magic = RELAY_MAGIC_BYTES;
			header.type = htonl(BLOCK_TYPE);
			header.length = htonl(txcount);
			compressed_block.insert(compressed_block.end(), (unsigned char*)&header, ((unsigned char*)&header) + sizeof(header));
			compressed_block.insert(compressed_block.end(), block.begin(), block.begin() + 80);

			for (uint32_t i = 0; i < txcount; i++) {
				std::vector<unsigned char>::const_iterator txstart = readit;

				move_forward(readit, 4, block.end());

				uint32_t txins = read_varint(readit, block.end());
				for (uint32_t j = 0; j < txins; j++) {
					move_forward(readit, 36, block.end());
					uint32_t scriptlen = read_varint(readit, block.end());
					move_forward(readit, scriptlen + 4, block.end());
				}

				uint32_t txouts = read_varint(readit, block.end());
				for (uint32_t j = 0; j < txouts; j++) {
					move_forward(readit, 8, block.end());
					uint32_t scriptlen = read_varint(readit, block.end());
					move_forward(readit, scriptlen, block.end());
				}

				move_forward(readit, 4, block.end());

				auto lookupVector = std::make_shared<std::vector<unsigned char> >(txstart, readit);
				int index = send_tx_cache.remove(lookupVector);
				if (index < 0) {
					compressed_block.push_back(0xff);
					compressed_block.push_back(0xff);

					uint32_t txlen = readit - txstart;
					compressed_block.push_back((txlen >> 16) & 0xff);
					compressed_block.push_back((txlen >>  8) & 0xff);
					compressed_block.push_back((txlen      ) & 0xff);

					compressed_block.insert(compressed_block.end(), txstart, readit);
				} else {
					compressed_block.push_back((index >> 8) & 0xff);
					compressed_block.push_back((index     ) & 0xff);
				}
			}
		} catch(read_exception) {
			printf("Failed to process block from bitcoind\n");
			send_mutex.unlock();
			return;
		}

		if (send_all(sock, (char*)&compressed_block[0], compressed_block.size()) != int(compressed_block.size()))
			printf("Error sending block to relay server\n");
		else {
			header.type = htonl(END_BLOCK_TYPE);
			header.length = 0;
			if (send_all(sock, (char*)&header, sizeof(header)) != int(sizeof(header)))
				printf("Error sending end block message to relay server\n");
			else
				printf("Sent block of size %lu with %lu bytes on the wire\n", (unsigned long)block.size(), (unsigned long)compressed_block.size());
		}

		send_mutex.unlock();
	}
};

class P2PRelayer {
private:
	const char* server_host;
	uint16_t server_port;

	const std::function<void (std::vector<unsigned char>&)> provide_block;
	const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)> provide_transaction;

	int sock;
	std::mutex send_mutex;
	std::thread* net_thread, *new_thread;

public:
	P2PRelayer(const char* serverHostIn, uint16_t serverPortIn,
				const std::function<void (std::vector<unsigned char>&)>& provide_block_in,
				const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)>& provide_transaction_in)
			: server_host(serverHostIn), server_port(serverPortIn), provide_block(provide_block_in), provide_transaction(provide_transaction_in),
			sock(0), net_thread(NULL), new_thread(NULL) {
		send_mutex.lock();
		new_thread = new std::thread(do_connect, this);
		send_mutex.unlock();
	}

private:
	void reconnect(std::string disconnectReason, bool alreadyLocked=false) {
		if (!alreadyLocked)
			send_mutex.lock();

		if (sock) {
			printf("Closing bitcoind socket, %s (%i: %s)\n", disconnectReason.c_str(), errno, errno ? strerror(errno) : "");
			#ifndef WIN32
				errno = 0;
			#endif
			close(sock);
		}

		sleep(1);

		new_thread = new std::thread(do_connect, this);
		send_mutex.unlock();
	}

	static void do_connect(P2PRelayer* me) {
		me->send_mutex.lock();

		if (me->net_thread)
			me->net_thread->join();
		me->net_thread = me->new_thread;

		me->sock = socket(AF_INET, SOCK_STREAM, 0);
		if (me->sock <= 0)
			return me->reconnect("unable to create socket", true);

		sockaddr_in addr;
		if (!lookup_address(me->server_host, &addr))
			return me->reconnect("unable to lookup host", true);

		addr.sin_port = htons(me->server_port);
		if (connect(me->sock, (struct sockaddr*)&addr, sizeof(addr)))
			return me->reconnect("failed to connect()", true);

		#ifdef WIN32
			unsigned long nonblocking = 0;
			ioctlsocket(me->sock, FIONBIO, &nonblocking);
		#else
			fcntl(me->sock, F_SETFL, fcntl(me->sock, F_GETFL) & ~O_NONBLOCK);
		#endif

		me->net_process();
	}

	bool send_message(const char* command, unsigned char* data, size_t datalen) {
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

		return send_all(sock, (char*)header, sizeof(*header) + datalen) == int(sizeof(*header) + datalen);
	}

	void net_process() {
		struct bitcoin_version_with_header version_msg;
		version_msg.version.timestamp = htole64(time(0));
		if (!send_message("version", (unsigned char*)&version_msg, sizeof(struct bitcoin_version)))
			return reconnect("failed to send version message", true);

		int nodelay = 1;
		setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));

		if (errno)
			return reconnect("error during connect", true);

		send_mutex.unlock();

		while (true) {
			struct bitcoin_msg_header header;
			if (read_all(sock, (char*)&header, sizeof(header)) != sizeof(header))
				return reconnect("failed to read message header");

			if (header.magic != BITCOIN_MAGIC)
				return reconnect("invalid magic bytes");

			header.length = le32toh(header.length);
			if (header.length > 5000000)
				return reconnect("got message too large");

			auto msg = std::make_shared<std::vector<unsigned char> > (uint32_t(header.length));
			if (read_all(sock, (char*)&(*msg)[0], msg->size()) != int(msg->size()))
				return reconnect("failed to read message");

			unsigned char fullhash[32];
			CSHA256 hash;
			hash.Write(&(*msg)[0], header.length).Finalize(fullhash);
			hash.Reset().Write(fullhash, sizeof(fullhash)).Finalize(fullhash);
			if (memcmp((char*)fullhash, header.checksum, sizeof(header.checksum)))
				return reconnect("got invalid message checksum");

			if (!strncmp(header.command, "version", strlen("version"))) {
				if (header.length < sizeof(struct bitcoin_version))
					return reconnect("got short version");
				struct bitcoin_version *their_version = (struct bitcoin_version*) &(*msg)[0];

				printf("Connected to bitcoind with version %u\n", le32toh(their_version->protocol_version));
				struct bitcoin_msg_header new_header;
				send_message("verack", (unsigned char*)&new_header, 0);
			} else if (!strncmp(header.command, "verack", strlen("verack"))) {
				printf("Finished connect handshake with bitcoind\n");
			} else if (!strncmp(header.command, "ping", strlen("ping"))) {
				std::vector<unsigned char> resp(sizeof(struct bitcoin_msg_header) + header.length);
				resp.insert(resp.begin() + sizeof(struct bitcoin_msg_header), msg->begin(), msg->end());
				send_message("pong", &resp[0], header.length);
			} else if (!strncmp(header.command, "inv", strlen("inv"))) {
				std::vector<unsigned char> resp(sizeof(struct bitcoin_msg_header) + header.length);
				resp.insert(resp.begin() + sizeof(struct bitcoin_msg_header), msg->begin(), msg->end());
				send_message("getdata", &resp[0], header.length);
			} else if (!strncmp(header.command, "block", strlen("block"))) {
				provide_block(*msg);
			} else if (!strncmp(header.command, "tx", strlen("tx"))) {
				provide_transaction(msg);
			}
		}
	}

public:
	void receive_transaction(const std::shared_ptr<std::vector<unsigned char> >& tx) {
		if (!send_mutex.try_lock())
			return;
		std::vector<unsigned char> resp(sizeof(struct bitcoin_msg_header));
		resp.insert(resp.end(), tx->begin(), tx->end());
		send_message("tx", &resp[0], tx->size());
		send_mutex.unlock();
	}

	void receive_block(std::vector<unsigned char>& block) {
		if (!send_mutex.try_lock())
			return;
		send_message("block", &block[0], block.size() - RELAY_PASSED_BLOCK_PREFIX_SIZE);
		send_mutex.unlock();
	}
};

int main(int argc, char** argv) {
	if (argc != 4) {
		printf("USAGE: %s RELAY_SERVER BITCOIND_ADDRESS BITCOIND_PORT\n", argv[0]);
		return -1;
	}

#ifdef WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2,2), &wsaData))
		return -1;
#endif

	RelayNetworkClient* relayClient;
	P2PRelayer p2p(argv[2], std::stoul(argv[3]),
					[&](std::vector<unsigned char>& bytes) { relayClient->receive_block(bytes); },
					[&](std::shared_ptr<std::vector<unsigned char> >& bytes) { relayClient->receive_transaction(bytes); });
	relayClient = new RelayNetworkClient(argv[1],
										[&](std::vector<unsigned char>& bytes) { p2p.receive_block(bytes); },
										[&](std::shared_ptr<std::vector<unsigned char> >& bytes) { p2p.receive_transaction(bytes); });

	while (true) { sleep(1000); }
}
