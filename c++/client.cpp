#include <map>
#include <vector>
#include <thread>
#include <mutex>

#include <assert.h>
#include <string.h>
#include <unistd.h>

#ifdef WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
#else // WIN32
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
class RelayNetworkClient {
private:
	RELAY_DECLARE_CLASS_VARS

	const char* server_host;

	const std::function<void (std::vector<unsigned char>&)> provide_block;
	const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)> provide_transaction;

	int sock;
	std::mutex send_mutex;
	std::thread* net_thread, *new_thread;

public:
	RelayNetworkClient(const char* serverHostIn,
						const std::function<void (std::vector<unsigned char>&)>& provide_block_in,
						const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)>& provide_transaction_in)
			: RELAY_DECLARE_CONSTRUCTOR_EXTENDS,
			server_host(serverHostIn), provide_block(provide_block_in), provide_transaction(provide_transaction_in),
			sock(0), net_thread(NULL), new_thread(NULL) {
		send_mutex.lock();
		new_thread = new std::thread(do_connect, this);
		send_mutex.unlock();
	}

	RelayNetworkClient() : RELAY_DECLARE_CONSTRUCTOR_EXTENDS {} // Fake...

	RELAY_DECLARE_FUNCTIONS

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

		me->sock = socket(AF_INET6, SOCK_STREAM, 0);
		if (me->sock <= 0)
			return me->reconnect("unable to create socket", true);

		sockaddr_in6 addr;
		if (!lookup_address(me->server_host, &addr))
			return me->reconnect("unable to lookup host", true);

		int v6only = 0;
		setsockopt(me->sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&v6only, sizeof(v6only));

		addr.sin6_port = htons(8336);
		if (connect(me->sock, (struct sockaddr*)&addr, sizeof(addr)))
			return me->reconnect("failed to connect()", true);

		#ifdef WIN32
			unsigned long nonblocking = 0;
			ioctlsocket(me->sock, FIONBIO, &nonblocking);
		#else
			fcntl(me->sock, F_SETFL, fcntl(me->sock, F_GETFL) & ~O_NONBLOCK);
		#endif

		#ifdef X86_BSD
			int nosigpipe = 1;
			setsockopt(me->sock, SOL_SOCKET, SO_NOSIGPIPE, (void *)&nosigpipe, sizeof(int));
		#endif

		me->net_process();
	}

	void net_process() {
		recv_tx_cache.clear();
		send_tx_cache.clear();

		relay_msg_header version_header = { RELAY_MAGIC_BYTES, VERSION_TYPE, htonl(strlen(VERSION_STRING)) };
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

			if (header.type == VERSION_TYPE) {
				char data[message_size];
				if (read_all(sock, data, message_size) < (int64_t)(message_size))
					return reconnect("failed to read version message");

				if (strncmp(VERSION_STRING, data, std::min(sizeof(VERSION_STRING), size_t(message_size))))
					return reconnect("unknown version string");
				else
					printf("Connected to relay node with protocol version %s\n", VERSION_STRING);
			} else if (header.type == MAX_VERSION_TYPE) {
				char data[message_size];
				if (read_all(sock, data, message_size) < (int64_t)(message_size))
					return reconnect("failed to read max_version string");

				if (strncmp(VERSION_STRING, data, std::min(sizeof(VERSION_STRING), size_t(message_size))))
					printf("Relay network is using a later version (PLEASE UPGRADE)\n");
				else
					return reconnect("got MAX_VERSION of same version as us");
			} else if (header.type == BLOCK_TYPE) {
				auto res = decompressRelayBlock(sock, message_size);
				if (std::get<2>(res))
					return reconnect(std::get<2>(res));

				provide_block(*std::get<1>(res));

				std::vector<unsigned char> fullhash(32);
				CSHA256 hash; // Probably not BE-safe
				hash.Write(&(*std::get<1>(res))[sizeof(struct bitcoin_msg_header)], 80).Finalize(&fullhash[0]);
				hash.Reset().Write(&fullhash[0], fullhash.size()).Finalize(&fullhash[0]);
				for (unsigned int i = 0; i < fullhash.size(); i++)
					printf("%02x", fullhash[fullhash.size() - i - 1]);
				printf(" recv'd, size %lu with %u bytes on the wire\n", (unsigned long)std::get<1>(res)->size() - sizeof(bitcoin_msg_header), std::get<0>(res));
			} else if (header.type == END_BLOCK_TYPE) {
			} else if (header.type == TRANSACTION_TYPE) {
				if (message_size > MAX_RELAY_TRANSACTION_BYTES && (recv_tx_cache.flagCount() >= MAX_EXTRA_OVERSIZE_TRANSACTIONS || message_size > MAX_RELAY_OVERSIZE_TRANSACTION_BYTES))
					return reconnect("got freely relayed transaction too large");

				auto tx = std::make_shared<std::vector<unsigned char> > (message_size);
				if (read_all(sock, (char*)&(*tx)[0], message_size) < (int64_t)(message_size))
					return reconnect("failed to read loose transaction data");

				recv_tx_cache.add(tx, message_size > MAX_RELAY_TRANSACTION_BYTES);
				provide_transaction(tx);
				printf("Received transaction of size %u from relay server\n", message_size);
			} else
				return reconnect("got unknown message type");
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

		if (send_tx_cache.contains(tx) ||
				(tx->size() > MAX_RELAY_TRANSACTION_BYTES &&
					(send_tx_cache.flagCount() >= MAX_EXTRA_OVERSIZE_TRANSACTIONS || tx->size() > MAX_RELAY_OVERSIZE_TRANSACTION_BYTES))) {
			send_mutex.unlock();
			return;
		}

		std::vector<unsigned char> msg(sizeof(struct relay_msg_header));
		struct relay_msg_header *header = (struct relay_msg_header*)&msg[0];
		header->magic = RELAY_MAGIC_BYTES;
		header->type = TRANSACTION_TYPE;
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

	void receive_block(const std::vector<unsigned char>& block) {
		#ifndef FOR_VALGRIND
			if (!send_mutex.try_lock())
				return;
		#else
			send_mutex.lock();
		#endif

		auto compressed_block = compressRelayBlock(block);
		if (!compressed_block->size()) {
			printf("Failed to process block from bitcoind\n");
			send_mutex.unlock();
			return;
		}

		if (send_all(sock, (char*)&(*compressed_block)[0], compressed_block->size()) != int(compressed_block->size()))
			printf("Error sending block to relay server\n");
		else {
			struct relay_msg_header header = { RELAY_MAGIC_BYTES, END_BLOCK_TYPE, 0 };
			if (send_all(sock, (char*)&header, sizeof(header)) != int(sizeof(header)))
				printf("Error sending end block message to relay server\n");
			else {
				std::vector<unsigned char> fullhash(32);
				CSHA256 hash; // Probably not BE-safe
				hash.Write(&block[sizeof(struct bitcoin_msg_header)], 80).Finalize(&fullhash[0]);
				hash.Reset().Write(&fullhash[0], fullhash.size()).Finalize(&fullhash[0]);
				for (unsigned int i = 0; i < fullhash.size(); i++)
					printf("%02x", fullhash[fullhash.size() - i - 1]);
				printf(" sent, size %lu with %lu bytes on the wire\n", (unsigned long)block.size(), (unsigned long)compressed_block->size());
			}
		}

		send_mutex.unlock();
	}
};

class P2PClient : public P2PRelayer {
public:
	P2PClient(const char* serverHostIn, uint16_t serverPortIn,
				const std::function<void (std::vector<unsigned char>&, struct timeval)>& provide_block_in,
				const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)>& provide_transaction_in) :
			P2PRelayer(serverHostIn, serverPortIn, provide_block_in, provide_transaction_in) {};

private:
	bool send_version() {
		struct bitcoin_version_with_header version_msg;
		version_msg.version.start.timestamp = htole64(time(0));
		version_msg.version.start.user_agent_length = BITCOIN_UA_LENGTH; // Work around apparent gcc bug
		return send_message("version", (unsigned char*)&version_msg, sizeof(struct bitcoin_version));
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
	P2PClient p2p(argv[2], std::stoul(argv[3]),
					[&](std::vector<unsigned char>& bytes, struct timeval) { relayClient->receive_block(bytes); },
					[&](std::shared_ptr<std::vector<unsigned char> >& bytes) { relayClient->receive_transaction(bytes); });
	relayClient = new RelayNetworkClient(argv[1],
										[&](std::vector<unsigned char>& bytes) { p2p.receive_block(bytes); },
										[&](std::shared_ptr<std::vector<unsigned char> >& bytes) { p2p.receive_transaction(bytes); });

	while (true) { sleep(1000); }
}
