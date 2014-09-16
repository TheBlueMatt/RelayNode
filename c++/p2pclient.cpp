#include "p2pclient.h"
#include "utils.h"
#include "crypto/sha2.h"

#include <thread>
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

void P2PRelayer::reconnect(std::string disconnectReason) {
	connected = false;
	if (sock) {
		printf("Closing bitcoind socket, %s (%i: %s)\n", disconnectReason.c_str(), errno, errno ? strerror(errno) : "");
		#ifndef WIN32
			errno = 0;
		#endif
		close(sock);
	}

	sleep(1);

	new_thread = new std::thread(do_connect, this);
}

void P2PRelayer::do_connect(P2PRelayer* me) {
	if (me->net_thread)
		me->net_thread->join();
	me->net_thread = me->new_thread;

	me->sock = socket(AF_INET6, SOCK_STREAM, 0);
	if (me->sock <= 0)
		return me->reconnect("unable to create socket");

	sockaddr_in6 addr;
	if (!lookup_address(me->server_host, &addr))
		return me->reconnect("unable to lookup host");

	int v6only = 0;
	setsockopt(me->sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&v6only, sizeof(v6only));

	addr.sin6_port = htons(me->server_port);
	if (connect(me->sock, (struct sockaddr*)&addr, sizeof(addr)))
		return me->reconnect("failed to connect()");

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

bool P2PRelayer::send_message(const char* command, unsigned char* headerAndData, size_t datalen) {
	prepare_message(command, headerAndData, datalen);
	return send_all(sock, (char*)headerAndData, sizeof(struct bitcoin_msg_header) + datalen) == int(sizeof(struct bitcoin_msg_header) + datalen);
}

void P2PRelayer::net_process() {
	if (!send_version()) {
		reconnect("failed to send version message");
		return;
	}

	int nodelay = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));

	if (errno)
		return reconnect("error during connect");

	while (true) {
		struct bitcoin_msg_header header;
		if (read_all(sock, (char*)&header, sizeof(header)) != sizeof(header))
			return reconnect("failed to read message header");

		if (header.magic != BITCOIN_MAGIC)
			return reconnect("invalid magic bytes");

		header.length = le32toh(header.length);
		if (header.length > 5000000)
			return reconnect("got message too large");

		uint32_t prependedHeaderSize = (!strncmp(header.command, "block", strlen("block"))) ? sizeof(struct bitcoin_msg_header) : 0;

		struct timeval read_start;
		gettimeofday(&read_start, NULL);

		auto msg = std::make_shared<std::vector<unsigned char> > (prependedHeaderSize + uint32_t(header.length));
		if (read_all(sock, (char*)&(*msg)[prependedHeaderSize], header.length) != int(header.length))
			return reconnect("failed to read message");

		unsigned char fullhash[32];
		CSHA256 hash;
		hash.Write(&(*msg)[prependedHeaderSize], header.length).Finalize(fullhash);
		hash.Reset().Write(fullhash, sizeof(fullhash)).Finalize(fullhash);
		if (memcmp((char*)fullhash, header.checksum, sizeof(header.checksum)))
			return reconnect("got invalid message checksum");

		if (!strncmp(header.command, "version", strlen("version"))) {
			if (header.length < sizeof(struct bitcoin_version_start))
				return reconnect("got short version");
			struct bitcoin_version_start *their_version = (struct bitcoin_version_start*) &(*msg)[0];

			struct bitcoin_msg_header new_header;
			send_message("verack", (unsigned char*)&new_header, 0);

			if (provide_headers) {
				std::vector<unsigned char> msg(sizeof(struct bitcoin_msg_header));
				struct bitcoin_version_start sent_version;
				msg.insert(msg.end(), (unsigned char*)&sent_version.protocol_version, ((unsigned char*)&sent_version.protocol_version) + sizeof(sent_version.protocol_version));
				msg.insert(msg.end(), 1, 1);
				msg.insert(msg.end(), 64, 0);
				send_message("getheaders", &msg[0], msg.size() - sizeof(struct bitcoin_msg_header));
			}

			printf("Connected to bitcoind with version %u\n", le32toh(their_version->protocol_version));
		} else if (!strncmp(header.command, "verack", strlen("verack"))) {
			printf("Finished connect handshake with bitcoind\n");
			connected = true;
		} else if (!strncmp(header.command, "ping", strlen("ping"))) {
			std::vector<unsigned char> resp(sizeof(struct bitcoin_msg_header) + header.length);
			resp.insert(resp.begin() + sizeof(struct bitcoin_msg_header), msg->begin(), msg->end());
			send_message("pong", &resp[0], header.length);
		} else if (!strncmp(header.command, "inv", strlen("inv"))) {
			std::vector<unsigned char> resp(sizeof(struct bitcoin_msg_header) + header.length);
			resp.insert(resp.begin() + sizeof(struct bitcoin_msg_header), msg->begin(), msg->end());
			send_message("getdata", &resp[0], header.length);
		} else if (!strncmp(header.command, "block", strlen("block"))) {
			provide_block(*msg, read_start);
		} else if (!strncmp(header.command, "tx", strlen("tx"))) {
			provide_transaction(msg);
		} else if (!strncmp(header.command, "headers", strlen("headers"))) {
			if (msg->size() <= 1 + 82)
				continue; // Probably last one

			if (!provide_headers || !provide_headers(*msg))
				continue;

			std::vector<unsigned char> req(sizeof(struct bitcoin_msg_header));
			struct bitcoin_version_start sent_version;
			req.insert(req.end(), (unsigned char*)&sent_version.protocol_version, ((unsigned char*)&sent_version.protocol_version) + sizeof(sent_version.protocol_version));
			req.insert(req.end(), 1, 1);

			std::vector<unsigned char> fullhash(32);
			CSHA256 hash;
			hash.Write(&(*msg)[msg->size() - 81], 80).Finalize(&fullhash[0]);
			hash.Reset().Write(&fullhash[0], fullhash.size()).Finalize(&fullhash[0]);
			req.insert(req.end(), fullhash.begin(), fullhash.end());
			req.insert(req.end(), 32, 0);

			std::lock_guard<std::mutex> lock(send_mutex);
			send_message("getheaders", &req[0], req.size() - sizeof(struct bitcoin_msg_header));
		}
	}
}

void P2PRelayer::receive_transaction(const std::shared_ptr<std::vector<unsigned char> >& tx) {
	if (!connected)
		return;

	#ifndef FOR_VALGRIND
		if (!send_mutex.try_lock())
			return;
	#else
		send_mutex.lock();
	#endif

	auto msg = std::vector<unsigned char>(sizeof(struct bitcoin_msg_header));
	msg.insert(msg.end(), tx->begin(), tx->end());
	send_message("tx", &msg[0], tx->size());

	if (requestAfterSend) {
		std::vector<unsigned char> req(sizeof(struct bitcoin_msg_header));
		req.insert(req.end(), 1, 1);
		uint32_t MSG_TX = htole32(1);
		req.insert(req.end(), (unsigned char*)&MSG_TX, ((unsigned char*)&MSG_TX) + sizeof(MSG_TX));

		std::vector<unsigned char> fullhash(32);
		CSHA256 hash; // Probably not BE-safe
		hash.Write(&(*tx)[0], tx->size()).Finalize(&fullhash[0]);
		hash.Reset().Write(&fullhash[0], fullhash.size()).Finalize(&fullhash[0]);
		req.insert(req.end(), fullhash.begin(), fullhash.end());

		send_message("getdata", &req[0], 37);
	}

	send_mutex.unlock();
}

void P2PRelayer::receive_block(std::vector<unsigned char>& block) {
	if (!connected)
		return;
	std::lock_guard<std::mutex> lock(send_mutex);
	send_message("block", &block[0], block.size() - sizeof(bitcoin_msg_header));
}
