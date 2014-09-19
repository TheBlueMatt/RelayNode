#include <map>
#include <vector>
#include <thread>
#include <mutex>

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>

#include "crypto/sha2.h"
#include "flaggedarrayset.h"
#include "relayprocess.h"
#include "utils.h"





/***********************************************
 **** Relay network client processing class ****
 ***********************************************/
class RelayNetworkClient {
	RELAY_DECLARE_CLASS_VARS
private:
	const char* server_host;

	const std::function<void (std::vector<unsigned char>&)> provide_message;

	int sock;
	std::mutex send_mutex;
	std::thread* net_thread, *new_thread;

public:
	RelayNetworkClient(const char* serverHostIn,
						const std::function<void (std::vector<unsigned char>&)>& provide_message_in)
			: RELAY_DECLARE_CONSTRUCTOR_EXTENDS, server_host(serverHostIn), provide_message(provide_message_in),
			sock(0), net_thread(NULL), new_thread(NULL) {
		send_mutex.lock();
		new_thread = new std::thread(do_connect, this);
		send_mutex.unlock();
	}

private:
	void reconnect(std::string disconnectReason, bool alreadyLocked=false) {
		printf("Closing relay socket, %s (%i: %s)\n", disconnectReason.c_str(), errno, errno ? strerror(errno) : "");
		exit(-1);
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

		fcntl(me->sock, F_SETFL, fcntl(me->sock, F_GETFL) & ~O_NONBLOCK);

		me->net_process();
	}

	void net_process() {
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

			std::vector<unsigned char> msg(sizeof(struct relay_msg_header) + message_size);
			struct relay_msg_header *new_header = (struct relay_msg_header*)&msg[0];
			new_header->magic = RELAY_MAGIC_BYTES;
			new_header->type = header.type;
			new_header->length = htonl(message_size);
			if (read_all(sock, (char*)&msg[sizeof(struct relay_msg_header)], message_size) < (int64_t)(message_size))
				return reconnect("failed to read message data");
			if (header.type != VERSION_TYPE)
				provide_message(msg);
		}
	}

public:
	void receive_message(const std::vector<unsigned char>& msg) {
		std::lock_guard<std::mutex> lock(send_mutex);
		if (send_all(sock, (char*)&msg[0], msg.size()) != int(msg.size()))
			printf("Error sending message to relay server\n");
		else
			printf("Sent message of size %lu to relay server\n", (unsigned long)msg.size());
	}
};




int main(int argc, char** argv) {
	if (argc != 3) {
		printf("USAGE: %s RELAY_SERVER_A RELAY_SERVER_B\n", argv[0]);
		return -1;
	}

	RelayNetworkClient *relayClientA, *relayClientB;
	relayClientA = new RelayNetworkClient(argv[1],
										[&](std::vector<unsigned char>& bytes) { relayClientB->receive_message(bytes); });
	relayClientB = new RelayNetworkClient(argv[2],
										[&](std::vector<unsigned char>& bytes) { relayClientA->receive_message(bytes); });

	while (true) { sleep(1000); }
}
