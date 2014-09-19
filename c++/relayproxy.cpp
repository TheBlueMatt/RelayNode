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

	const std::function<void (int)> provide_sock;

	int sock;
	std::mutex send_mutex;
	std::thread* net_thread, *new_thread;

public:
	RelayNetworkClient(const char* serverHostIn,
						const std::function<void (int)>& provide_sock_in)
			: RELAY_DECLARE_CONSTRUCTOR_EXTENDS, server_host(serverHostIn), provide_sock(provide_sock_in),
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

		relay_msg_header header;
		if (read_all(sock, (char*)&header, 4*3) != 4*3)
			return reconnect("failed to read message header");

		if (header.magic != RELAY_MAGIC_BYTES)
			return reconnect("invalid magic bytes");
		if (header.type != VERSION_TYPE)
			return reconnect("didnt get version first");

		uint32_t message_size = ntohl(header.length);
		if (message_size > 1000000)
			return reconnect("got message too large");

		char msg[message_size];
		if (read_all(sock, (char*)msg, message_size) < (int64_t)(message_size))
			return reconnect("failed to read message data");

		return provide_sock(sock);
	}

public:
	void receive_sock(int recv_sock) {
		std::lock_guard<std::mutex> lock(send_mutex);
		int pipes[2];
		if (pipe(pipes))
			exit(-42);
		fcntl(recv_sock, F_SETFL, fcntl(recv_sock, F_GETFL) & ~O_NONBLOCK);
		fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) & ~O_NONBLOCK);
		while (true) {
			ssize_t res = splice(recv_sock, NULL, pipes[1], NULL, 0xffff, SPLICE_F_MOVE);
			if (res <= 0) { printf("Error splicing from recv_sock %d to pipe %d: %ld (%s)\n", recv_sock, pipes[1], res, strerror(errno)); continue; }
			res = splice(pipes[0], NULL, sock, NULL, 0xffff, SPLICE_F_MOVE);
			if (res <= 0) printf("Error splicing from pipe %d to sock %d: %ld (%s)\n", pipes[0], sock, res, strerror(errno));
		}
	}
};




int main(int argc, char** argv) {
	if (argc != 3) {
		printf("USAGE: %s RELAY_SERVER_A RELAY_SERVER_B\n", argv[0]);
		return -1;
	}

	RelayNetworkClient *relayClientA, *relayClientB;
	relayClientA = new RelayNetworkClient(argv[1], [&](int sock) { relayClientB->receive_sock(sock); });
	relayClientB = new RelayNetworkClient(argv[2], [&](int sock) { relayClientA->receive_sock(sock); });

	while (true) { sleep(1000); }
}
