#include "preinclude.h"

#include <map>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>

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

		std::string error;
		me->sock = create_connect_socket(me->server_host, 8336, error);
		if (me->sock <= 0)
			return me->reconnect(error, true);

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

		struct sockaddr_in6 addr;
		socklen_t len = sizeof(addr);
		if (getsockname(sock, (struct sockaddr*)&addr, &len) != 0)
			return reconnect("failed to get bound host/port");
		if (len != sizeof(addr))
			return reconnect("getsockname didnt return a sockaddr_in6?");

		printf("Connected to %s local_port %d at %lu\n", server_host, addr.sin6_port, epoch_millis_lu(std::chrono::system_clock::now()));

		provide_sock(sock);
		return reconnect("provide_sock returned");
	}

public:
	void receive_sock(int recv_sock) {
		std::lock_guard<std::mutex> lock(send_mutex);
		char buff[0xffff];
		while (true) {
			ssize_t res = recv(recv_sock, buff, sizeof(buff), 0);
			if (res <= 0) { printf("Error reading from recv_sock %d: %ld (%s)\n", recv_sock, res, strerror(errno)); return; }
			res = send_all(sock, buff, res);
			if (res <= 0) { printf("Error sending to sock %d: %ld (%s)\n", sock, res, strerror(errno)); return; }
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
