#include <assert.h>
#include <string.h>

#ifdef WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#define SHUT_RDWR SD_BOTH
#else // WIN32
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <netinet/tcp.h>
	#include <netdb.h>
	#include <fcntl.h>
#endif // !WIN32

#include "connection.h"

#include "utils.h"

Connection::~Connection() {
	assert(disconnectFlags & DISCONNECT_COMPLETE);
	if (disconnectFlags & DISCONNECT_FROM_WRITE_THREAD)
		write_thread->join();
	else if (disconnectFlags & DISCONNECT_FROM_READ_THREAD)
		read_thread->join();
	else
		assert(!"DISCONNECT_COMPLETE set but not from either thread?");
	close(sock);
	delete read_thread;
	delete write_thread;
}


ssize_t Connection::read_all(char *buf, size_t nbyte) {
	return ::read_all(sock, buf, nbyte);
}

void Connection::do_send_bytes(const std::shared_ptr<std::vector<unsigned char> >& bytes, int send_mutex_token) {
	if (!send_mutex_token)
		send_mutex.lock();
	else
		ALWAYS_ASSERT(send_mutex_token == outside_send_mutex_token);

	if (total_waiting_size > 4000000) {
		if (!send_mutex_token)
			send_mutex.unlock();
		return disconnect_from_outside("total_waiting_size blew up :(", false);
	}

	outbound_primary_queue.push_back(bytes);
	total_waiting_size += bytes->size();
	cv.notify_all();
	if (!send_mutex_token)
		send_mutex.unlock();
}

void Connection::maybe_send_bytes(const std::shared_ptr<std::vector<unsigned char> >& bytes, int send_mutex_token) {
	if (!send_mutex_token) {
		if (!send_mutex.try_lock())
			return;
	} else
		ALWAYS_ASSERT(send_mutex_token == outside_send_mutex_token);

	if (total_waiting_size > 4000000) {
		if (!send_mutex_token)
			send_mutex.unlock();
		return disconnect_from_outside("total_waiting_size blew up :(", false);
	}

	outbound_secondary_queue.push_back(bytes);
	total_waiting_size += bytes->size();
	cv.notify_all();
	if (!send_mutex_token)
		send_mutex.unlock();
}

void Connection::disconnect_from_outside(const char* reason, bool push_send) {
	if (disconnectFlags.fetch_or(DISCONNECT_PRINT_AND_CLOSE) & DISCONNECT_PRINT_AND_CLOSE)
		return;

	printf("%s Disconnect: %s (%s)\n", host.c_str(), reason, strerror(errno));
	shutdown(sock, SHUT_RDWR);

	if (push_send)
		do_send_bytes(std::make_shared<std::vector<unsigned char> >(1));
}

void Connection::disconnect(const char* reason) {
	if (disconnectFlags.fetch_or(DISCONNECT_STARTED) & DISCONNECT_STARTED)
		return;

	if (!(disconnectFlags.fetch_or(DISCONNECT_PRINT_AND_CLOSE) & DISCONNECT_PRINT_AND_CLOSE)) {
		printf("%s Disconnect: %s (%s)\n", host.c_str(), reason, strerror(errno));
		shutdown(sock, SHUT_RDWR);
	}

	if (std::this_thread::get_id() != read_thread->get_id()) {
		disconnectFlags |= DISCONNECT_FROM_WRITE_THREAD;
		read_thread->join();
	} else {
		disconnectFlags |= DISCONNECT_FROM_READ_THREAD;
		{
			/* Wake up the write thread */
			std::lock_guard<std::mutex> lock(send_mutex);
			outbound_secondary_queue.push_back(std::make_shared<std::vector<unsigned char> >(1));
			cv.notify_all();
		}
		write_thread->join();
	}

	outbound_secondary_queue.clear();
	outbound_primary_queue.clear();

	disconnectFlags |= DISCONNECT_COMPLETE;

	if (on_disconnect)
		std::thread(on_disconnect).detach();
}

void Connection::do_setup_and_read(Connection* me) {
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

	int nodelay = 1;
	setsockopt(me->sock, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));

	if (errno)
		return me->disconnect("error during connect");

	me->net_process([&](const char* reason) { me->disconnect(reason); });
}

void Connection::do_write(Connection* me) {
	me->net_write();
}

void Connection::net_write() {
	//TODO: Have a single global thread doing this
	while (true) {
		std::shared_ptr<std::vector<unsigned char> > msg;
		bool sleepFirst = false;
		{
			std::unique_lock<std::mutex> write_lock(send_mutex);
			while (!outbound_secondary_queue.size() && !outbound_primary_queue.size())
				cv.wait(write_lock);

			if (disconnectFlags)
				return disconnect("disconnect started elsewhere");

			if (outbound_primary_queue.size()) {
				msg = outbound_primary_queue.front();
				outbound_primary_queue.pop_front();
			} else {
				msg = outbound_secondary_queue.front();
				outbound_secondary_queue.pop_front();
			}

			total_waiting_size -= msg->size();
			if (!total_waiting_size)
				initial_outbound_throttle = false;
			else if (initial_outbound_throttle)
				sleepFirst = true;
		}
		if (sleepFirst)
			std::this_thread::sleep_for(std::chrono::milliseconds(20)); // Limit outbound to avg 5Mbps worst-case
		if (send_all(sock, (char*)&(*msg)[0], msg->size()) != int64_t(msg->size()))
			return disconnect("failed to send msg");
	}
}

void OutboundPersistentConnection::reconnect(std::string disconnectReason) {
	OutboundConnection* old = (OutboundConnection*) connection.fetch_and(0);
	if (old)
		old->disconnect_from_outside(disconnectReason.c_str());

	on_disconnect();

	std::this_thread::sleep_for(std::chrono::seconds(1));
	while (old && !(old->getDisconnectFlags() & DISCONNECT_COMPLETE)) {
		printf("Disconnect of outbound connection still not complete (status is %d)\n", old->getDisconnectFlags());
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}

	std::thread(do_connect, this).detach();
	delete old;
}

void OutboundPersistentConnection::do_connect(OutboundPersistentConnection* me) {
	int sock = socket(AF_INET6, SOCK_STREAM, 0);
	if (sock <= 0)
		return me->reconnect("unable to create socket");

	sockaddr_in6 addr;
	if (!lookup_address(me->serverHost.c_str(), &addr)) {
		close(sock);
		return me->reconnect("unable to lookup host");
	}

	int v6only = 0;
	setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&v6only, sizeof(v6only));

	addr.sin6_port = htons(me->serverPort);
	if (connect(sock, (struct sockaddr*)&addr, sizeof(addr))) {
		close(sock);
		return me->reconnect("failed to connect()");
	}

	OutboundConnection* new_conn = new OutboundConnection(sock, me);
#ifndef NDEBUG
	unsigned long old_val =
#endif
		me->connection.exchange((unsigned long)new_conn);
	assert(old_val == 0);
	new_conn->construction_done();
}
