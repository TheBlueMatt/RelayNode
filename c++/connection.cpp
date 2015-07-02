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

#include <unordered_map>

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


void Connection::do_send_bytes(const std::shared_ptr<std::vector<unsigned char> >& bytes, int send_mutex_token) {
	if (!send_mutex_token)
		send_mutex.lock();
	else
		ALWAYS_ASSERT(send_mutex_token == outside_send_mutex_token);

	if (initial_outbound_throttle && send_mutex_token)
		initial_outbound_bytes += bytes->size();

	if (total_waiting_size - (initial_outbound_throttle ? initial_outbound_bytes : 0) > 4000000) {
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

	if (total_waiting_size - (initial_outbound_throttle ? initial_outbound_bytes : 0) > 4000000) {
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
	inbound_queue.clear();

	disconnectFlags |= DISCONNECT_COMPLETE;

	if (on_disconnect)
		std::thread(on_disconnect).detach();
}

class GlobalNetProcess {
public:
	std::mutex fd_map_mutex;
	std::unordered_map<int, Connection*> fd_map;
#ifndef WIN32
	int pipe_write;
#endif

	static void do_net_process(GlobalNetProcess* me) {
		fd_set fd_set_read, fd_set_write;
		struct timeval timeout;

#ifndef WIN32
		int pipefd[2];
		assert(!pipe(pipefd));
		fcntl(pipefd[1], F_SETFL, fcntl(pipefd[1], F_GETFL) | O_NONBLOCK);
		fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);
		me->pipe_write = pipefd[1];
#endif

		while (true) {
#ifndef WIN32
			timeout.tv_sec = 60;
			timeout.tv_usec = 0;
#else
			timeout.tv_sec = 0;
			timeout.tv_usec = 1000;
#endif

			FD_ZERO(&fd_set_read); FD_ZERO(&fd_set_write);
#ifndef WIN32
			int max = pipefd[0];
			FD_SET(pipefd[0], &fd_set_read);
#else
			int max = 0;
#endif
			{
				std::lock_guard<std::mutex> lock(me->fd_map_mutex);
				for (const auto& e : me->fd_map) {
					ALWAYS_ASSERT(e.first < FD_SETSIZE);
					FD_SET(e.first, &fd_set_read);
					//FD_SET(e.first, &fd_set_write);
					max = std::max(e.first, max);
				}
			}

			assert(select(max + 1, &fd_set_read, &fd_set_write, NULL, &timeout) >= 0);

			unsigned char buf[4096];
			{
				std::list<int> remove_list;
				std::lock_guard<std::mutex> lock(me->fd_map_mutex);
				for (const auto& e : me->fd_map) {
					if (FD_ISSET(e.first, &fd_set_read)) {
						ssize_t count = recv(e.second->sock, (char*)buf, 4096, 0);

						std::lock_guard<std::mutex> lock(e.second->read_mutex);
						if (count <= 0) {
							e.second->inbound_queue.emplace_back((std::nullptr_t)NULL);
							remove_list.push_back(e.first);
						} else
							e.second->inbound_queue.emplace_back(new std::vector<unsigned char>(buf, buf + count));
						e.second->read_cv.notify_all();
					}
					if (FD_ISSET(e.first, &fd_set_write)) {
						//TODO: Move write here
					}
				}

				for (const int fd : remove_list)
					me->fd_map.erase(fd);
			}
#ifndef WIN32
			if (FD_ISSET(pipefd[0], &fd_set_read))
				while (read(pipefd[0], buf, 4096) > 0);
#endif
		}
	}

	GlobalNetProcess() {
		std::thread(do_net_process, this).detach();
	}
};
static GlobalNetProcess processor;

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

	{
		std::lock_guard<std::mutex>(processor.fd_map_mutex);
		processor.fd_map[me->sock] = me;
#ifndef WIN32
		write(processor.pipe_write, "1", 1);
#endif
	}

	me->net_process([&](const char* reason) { me->disconnect(reason); });
}

ssize_t Connection::read_all(char *buf, size_t nbyte) {
	size_t total = 0;
	while (total < nbyte) {
		std::unique_lock<std::mutex> lock(read_mutex);
		while (!inbound_queue.size())
			read_cv.wait(lock);

		if (!inbound_queue.front())
			return -1;

		size_t readamt = std::min(nbyte - total, inbound_queue.front()->size() - readpos);
		memcpy(buf + total, &(*inbound_queue.front())[readpos], readamt);
		if (readpos + readamt == inbound_queue.front()->size()) {
			readpos = 0;
			inbound_queue.pop_front();
		} else
			readpos += readamt;
		total += readamt;
	}
	assert(total == nbyte);
	return nbyte;
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
