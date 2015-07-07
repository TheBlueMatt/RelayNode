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
#include <set>

#include "connection.h"

#include "utils.h"


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
		ALWAYS_ASSERT(!pipe(pipefd));
		fcntl(pipefd[1], F_SETFL, fcntl(pipefd[1], F_GETFL) | O_NONBLOCK);
		fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);
		me->pipe_write = pipefd[1];
#endif

		while (true) {
#ifndef WIN32
			timeout.tv_sec = 86400;
			timeout.tv_usec = 20 * 1000;
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
			auto now = std::chrono::steady_clock::now();
			{
				std::lock_guard<std::mutex> lock(me->fd_map_mutex);
				for (const auto& e : me->fd_map) {
					ALWAYS_ASSERT(e.first < FD_SETSIZE);
					if (e.second->total_inbound_size < 65536)
						FD_SET(e.first, &fd_set_read);
					if (e.second->total_waiting_size > 0) {
						if (now < e.second->earliest_next_write) {
							timeout.tv_sec = 0;
							timeout.tv_usec = std::min((long unsigned)timeout.tv_usec, to_micros_lu(e.second->earliest_next_write - now));
						} else
							FD_SET(e.first, &fd_set_write);
					}
					max = std::max(e.first, max);
				}
			}

			ALWAYS_ASSERT(select(max + 1, &fd_set_read, &fd_set_write, NULL, &timeout) >= 0);

			now = std::chrono::steady_clock::now();
			unsigned char buf[4096];
			{
				std::set<int> remove_set;
				std::lock_guard<std::mutex> lock(me->fd_map_mutex);
				for (const auto& e : me->fd_map) {
					Connection* conn = e.second;

					if (FD_ISSET(e.first, &fd_set_read)) {
						ssize_t count = recv(conn->sock, (char*)buf, 4096, 0);

						std::lock_guard<std::mutex> lock(conn->read_mutex);
						if (count <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
							remove_set.insert(e.first);
							conn->sock_errno = errno;
						} else {
							conn->inbound_queue.emplace_back(new std::vector<unsigned char>(buf, buf + count));
							conn->total_inbound_size += count;
							conn->read_cv.notify_all();
						}
					}
					if (FD_ISSET(e.first, &fd_set_write)) {
						if (now < conn->earliest_next_write)
							continue;
						std::lock_guard<std::mutex> lock(conn->send_bytes_mutex);
						if (!conn->secondary_writepos && conn->outbound_primary_queue.size()) {
							auto& msg = conn->outbound_primary_queue.front();
							ssize_t count = send(conn->sock, (char*) &(*msg)[conn->primary_writepos], msg->size() - conn->primary_writepos, MSG_NOSIGNAL);
							if (count <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
								remove_set.insert(e.first);
								conn->sock_errno = errno;
							} else {
								conn->primary_writepos += count;
								if (conn->primary_writepos == msg->size()) {
									conn->primary_writepos = 0;
									conn->total_waiting_size -= msg->size();
									conn->outbound_primary_queue.pop_front();
								}
							}
						} else {
							assert(conn->outbound_secondary_queue.size() && !conn->primary_writepos);
							auto& msg = conn->outbound_secondary_queue.front();
							ssize_t count = send(conn->sock, (char*) &(*msg)[conn->secondary_writepos], msg->size() - conn->secondary_writepos, MSG_NOSIGNAL);
							if (count <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
								remove_set.insert(e.first);
								conn->sock_errno = errno;
							} else {
								conn->secondary_writepos += count;
								if (conn->secondary_writepos == msg->size()) {
									conn->secondary_writepos = 0;
									conn->total_waiting_size -= msg->size();
									conn->outbound_secondary_queue.pop_front();
								}
							}
						}
						if (conn->send_mutex.try_lock()) {
							if (!conn->total_waiting_size)
								conn->initial_outbound_throttle = false;
							conn->send_mutex.unlock();
						}
						if (!conn->primary_writepos && !conn->secondary_writepos && conn->initial_outbound_throttle)
							conn->earliest_next_write = std::chrono::steady_clock::now() + std::chrono::milliseconds(20); // Limit outbound to avg 5Mbps worst-case
					}
				}

				for (const int fd : remove_set) {
					Connection* conn = me->fd_map[fd];
					std::lock_guard<std::mutex> lock(conn->read_mutex);
					conn->inbound_queue.emplace_back((std::nullptr_t)NULL);
					conn->read_cv.notify_all();
					conn->disconnectFlags |= DISCONNECT_GLOBAL_THREAD_DONE;
					me->fd_map.erase(fd);
				}
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



Connection::~Connection() {
	assert(disconnectFlags & DISCONNECT_COMPLETE);
	user_thread->join();
	close(sock);
	delete user_thread;
}


void Connection::do_send_bytes(const std::shared_ptr<std::vector<unsigned char> >& bytes, int send_mutex_token) {
	if (!send_mutex_token)
		send_mutex.lock();
	else
		ALWAYS_ASSERT(send_mutex_token == outside_send_mutex_token);

	std::lock_guard<std::mutex> bytes_lock(send_bytes_mutex);

	if (initial_outbound_throttle && send_mutex_token)
		initial_outbound_bytes += bytes->size();

	if (total_waiting_size - (initial_outbound_throttle ? initial_outbound_bytes : 0) > 4000000) {
		if (!send_mutex_token)
			send_mutex.unlock();
		return disconnect_from_outside("total_waiting_size blew up :(");
	}

	outbound_primary_queue.push_back(bytes);
	total_waiting_size += bytes->size();
#ifndef WIN32
	if (total_waiting_size > (ssize_t)bytes->size())
		ALWAYS_ASSERT(write(processor.pipe_write, "1", 1) == 1);
#endif

	if (!send_mutex_token)
		send_mutex.unlock();
}

void Connection::maybe_send_bytes(const std::shared_ptr<std::vector<unsigned char> >& bytes, int send_mutex_token) {
	if (!send_mutex_token) {
		if (!send_mutex.try_lock())
			return;
	} else
		ALWAYS_ASSERT(send_mutex_token == outside_send_mutex_token);

	std::lock_guard<std::mutex> bytes_lock(send_bytes_mutex);

	if (total_waiting_size - (initial_outbound_throttle ? initial_outbound_bytes : 0) > 4000000) {
		if (!send_mutex_token)
			send_mutex.unlock();
		return disconnect_from_outside("total_waiting_size blew up :(");
	}

	outbound_secondary_queue.push_back(bytes);
	total_waiting_size += bytes->size();
#ifndef WIN32
	if (total_waiting_size > (ssize_t)bytes->size())
		ALWAYS_ASSERT(write(processor.pipe_write, "1", 1) == 1);
#endif

	if (!send_mutex_token)
		send_mutex.unlock();
}

int Connection::get_send_mutex() {
	send_mutex.lock();
	return (outside_send_mutex_token *= 0xdeadbeef);
}

void Connection::release_send_mutex(int send_mutex_token) {
	outside_send_mutex_token *= 0xdeadbeef;
	send_mutex.unlock();
}

void Connection::disconnect_from_outside(const char* reason) {
	if (disconnectFlags.fetch_or(DISCONNECT_PRINT_AND_CLOSE) & DISCONNECT_PRINT_AND_CLOSE)
		return;

	printf("%s Disconnect: %s (%s)\n", host.c_str(), reason, strerror(errno));
	shutdown(sock, SHUT_RDWR);
}

void Connection::disconnect(const char* reason) {
	if (disconnectFlags.fetch_or(DISCONNECT_STARTED) & DISCONNECT_STARTED)
		return;

	if (!(disconnectFlags.fetch_or(DISCONNECT_PRINT_AND_CLOSE) & DISCONNECT_PRINT_AND_CLOSE)) {
		printf("%s Disconnect: %s (%s)\n", host.c_str(), reason, strerror(sock_errno));
		shutdown(sock, SHUT_RDWR);
	}

	assert(std::this_thread::get_id() == user_thread->get_id());

	std::unique_lock<std::mutex> lock(read_mutex);
	while (!(disconnectFlags & DISCONNECT_GLOBAL_THREAD_DONE))
		read_cv.wait(lock);

	disconnectFlags |= DISCONNECT_COMPLETE;

	if (on_disconnect)
		std::thread(on_disconnect).detach();
}

void Connection::do_setup_and_read(Connection* me) {
	#ifdef WIN32
		unsigned long nonblocking = 1;
		ioctlsocket(me->sock, FIONBIO, &nonblocking);
	#else
		fcntl(me->sock, F_SETFL, fcntl(me->sock, F_GETFL) | O_NONBLOCK);
	#endif

	#ifdef X86_BSD
		int nosigpipe = 1;
		setsockopt(me->sock, SOL_SOCKET, SO_NOSIGPIPE, (void *)&nosigpipe, sizeof(int));
	#endif

	int nodelay = 1;
	setsockopt(me->sock, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));

	if (errno) {
		me->disconnectFlags |= DISCONNECT_GLOBAL_THREAD_DONE;
		return me->disconnect("error during connect");
	}

	{
		std::lock_guard<std::mutex> lock(processor.fd_map_mutex);
		processor.fd_map[me->sock] = me;
#ifndef WIN32
		ALWAYS_ASSERT(write(processor.pipe_write, "1", 1) == 1);
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
#ifndef WIN32
			int32_t old_size = total_inbound_size;
#endif
			total_inbound_size -= inbound_queue.front()->size();
#ifndef WIN32
			// If the old size is >= 64k, we may need to wakeup the select thread to get it to read more
			if (old_size >= 65536)
				ALWAYS_ASSERT(write(processor.pipe_write, "1", 1) == 1);
#endif

			readpos = 0;
			inbound_queue.pop_front();
		} else
			readpos += readamt;
		total += readamt;
	}
	assert(total == nbyte);
	return nbyte;
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
