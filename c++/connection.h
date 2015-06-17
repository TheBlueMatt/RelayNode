#ifndef _RELAY_CONNECTION_H
#define _RELAY_CONNECTION_H

#include <atomic>
#include <condition_variable>
#include <list>

enum DisconnectFlags {
	DISCONNECT_STARTED = 1,
	DISCONNECT_PRINT_AND_CLOSE = 2,
	DISCONNECT_FROM_WRITE_THREAD = 4,
	DISCONNECT_FROM_READ_THREAD = 8,
	DISCONNECT_COMPLETE = 16,
};

class Connection {
public: // TODO: make private
	const int sock;
private:
	std::mutex send_mutex;
	bool outside_send_mutex_held;
public: // TODO: make private?
	std::atomic<int> connected;
private:

	std::condition_variable cv;
	std::list<std::shared_ptr<std::vector<unsigned char> > > outbound_secondary_queue;
	std::list<std::shared_ptr<std::vector<unsigned char> > > outbound_primary_queue;
	bool initial_outbound_throttle;
	uint32_t total_waiting_size;

	std::thread *read_thread, *write_thread;

	std::atomic<int> disconnectFlags;
public:
	const std::string host;

	Connection(int sockIn, std::string hostIn) : sock(sockIn), outside_send_mutex_held(false),
			connected(0), initial_outbound_throttle(true), total_waiting_size(0), disconnectFlags(0), host(hostIn) {
		std::lock_guard<std::mutex> lock(send_mutex);
		read_thread = new std::thread(do_setup_and_read, this);
		write_thread = new std::thread(do_write, this);
	}

	virtual ~Connection() {
		assert(disconnectFlags & DISCONNECT_COMPLETE);
		if (disconnectFlags & DISCONNECT_FROM_WRITE_THREAD)
			write_thread->join();
		else if (disconnectFlags & DISCONNECT_FROM_READ_THREAD)\
			read_thread->join();
		else
			assert(!"DISCONNECT_COMPLETE set but not from either thread?");
		close(sock);
		delete read_thread;
		delete write_thread;
	}

	int getDisconnectFlags() { return disconnectFlags; }

protected:
	virtual void net_process(const std::function<void(const char*)>& disconnect)=0;
	ssize_t read_all(char *buf, size_t nbyte) { return ::read_all(sock, buf, nbyte); }

	void do_send_bytes(const char *buf, size_t nbyte) {
		do_send_bytes(std::make_shared<std::vector<unsigned char> >((unsigned char*)buf, (unsigned char*)buf + nbyte));
	}

	void do_send_bytes(const std::shared_ptr<std::vector<unsigned char> >& bytes) {
		if (!outside_send_mutex_held)
			send_mutex.lock();
		if (total_waiting_size > 4000000) {
			if (!outside_send_mutex_held)
				send_mutex.unlock();
			return disconnect_from_outside("total_waiting_size blew up :(");;
		}

		outbound_primary_queue.push_back(bytes);
		total_waiting_size += bytes->size();
		cv.notify_all();
		if (!outside_send_mutex_held)
			send_mutex.unlock();
	}

	void maybe_send_bytes(const std::shared_ptr<std::vector<unsigned char> >& bytes) {
		if (!outside_send_mutex_held)
			if (!send_mutex.try_lock())
				return;
		if (total_waiting_size > 4000000) {
			if (!outside_send_mutex_held)
				send_mutex.unlock();
			return disconnect_from_outside("total_waiting_size blew up :(");;
		}

		outbound_secondary_queue.push_back(bytes);
		total_waiting_size += bytes->size();
		cv.notify_all();
		if (!outside_send_mutex_held)
			send_mutex.unlock();
	}


	void get_send_mutex() { send_mutex.lock(); outside_send_mutex_held = true; }
	void release_send_mutex() { outside_send_mutex_held = false; send_mutex.unlock(); }

private:
	void disconnect_from_outside(const char* reason) {
		if (disconnectFlags.fetch_or(DISCONNECT_PRINT_AND_CLOSE) & DISCONNECT_PRINT_AND_CLOSE)
			return;

		printf("%s Disconnect: %s (%s)\n", host.c_str(), reason, strerror(errno));
		shutdown(sock, SHUT_RDWR);
	}

	void disconnect(const char* reason) {
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
	}

	static void do_setup_and_read(Connection* me) {
		fcntl(me->sock, F_SETFL, fcntl(me->sock, F_GETFL) & ~O_NONBLOCK);

		int nodelay = 1;
		setsockopt(me->sock, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));

		if (errno)
			return me->disconnect("error during connect");

		me->net_process([&](const char* reason) { me->disconnect(reason); });
	}

	static void do_write(Connection* me) {
		me->net_write();
	}

	void net_write() {
		while (true) {
			std::shared_ptr<std::vector<unsigned char> > msg;
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
					usleep(20*1000); /* Limit outbound to avg 5Mbps worst case */
			}
			if (send_all(sock, (char*)&(*msg)[0], msg->size()) != int64_t(msg->size()))
				return disconnect("failed to send msg");
		}
	}
};

#endif
