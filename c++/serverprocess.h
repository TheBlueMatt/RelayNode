#ifndef _RELAY_SERVERPROCESS_H
#define _RELAY_SERVERPROCESS_H

#include <atomic>
#include <condition_variable>
#include <list>

#include "mruset.h"

#define SERVER_DECLARE_CLASS_VARS \
private: \
	const int sock; \
	std::mutex send_mutex; \
	std::atomic<int> connected; \
 \
	std::condition_variable cv; \
	std::list<std::shared_ptr<std::vector<unsigned char> > > outbound_secondary_queue; \
	std::list<std::shared_ptr<std::vector<unsigned char> > > outbound_primary_queue; \
	mruset<std::vector<unsigned char> > txnAlreadySeen; \
	mruset<std::vector<unsigned char> > blocksAlreadySeen; \
	uint32_t total_waiting_size; \
 \
	std::thread *read_thread, *write_thread; \
 \
public: \
	const std::string host; \
	std::atomic<int> disconnectFlags;

#define SERVER_DECLARE_CONSTRUCTOR_EXTENDS_AND_BODY \
	sock(sockIn), connected(0), txnAlreadySeen(100), blocksAlreadySeen(10), total_waiting_size(0), \
	host(hostIn), disconnectFlags(0) { \
		send_mutex.lock(); \
		read_thread = new std::thread(do_setup_and_read, this); \
		write_thread = new std::thread(do_write, this); \
		send_mutex.unlock();

#define SERVER_DECLARE_DESTRUCTOR \
	if (disconnectFlags & 4) \
		write_thread->join(); \
	else \
		read_thread->join(); \
	delete read_thread; \
	delete write_thread;

#define SERVER_DECLARE_FUNCTIONS(CLASS) \
private: \
	void disconnect(const char* reason) { \
		if (disconnectFlags.fetch_or(1) & 1) \
			return; \
 \
		printf("%s Disconnect: %s (%s)\n", host.c_str(), reason, strerror(errno)); \
 \
		close(sock); \
 \
		if (std::this_thread::get_id() != read_thread->get_id()) { \
			read_thread->join(); \
			disconnectFlags |= 4; \
		} else { \
			if (connected == 2) \
				send_mutex.lock(); \
 \
			outbound_secondary_queue.push_back(std::make_shared<std::vector<unsigned char> >(1)); \
			cv.notify_all(); \
			send_mutex.unlock(); \
 \
			write_thread->join(); \
		} \
 \
		outbound_secondary_queue.clear(); \
		outbound_primary_queue.clear(); \
 \
		disconnectFlags |= 2; \
	} \
 \
	static void do_setup_and_read(CLASS* me) { \
		me->send_mutex.lock(); \
 \
		fcntl(me->sock, F_SETFL, fcntl(me->sock, F_GETFL) & ~O_NONBLOCK); \
 \
		int nodelay = 1; \
		setsockopt(me->sock, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay)); \
 \
		if (errno) \
			return me->disconnect("error during connect"); \
 \
		me->net_process(); \
	} \
 \
	static void do_write(CLASS* me) { \
		me->net_write(); \
	} \
 \
	void net_write() { \
		while (true) { \
			std::shared_ptr<std::vector<unsigned char> > msg; \
			{ \
				std::unique_lock<std::mutex> write_lock(send_mutex); \
				while (!outbound_secondary_queue.size() && !outbound_primary_queue.size()) \
					cv.wait(write_lock); \
 \
				if (outbound_primary_queue.size()) { \
					msg = outbound_primary_queue.front(); \
					outbound_primary_queue.pop_front(); \
				} else { \
					msg = outbound_secondary_queue.front(); \
					outbound_secondary_queue.pop_front(); \
				} \
			} \
			if (send_all(sock, (char*)&(*msg)[0], msg->size()) != int64_t(msg->size())) \
				return disconnect("failed to send msg"); \
		} \
	}

#endif
