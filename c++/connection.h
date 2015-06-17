#ifndef _RELAY_CONNECTION_H
#define _RELAY_CONNECTION_H

#include <atomic>
#include <condition_variable>
#include <thread>
#include <list>
#include <vector>

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

	std::function<void(void)> on_disconnect;

	std::condition_variable cv;
	std::list<std::shared_ptr<std::vector<unsigned char> > > outbound_secondary_queue;
	std::list<std::shared_ptr<std::vector<unsigned char> > > outbound_primary_queue;
	bool initial_outbound_throttle;
	uint32_t total_waiting_size;

	std::thread *read_thread, *write_thread;

	std::atomic<int> disconnectFlags;
public:
	const std::string host;

	Connection(int sockIn, std::string hostIn, std::function<void(void)> on_disconnect_in) :
			sock(sockIn), outside_send_mutex_held(false), on_disconnect(on_disconnect_in),
			initial_outbound_throttle(true), total_waiting_size(0), disconnectFlags(0), host(hostIn)
		{}

protected:
	void construction_done() {
		read_thread = new std::thread(do_setup_and_read, this);
		write_thread = new std::thread(do_write, this);
	}

public:
	virtual ~Connection();

	int getDisconnectFlags() { return disconnectFlags; }

protected:
	virtual void net_process(const std::function<void(const char*)>& disconnect)=0;
	ssize_t read_all(char *buf, size_t nbyte);

	void do_send_bytes(const char *buf, size_t nbyte) {
		do_send_bytes(std::make_shared<std::vector<unsigned char> >((unsigned char*)buf, (unsigned char*)buf + nbyte));
	}

	void do_send_bytes(const std::shared_ptr<std::vector<unsigned char> >& bytes);
	void maybe_send_bytes(const std::shared_ptr<std::vector<unsigned char> >& bytes);

	void get_send_mutex() { send_mutex.lock(); outside_send_mutex_held = true; }
	void release_send_mutex() { outside_send_mutex_held = false; send_mutex.unlock(); }

private:
	void disconnect_from_outside(const char* reason, bool push_send);

public:
	void disconnect_from_outside(const char* reason) {
		return disconnect_from_outside(reason, true);
	}

private:
	void disconnect(const char* reason);
	static void do_setup_and_read(Connection* me);
	static void do_write(Connection* me);
	void net_write();
};

#endif
