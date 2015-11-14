#ifndef _RELAY_CONNECTION_H
#define _RELAY_CONNECTION_H

#include <string>
#include <atomic>
#include <condition_variable>
#include <thread>
#include <list>
#include <vector>
#include <set>
#include <assert.h>

#include "utils.h"

enum DisconnectFlags {
	DISCONNECT_STARTED = 1,
	DISCONNECT_PRINT_AND_CLOSE = 2,
	DISCONNECT_READS_DONE = 4,
	DISCONNECT_GLOBAL_THREAD_DONE = 8,
	DISCONNECT_COMPLETE = 16,
};

class Connection {
private:
	const int sock;
	std::mutex send_mutex, send_bytes_mutex;
	int outside_send_mutex_token;

	std::function<void(void)> on_disconnect;

	std::list<std::shared_ptr<std::vector<unsigned char> > > outbound_primary_queue, outbound_secondary_queue;
	size_t primary_writepos, secondary_writepos;

	// During initial_outbound_throttle, total_waiting_size is allowed to exceed the
	// usual outbound buffer size but only by initial_outbound_bytes
	//
	// initial_outbound_bytes is defined as the quantity of bytes sent with send_mutex_token
	// (not mabye_send, do_send), during initial_outbound_throttle
	std::atomic_bool initial_outbound_throttle;
	std::atomic_flag initial_outbound_throttle_done;
	int64_t initial_outbound_bytes;
	std::atomic<int64_t> total_waiting_size;
	std::chrono::steady_clock::time_point earliest_next_write;
	uint32_t max_outbound_buffer_size;

	std::mutex read_mutex;
	std::condition_variable read_cv;
	size_t readpos;
	std::atomic<int64_t> total_inbound_size;
	std::list<std::unique_ptr<std::vector<unsigned char> > > inbound_queue;

	std::thread *user_thread;
	int sock_errno;

	std::atomic<int> disconnectFlags;
public:
	const std::string host;

	Connection(int sockIn, std::string hostIn, std::function<void(void)> on_disconnect_in, uint32_t max_outbound_buffer_size_in=10000000) :
			sock(sockIn), outside_send_mutex_token(0xdeadbeef * (unsigned long)this), on_disconnect(on_disconnect_in),
			primary_writepos(0), secondary_writepos(0), initial_outbound_throttle(false), initial_outbound_throttle_done(false),
			initial_outbound_bytes(0), total_waiting_size(0), earliest_next_write(std::chrono::steady_clock::time_point::min()),
			max_outbound_buffer_size(max_outbound_buffer_size_in), readpos(0), total_inbound_size(0), sock_errno(0),
			disconnectFlags(0), host(hostIn)
		{}

protected:
	void construction_done() {
		user_thread = new std::thread(do_setup_and_read, this);
	}

public:
	virtual ~Connection();

	int getDisconnectFlags() { return disconnectFlags; }

protected:
	virtual void net_process(const std::function<void(std::string)>& disconnect)=0;
	ssize_t read_all(char *buf, size_t nbyte, millis_lu_type max_sleep = millis_lu_type::max()); // Only allowed from within net_process

	void do_send_bytes(const char *buf, size_t nbyte, int send_mutex_token=0) {
		do_send_bytes(std::make_shared<std::vector<unsigned char> >((unsigned char*)buf, (unsigned char*)buf + nbyte), send_mutex_token);
	}

	void do_send_bytes(const std::shared_ptr<std::vector<unsigned char> >& bytes, int send_mutex_token=0);
	void maybe_send_bytes(const std::shared_ptr<std::vector<unsigned char> >& bytes, int send_mutex_token=0);

public:
	// See the comment above initial_outbound_throttle for special meanings of the send_mutex_tokens
	int get_send_mutex();
	void release_send_mutex(int send_mutex_token);
	void do_throttle_outbound() { if (!initial_outbound_throttle_done.test_and_set()) initial_outbound_throttle = true; }

	void disconnect_from_outside(const char* reason);

private:
	void disconnect(std::string reason);
	static void do_setup_and_read(Connection* me);

	friend class GlobalNetProcess;
};

class OutboundPersistentConnection {
private:
	std::atomic_int mutex_valid;
	uint32_t max_outbound_buffer_size;

	class OutboundConnection : public Connection {
	private:
		OutboundPersistentConnection *parent;
		void net_process(const std::function<void(std::string)>& disconnect) { parent->on_connect_keepalive(); parent->net_process(disconnect); }

	public:
		OutboundConnection(int sockIn, OutboundPersistentConnection* parentIn) :
				Connection(sockIn, parentIn->serverHost, [&](void) { parent->reconnect("THIS SHOULD NEVER PRINT"); }, parentIn->max_outbound_buffer_size),
				parent(parentIn)
			{ }

		ssize_t read_all(char *buf, size_t nbyte, millis_lu_type max_sleep) { return Connection::read_all(buf, nbyte, max_sleep); }
		void do_send_bytes(const char *buf, size_t nbyte, int send_mutex_token) { return Connection::do_send_bytes(buf, nbyte, send_mutex_token); }
		void do_send_bytes(const std::shared_ptr<std::vector<unsigned char> >& bytes, int send_mutex_token) { return Connection::do_send_bytes(bytes, send_mutex_token); }
		void construction_done() { Connection::construction_done(); }
	};

	std::atomic<unsigned long> connection;
	static_assert(sizeof(unsigned long) == sizeof(OutboundConnection*), "unsigned long must be the size of a pointer");

public:
	const std::string serverHost;
	const uint16_t serverPort;

	OutboundPersistentConnection(std::string serverHostIn, uint16_t serverPortIn, uint32_t max_outbound_buffer_size_in=10000000) :
			mutex_valid(false), max_outbound_buffer_size(max_outbound_buffer_size_in), connection(0), serverHost(serverHostIn), serverPort(serverPortIn)
		{}

	int get_send_mutex();
	void release_send_mutex(int token);
	void do_throttle_outbound(int token) {
		OutboundConnection* conn = (OutboundConnection*)connection.load();
		if (conn && mutex_valid == token)
			conn->do_throttle_outbound();
	}

	void disconnect_from_outside(const char* reason) {
		OutboundConnection* conn = (OutboundConnection*)connection.load();
		if (conn)
			conn->disconnect_from_outside(reason);
	}

protected:
	void construction_done() { std::thread(do_connect, this).detach(); }

	virtual void on_disconnect()=0;
	virtual void net_process(const std::function<void(std::string)>& disconnect)=0;
	ssize_t read_all(char *buf, size_t nbyte, millis_lu_type max_sleep = millis_lu_type::max()) { return ((OutboundConnection*)connection.load())->read_all(buf, nbyte, max_sleep); } // Only allowed from within net_process

	void maybe_do_send_bytes(const char *buf, size_t nbyte, int send_mutex_token=0) {
		OutboundConnection* conn = (OutboundConnection*)connection.load();
		if (conn) {
			assert(!mutex_valid || send_mutex_token == mutex_valid);
			conn->do_send_bytes(buf, nbyte, mutex_valid == send_mutex_token ? send_mutex_token : 0);
		}
	}
	void maybe_do_send_bytes(const std::shared_ptr<std::vector<unsigned char> >& bytes, int send_mutex_token=0) {
		OutboundConnection* conn = (OutboundConnection*)connection.load();
		if (conn) {
			assert(!mutex_valid || send_mutex_token == mutex_valid);
			conn->do_send_bytes(bytes, mutex_valid == send_mutex_token ? send_mutex_token : 0);
		}
	}

private:
	void reconnect(std::string disconnectReason); // Called only after DISCONNECT_COMPLETE in Connection, or before Connection::construction_done()
	static void do_connect(OutboundPersistentConnection* me);

	virtual void on_disconnect_keepalive() {}
	virtual void on_connect_keepalive() {}
	friend class KeepaliveOutboundPersistentConnection;
};

class KeepaliveOutboundPersistentConnection : public OutboundPersistentConnection {
private:
	std::mutex ping_mutex;
	bool connected;
	std::set<uint64_t> ping_nonces_waiting;
	uint64_t next_nonce;

	uint32_t ping_interval_msec;
	bool scheduled;

	void schedule();

	void on_disconnect_keepalive();
	void on_connect_keepalive();

protected:
	virtual void send_ping(uint64_t nonce)=0;
	void pong_received(uint64_t nonce);

public:
	KeepaliveOutboundPersistentConnection(std::string serverHostIn, uint16_t serverPortIn,
			uint32_t ping_interval_msec, uint32_t max_outbound_buffer_size_in=10000000);
};

#endif
