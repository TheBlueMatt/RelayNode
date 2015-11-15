#ifndef _RELAY_CONNECTION_H
#define _RELAY_CONNECTION_H

#include <string>
#include <condition_variable>
#include <thread>
#include <list>
#include <vector>
#include <set>
#include <assert.h>

#include "utils.h"

class Connection {
private:
	const int sock;

	int outside_send_mutex_token;
	std::mutex send_mutex, send_bytes_mutex;
	std::list<std::shared_ptr<std::vector<unsigned char> > > outbound_primary_queue, outbound_secondary_queue;
	size_t primary_writepos, secondary_writepos;

	// During initial_outbound_throttle, total_waiting_size is allowed to exceed the
	// usual outbound buffer size but only by initial_outbound_bytes
	//
	// initial_outbound_bytes is defined as the quantity of bytes sent with send_mutex_token
	// (not mabye_send, do_send), during initial_outbound_throttle
	DECLARE_ATOMIC(bool, initial_outbound_throttle);
	std::atomic_flag initial_outbound_throttle_done;
	int64_t initial_outbound_bytes;
	DECLARE_ATOMIC_INT(int64_t, total_waiting_size);
	std::chrono::steady_clock::time_point earliest_next_write;
	uint32_t max_outbound_buffer_size;

protected:
	enum DisconnectFlags {
		// Used by Connection:
		DISCONNECT_PRINT_AND_CLOSE = 1,
		DISCONNECT_SOCK_DOWN = 2,
		DISCONNECT_GLOBAL_THREAD_DONE = 4,
		// Used by ThreadedConnection:
		DISCONNECT_STARTED = 8,
		DISCONNECT_THREADS_CLOSED = 16,
	};
	DECLARE_ATOMIC_INT(int, disconnectFlags);
private:
	DECLARE_ATOMIC_INT(int, sock_errno);

public:
	const std::string host;

	Connection(int sockIn, std::string hostIn, uint32_t max_outbound_buffer_size_in=10000000) : sock(sockIn),
			outside_send_mutex_token(0xdeadbeef * (unsigned long)this), primary_writepos(0), secondary_writepos(0),
			initial_outbound_throttle(false), initial_outbound_throttle_done(false),
			initial_outbound_bytes(0), total_waiting_size(0), earliest_next_write(std::chrono::steady_clock::time_point::min()),
			max_outbound_buffer_size(max_outbound_buffer_size_in), disconnectFlags(0), sock_errno(0), host(hostIn)
		{}

	virtual ~Connection();

protected:
	void construction_done();

public:
	// See the comment above initial_outbound_throttle for special meanings of the send_mutex_tokens
	int get_send_mutex();
	void release_send_mutex(int send_mutex_token);
	void do_throttle_outbound() { if (!initial_outbound_throttle_done.test_and_set()) initial_outbound_throttle = true; }

	void disconnect(const char* reason);
	virtual bool disconnectComplete() { return disconnectFlags & DISCONNECT_GLOBAL_THREAD_DONE; }
	bool disconnectStarted() { return disconnectFlags != 0; }
	std::string getDisconnectDebug() {
		int flags = disconnectFlags;
		std::string res("0");
		if (flags & DISCONNECT_PRINT_AND_CLOSE) res += "|PRINT_AND_CLOSE";
		if (flags & DISCONNECT_SOCK_DOWN) res += "|SOCK_DOWN";
		if (flags & DISCONNECT_GLOBAL_THREAD_DONE) res += "|GLOBAL_THREAD_DONE";
		if (flags & DISCONNECT_STARTED) res += "|STARTED";
		if (flags & DISCONNECT_THREADS_CLOSED) res += "|THREADS_CLOSED";
		return res;
	}

protected:
	void do_send_bytes(const char *buf, size_t nbyte, int send_mutex_token=0) {
		do_send_bytes(std::make_shared<std::vector<unsigned char> >((unsigned char*)buf, (unsigned char*)buf + nbyte), send_mutex_token);
	}

	void do_send_bytes(const std::shared_ptr<std::vector<unsigned char> >& bytes, int send_mutex_token=0);
	void maybe_send_bytes(const std::shared_ptr<std::vector<unsigned char> >& bytes, int send_mutex_token=0);

	//recv_bytes will only ever be called in a thread-safe manner, however it may be called, at different times, from different threads
	virtual void recv_bytes(char* buf, size_t len)=0;
	virtual bool readable()=0;
	virtual void on_disconnect_done() {}

private:
	friend class GlobalNetProcess;
};

class ThreadedConnection : public Connection {
private:
	std::function<void(void)> on_disconnect;

	std::mutex read_mutex;
	std::condition_variable read_cv;
	size_t readpos;
	DECLARE_ATOMIC_INT(int64_t, total_inbound_size);
	std::list<std::unique_ptr<std::vector<unsigned char> > > inbound_queue;

	DECLARE_ATOMIC_PTR(std::thread, user_thread);

public:
	ThreadedConnection(int sockIn, std::string hostIn, std::function<void(void)> on_disconnect_in, uint32_t max_outbound_buffer_size_in=10000000) :
			Connection(sockIn, hostIn, max_outbound_buffer_size_in), on_disconnect(on_disconnect_in),
			readpos(0), total_inbound_size(0), user_thread(NULL)
		{}

	void disconnect_from_outside(const char* reason) { Connection::disconnect(reason); }

protected:
	void construction_done() {
		Connection::construction_done();
		user_thread = new std::thread(do_setup_and_read, this);
	}

public:
	virtual ~ThreadedConnection();

	virtual bool disconnectComplete() { return Connection::disconnectComplete() && (disconnectFlags & DISCONNECT_THREADS_CLOSED); }

private:
	void recv_bytes(char* buf, size_t len);
	bool readable();
	void on_disconnect_done();

protected:
	virtual void net_process(const std::function<void(std::string)>& disconnect)=0;
	ssize_t read_all(char *buf, size_t nbyte, millis_lu_type max_sleep = millis_lu_type::max()); // Only allowed from within net_process

private:
	void disconnect(std::string reason);
	static void do_setup_and_read(ThreadedConnection* me);
};

class OutboundPersistentConnection {
private:
	DECLARE_ATOMIC_INT(int, mutex_valid);
	uint32_t max_outbound_buffer_size;

	class OutboundConnection : public ThreadedConnection {
	private:
		OutboundPersistentConnection *parent;
		void net_process(const std::function<void(std::string)>& disconnect) { parent->on_connect_keepalive(); parent->net_process(disconnect); }

	public:
		OutboundConnection(int sockIn, OutboundPersistentConnection* parentIn) :
				ThreadedConnection(sockIn, parentIn->serverHost, [&](void) { parent->reconnect("THIS SHOULD NEVER PRINT"); }, parentIn->max_outbound_buffer_size),
				parent(parentIn)
			{ }

		ssize_t read_all(char *buf, size_t nbyte, millis_lu_type max_sleep) { return ThreadedConnection::read_all(buf, nbyte, max_sleep); }
		void do_send_bytes(const char *buf, size_t nbyte, int send_mutex_token) { return ThreadedConnection::do_send_bytes(buf, nbyte, send_mutex_token); }
		void do_send_bytes(const std::shared_ptr<std::vector<unsigned char> >& bytes, int send_mutex_token) { return ThreadedConnection::do_send_bytes(bytes, send_mutex_token); }
		void construction_done() { ThreadedConnection::construction_done(); }
	};

	DECLARE_ATOMIC_INT(unsigned long, connection);
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
	void reconnect(std::string disconnectReason); // Called only after DISCONNECT_COMPLETE in ThreadedConnection, or before ThreadedConnection::construction_done()
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
