#ifndef _RELAY_LZMA_CONNECTION_H
#define _RELAY_LZMA_CONNECTION_H

#include <atomic>
#include <mutex>
#include <lzma.h>

#include "connection.h"

class LZMACompressor {
private:
	lzma_stream write_stream = LZMA_STREAM_INIT;
	lzma_stream read_stream = LZMA_STREAM_INIT;
	char write_out_buf[65536], read_out_buf[65536], read_in_buf[65536];
	std::mutex write_mutex, read_mutex;

	std::function<void(const char*, size_t)> write_compressed;
	std::function<void(const char*, size_t)> read_decompressed;

public:
	LZMACompressor(std::function<void(const char*, size_t)> write_compressed_in, std::function<void(const char*, size_t)> read_decompressed_in);
	~LZMACompressor();

	bool write_bytes(const char* buf, size_t nbytes);
	bool read_bytes(const char* buf, size_t nbytes);

	void reset();
};

class LZMAConnection {
private:
	class OutboundLZMAConnection : public Connection {
		LZMAConnection* parent;
	public:
		OutboundLZMAConnection(LZMAConnection* parentIn, int sock, std::string host);
		void net_process(const std::function<void(std::string)>& disconnect);
		void do_blocking_write(const char* buf, size_t nbyte) { return do_send_bytes(buf, nbyte, 0, true); }
		void construction_done() { Connection::construction_done(); }
	};

	class InboundLZMAConnection : public Connection {
		LZMAConnection* parent;
	public:
		InboundLZMAConnection(LZMAConnection* parentIn, int sock, std::string host);
		void net_process(const std::function<void(std::string)>& disconnect);
		void do_blocking_write(const char* buf, size_t nbyte) { return do_send_bytes(buf, nbyte, 0, true); }
		void construction_done() { Connection::construction_done(); }
	};

	InboundLZMAConnection in_conn;
	OutboundLZMAConnection out_conn;

	LZMACompressor compressor;

public:
	LZMAConnection(int inSock, std::string host, int outSock);
	int getDisconnectFlags() { return in_conn.getDisconnectFlags() & out_conn.getDisconnectFlags(); }
};

class LZMAOutboundPersistentConnection : public OutboundPersistentConnection {
private:
	LZMACompressor compressor;
	std::list<std::vector<unsigned char> > pending_reads;
	size_t pending_total = 0, pending_read_pos = 0;

	std::mutex write_mutex;

	std::function<void(void)> on_disconnect;

public:
	LZMAOutboundPersistentConnection(std::string serverHostIn, uint16_t serverPortIn, std::function<void(void)> on_disconnect_in);
	ssize_t read_all(char *buf, size_t nbyte, millis_lu_type max_sleep = millis_lu_type::max()); // Only allowed from within net_process

	void maybe_do_send_bytes(const char *buf, size_t nbyte, int send_mutex_token=0);
	void maybe_do_send_bytes(const std::shared_ptr<std::vector<unsigned char> >& bytes, int send_mutex_token=0);
};

#endif
