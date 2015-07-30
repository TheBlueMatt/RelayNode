#include "lzmaconnection.h"

#include <string.h>

LZMACompressor::LZMACompressor(std::function<void(const char*, size_t)> write_compressed_in, std::function<void(const char*, size_t)> read_decompressed_in) :
		write_compressed(write_compressed_in), read_decompressed(read_decompressed_in) {
	reset();
}

LZMACompressor::~LZMACompressor() {
	lzma_end(&write_stream);
	lzma_end(&read_stream);
}

void LZMACompressor::reset() {
	ALWAYS_ASSERT(lzma_easy_encoder(&write_stream, 6, LZMA_CHECK_CRC64) == LZMA_OK);
	ALWAYS_ASSERT(lzma_stream_decoder(&read_stream, UINT64_MAX, 0) == LZMA_OK);

	write_stream.next_out = (unsigned char*)write_out_buf;
	write_stream.avail_out = sizeof(write_out_buf);

	read_stream.next_out = (unsigned char*)read_out_buf;
	read_stream.avail_out = sizeof(read_out_buf);
	read_stream.next_in = (unsigned char*)read_in_buf;
	read_stream.avail_in = 0;
}


bool LZMACompressor::write_bytes(const char* buf, size_t nbytes) {
	std::lock_guard<std::mutex> lock(write_mutex);

	write_stream.next_in = (unsigned char*)buf;
	write_stream.avail_in = nbytes;

	lzma_ret res;
	do {
		res = lzma_code(&write_stream, LZMA_SYNC_FLUSH);
		if (res != LZMA_OK && res != LZMA_STREAM_END)
			return false;

		if (sizeof(write_out_buf) - write_stream.avail_out > 0) {
			write_compressed(write_out_buf, sizeof(write_out_buf) - write_stream.avail_out);
			write_stream.next_out = (unsigned char*)write_out_buf;
			write_stream.avail_out = sizeof(write_out_buf);
		} else if (res != LZMA_STREAM_END)
			return false;
	} while (res != LZMA_STREAM_END);

	if (write_stream.avail_in)
		return false;

	write_stream.next_in = NULL;
	write_stream.avail_in = 0;
	return true;
}

bool LZMACompressor::read_bytes(const char* buf, size_t nbytes) {
	std::lock_guard<std::mutex> lock(read_mutex);

	assert(read_stream.next_in == (unsigned char*)read_in_buf);
	size_t copied = 0;
	do {
		size_t copy = std::min(sizeof(read_in_buf) - read_stream.avail_in, nbytes - copied);
		memcpy(const_cast<unsigned char*>(read_stream.next_in) + read_stream.avail_in, buf + copied, copy);
		read_stream.avail_in += copy;
		copied += copy;

		lzma_ret res = lzma_code(&read_stream, LZMA_RUN);
		if (res != LZMA_OK)
			return false;

		if (read_stream.avail_out - sizeof(read_out_buf) > 0) {
			read_decompressed(read_out_buf, sizeof(read_out_buf) - read_stream.avail_out);
			read_stream.next_out = (unsigned char*)read_out_buf;
			read_stream.avail_out = sizeof(read_out_buf);
		}

		if (read_stream.avail_in)
			memmove(read_in_buf, read_stream.next_in, read_stream.avail_in);
		read_stream.next_in = (unsigned char*)read_in_buf;

		if (copied == nbytes)
			break;
	} while (true);
	return true;
}

LZMAConnection::OutboundLZMAConnection::OutboundLZMAConnection(LZMAConnection* parentIn, int sock, std::string host)
	: Connection(sock, host, [&]() { parent->in_conn.disconnect_from_outside("Lost outbound connection"); }, 262144), parent(parentIn)
	{}

LZMAConnection::InboundLZMAConnection::InboundLZMAConnection(LZMAConnection* parentIn, int sock, std::string host)
	: Connection(sock, host, [&]() { parent->out_conn.disconnect_from_outside("Lost inbound connection"); }, 262144), parent(parentIn)
	{}

void LZMAConnection::OutboundLZMAConnection::net_process(const std::function<void(std::string)>& disconnect) {
	char buf[65536];
	while (true) {
		ssize_t read = maybe_read(buf, 65536);
		if (read <= 0)
			return disconnect("Failed to read bytes from socket");
		if (!parent->compressor.write_bytes(buf, read))
			return disconnect("Failed to compress new data");
	}
}

void LZMAConnection::InboundLZMAConnection::net_process(const std::function<void(std::string)>& disconnect) {
	char buf[65536];
	while (true) {
		ssize_t read = maybe_read(buf, 65536);
		if (read <= 0)
			return disconnect("Failed to read bytes from socket");
		if (!parent->compressor.read_bytes(buf, read))
			return disconnect("Failed to decompress new data");
	}
}

LZMAConnection::LZMAConnection(int inSock, std::string host, int outSock) :
		in_conn(this, inSock, host), out_conn(this, outSock, "127.0.0.1"),
		compressor([&](const char* buf, size_t size) {
				in_conn.do_blocking_write(buf, size);
			}, [&](const char* buf, size_t size) {
				out_conn.do_blocking_write(buf, size);
			}) {
	in_conn.construction_done();
	out_conn.construction_done();
}

LZMAOutboundPersistentConnection::LZMAOutboundPersistentConnection(std::string serverHostIn, uint16_t serverPortIn, std::function<void(void)> on_disconnect_in) :
	OutboundPersistentConnection(serverHostIn, serverPortIn, [&]() { compressor.reset(); if (on_disconnect) on_disconnect(); }),
	compressor([&](const char* buf, size_t size) {
				// Newer GCCs let us call maybe_do_send_bytes directly, but we work around it for older ones
				workaround_maybe_do_send_bytes(buf, size);
			}, [&](const char* buf, size_t size) {
				pending_reads.emplace_back(buf, buf + size);
				pending_total += size;
			}), on_disconnect(on_disconnect_in) {}

ssize_t LZMAOutboundPersistentConnection::read_all(char *buf, size_t nbyte, millis_lu_type max_sleep) {

	std::chrono::system_clock::time_point stop_time;
	if (max_sleep != millis_lu_type::max())
		stop_time = std::chrono::system_clock::now() + max_sleep;

	char stackbuf[8192];
	while (pending_total < nbyte) {
		millis_lu_type this_sleep;
		if (max_sleep == millis_lu_type::max())
			this_sleep = millis_lu_type::max();
		else
			this_sleep = to_millis_lu_dur(stop_time - std::chrono::system_clock::now());

		ssize_t read = OutboundPersistentConnection::maybe_read(stackbuf, sizeof(stackbuf), this_sleep);
		if (read <= 0)
			return read;
		if (!compressor.read_bytes(stackbuf, read))
			return -1;
	}

	size_t total = 0;
	while (total < nbyte) {
		size_t to_read = std::min(pending_reads.front().size() - pending_read_pos, nbyte - total);
		memcpy(buf, &pending_reads.front()[pending_read_pos], to_read);

		pending_read_pos += to_read;
		total += to_read;
		buf += to_read;
		pending_total -= to_read;

		if (pending_read_pos == pending_reads.front().size()) {
			pending_reads.pop_front();
			pending_read_pos = 0;
		}
	}
	return total;
}

void LZMAOutboundPersistentConnection::maybe_do_send_bytes(const char *buf, size_t nbyte, int send_mutex_token) {
	std::lock_guard<std::mutex> lock(write_mutex);
	if (!compressor.write_bytes(buf, nbyte))
		return disconnect("Failed to compress bytes to write");
}

void LZMAOutboundPersistentConnection::maybe_do_send_bytes(const std::shared_ptr<std::vector<unsigned char> >& bytes, int send_mutex_token) {
	std::lock_guard<std::mutex> lock(write_mutex);
	if (!compressor.write_bytes((char*) &(*bytes)[0], bytes->size()))
		return disconnect("Failed to compress bytes to write");
}
