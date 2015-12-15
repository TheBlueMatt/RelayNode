#ifndef _RELAY_RELAYCONNECTION_H
#define _RELAY_RELAYCONNECTION_H

#include "preinclude.h"

#include "relayprocess.h"

#include <vector>
#include <chrono>
#include <memory>
#include <functional>

class RelayConnectionProcessor {
private:
	enum ReadState {
		READ_STATE_NEW_MESSAGE,
		READ_STATE_IN_SIZED_MESSAGE,
		READ_STATE_START_BLOCK_MESSAGE,
		READ_STATE_IN_BLOCK_MESSAGE,
		READ_STATE_DISCONNECTED,
	};
	ReadState read_state;
	bool have_received_version_msg;
	std::vector<char> read_buff;

	relay_msg_header current_msg;
	RelayNodeCompressor::DecompressState current_block;
	std::unique_ptr<RelayNodeCompressor::DecompressLocks> current_block_locks;

	std::chrono::steady_clock::time_point current_block_read_start;

	RELAY_DECLARE_CLASS_VARS

protected:
	RelayNodeCompressor compressor;

public:
	RelayConnectionProcessor() : read_state(READ_STATE_NEW_MESSAGE), have_received_version_msg(false),
			current_block(false, 1), RELAY_DECLARE_CONSTRUCTOR_EXTENDS, compressor(false, false) {}

protected:
	virtual const char* handle_peer_version(const std::string& peer_version)=0;
	virtual const char* handle_max_version(const std::string& max_version)=0;
	virtual void handle_block(RelayNodeCompressor::DecompressState& block,
			std::chrono::system_clock::time_point& read_end_time,
			std::chrono::steady_clock::time_point& read_end,
			std::chrono::steady_clock::time_point& read_start)=0;
	virtual void handle_transaction(std::shared_ptr<std::vector<unsigned char> >& tx)=0;
	virtual void disconnect(const char* reason)=0;
	virtual void do_send_bytes(const char *buf, size_t nbyte)=0;

private:
	inline size_t fail_msg(const char* reason) {
		disconnect(reason);
		read_state = READ_STATE_DISCONNECTED;
		return 0;
	}

	bool process_version_message(size_t read_pos) {
		char data[ntohl(current_msg.length) + 1];
		memcpy(data, &read_buff[read_pos], ntohl(current_msg.length));

		for (uint32_t i = 0; i < ntohl(current_msg.length); i++)
			if (data[i] > 'z' && data[i] < 'a' && data[i] != ' ')
				return fail_msg("bogus version string");
		data[ntohl(current_msg.length)] = 0;

		std::string their_version(data);
		const char* err = handle_peer_version(their_version);
		if (err)
			return fail_msg(err);

		have_received_version_msg = true;

		return true;
	}

	bool process_max_version_message(size_t read_pos) {
		char data[ntohl(current_msg.length) + 1];
		memcpy(data, &read_buff[read_pos], ntohl(current_msg.length));

		for (uint32_t i = 0; i < ntohl(current_msg.length); i++)
			if (data[i] > 'z' && data[i] < 'a' && data[i] != ' ')
				return fail_msg("bogus max_version string");
		data[ntohl(current_msg.length)] = 0;

		std::string max_version(data);
		const char* err = handle_max_version(max_version);
		if (err)
			return fail_msg(err);

		return true;
	}

	void start_block_message() {
		current_block_read_start = std::chrono::steady_clock::now();
		current_block.reset(true, ntohl(current_msg.length));
		current_block_locks.reset(new RelayNodeCompressor::DecompressLocks(&compressor));
		read_state = READ_STATE_IN_BLOCK_MESSAGE;
	}

	ssize_t process_block_message(size_t read_pos) {
		std::chrono::system_clock::time_point read_finish_time(std::chrono::system_clock::now());
		std::chrono::steady_clock::time_point read_finish(std::chrono::steady_clock::now());

		size_t start_read_pos = read_pos;
		std::function<bool(char*, size_t)> do_read = [&](char* buf, size_t count) {
			if (read_pos + count > read_buff.size())
				return false;
			memcpy(buf, &read_buff[read_pos], count);
			read_pos += count;
			return true;
		};

		const char* err = compressor.do_partial_decompress(*current_block_locks, current_block, do_read);
		if (err) {
			current_block.clear();
			current_block_locks.reset(NULL);
			fail_msg(err);
			return -1;
		}

		if (current_block.is_finished()) {
			current_block_locks.reset(NULL);
			handle_block(current_block, read_finish_time, read_finish, current_block_read_start);
			current_block.clear();
			read_state = READ_STATE_NEW_MESSAGE;
		}

		return read_pos - start_read_pos;
	}

	bool process_transaction_message(size_t read_pos, bool outOfBand) {
		if (ntohl(current_msg.length) > 1000000)
			return fail_msg("got transaction too large");

		if (!outOfBand && !compressor.maybe_recv_tx_of_size(ntohl(current_msg.length), false))
			return fail_msg("got freely relayed transaction too large");

		auto tx = std::make_shared<std::vector<unsigned char> > (ntohl(current_msg.length));
		memcpy(&(*tx)[0], &read_buff[read_pos], ntohl(current_msg.length));

		if (!outOfBand)
			compressor.recv_tx(tx);
		handle_transaction(tx);

		return true;
	}

	bool process_ping_message(size_t read_pos) {
		if (ntohl(current_msg.length) != 8)
			return fail_msg("got ping message of non-8 length");

		relay_msg_header pong_msg_header = { RELAY_MAGIC_BYTES, PONG_TYPE, htonl(8) };
		char data[8 + sizeof(pong_msg_header)];
		memcpy(data + sizeof(pong_msg_header), &read_buff[read_pos], 8);
		memcpy(data, &pong_msg_header, sizeof(pong_msg_header));

		do_send_bytes(data, sizeof(data));

		return true;
	}

	size_t process_messages() {
		size_t read_pos = 0;
		while (read_buff.size() > read_pos) {
			switch (read_state) {
				case READ_STATE_DISCONNECTED:
					return 0;
				case READ_STATE_NEW_MESSAGE:
					if (read_buff.size() - read_pos < 4*3)
						return read_pos;
					memcpy((char*)&current_msg, &read_buff[read_pos], 4*3);
					read_pos += 4*3;

					if (current_msg.magic != RELAY_MAGIC_BYTES)
						return fail_msg("invalid magic bytes");

					if (ntohl(current_msg.length) > 1000000)
						return fail_msg("got message too large");

					if (have_received_version_msg != true && current_msg.type != VERSION_TYPE)
						return fail_msg("got non-version before version");

					if (current_msg.type == BLOCK_TYPE)
						read_state = READ_STATE_START_BLOCK_MESSAGE;
					else
						read_state = READ_STATE_IN_SIZED_MESSAGE;
					break;
				case READ_STATE_IN_SIZED_MESSAGE:
					if (read_buff.size() - read_pos < ntohl(current_msg.length))
						return read_pos;

					if (current_msg.type == VERSION_TYPE) {
						if (!process_version_message(read_pos))
							return 0;
					} else if (current_msg.type == MAX_VERSION_TYPE) {
						if (!process_max_version_message(read_pos))
							return 0;
					} else if (current_msg.type == SPONSOR_TYPE) {
					} else if (current_msg.type == END_BLOCK_TYPE) {
						if (ntohl(current_msg.length) != 0)
							return fail_msg("got non-0-length END_BLOCK message");
					} else if (current_msg.type == TRANSACTION_TYPE) {
						if (!process_transaction_message(read_pos, false))
							return 0;
					} else if (current_msg.type == OOB_TRANSACTION_TYPE) {
						if (!process_transaction_message(read_pos, true))
							return 0;
					} else if (current_msg.type == PING_TYPE) {
						if (!process_ping_message(read_pos))
							return 0;
					} else
						return fail_msg("got unknown message type");

					read_pos += ntohl(current_msg.length);
					read_state = READ_STATE_NEW_MESSAGE;

					break;
				case READ_STATE_START_BLOCK_MESSAGE:
					start_block_message();
				case READ_STATE_IN_BLOCK_MESSAGE:
					ssize_t res = process_block_message(read_pos);
					if (res < 0)
						return 0;
					else if (res == 0)
						return read_pos;
					read_pos += res;
					break;
			}
		}
		return read_pos;
	}

protected:
	void recv_bytes(char* buf, size_t len) {
		read_buff.insert(read_buff.end(), buf, buf + len);
		size_t read = process_messages();
		if (read) {
			read_buff.erase(read_buff.begin(), read_buff.begin() + read);
			read_buff.reserve(65536);
		}
	}
};

#endif
