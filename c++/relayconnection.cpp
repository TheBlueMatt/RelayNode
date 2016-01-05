#include "relayconnection.h"

#include <string.h>

bool RelayConnectionProcessor::process_version_message() {
	assert(read_buff.size() == ntohl(current_msg.length));

	for (uint32_t i = 0; i < ntohl(current_msg.length); i++)
		if (read_buff[i] > 'z' && read_buff[i] < 'a' && read_buff[i] != ' ')
			return fail_msg("bogus version string");
	read_buff.push_back(0);

	std::string their_version(&read_buff[0]);
	const char* err = handle_peer_version(their_version);
	if (err)
		return fail_msg(err);

	have_received_version_msg = true;

	return true;
}

bool RelayConnectionProcessor::process_max_version_message() {
	for (uint32_t i = 0; i < ntohl(current_msg.length); i++)
		if (read_buff[i] > 'z' && read_buff[i] < 'a' && read_buff[i] != ' ')
			return fail_msg("bogus max_version string");
	read_buff.push_back(0);

	std::string max_version(&read_buff[0]);
	const char* err = handle_max_version(max_version);
	if (err)
		return fail_msg(err);

	return true;
}

bool RelayConnectionProcessor::process_sponsor_message() {
	for (uint32_t i = 0; i < ntohl(current_msg.length); i++)
		if (read_buff[i] < 0x20 || read_buff[i] > 0x7e)
			return fail_msg("bogus sponsor string");
	read_buff.push_back(0);

	std::string sponsor(&read_buff[0]);
	const char* err = handle_sponsor(sponsor);
	if (err)
		return fail_msg(err);

	return true;
}

void RelayConnectionProcessor::start_block_message() {
	current_block_read_start = std::chrono::steady_clock::now();
	current_block.init(true, ntohl(current_msg.length));
	current_block_locks.reset(new RelayNodeCompressor::DecompressLocks(&compressor));
}

ssize_t RelayConnectionProcessor::process_block_message(char* this_read_buf, size_t read_buf_len) {
	std::chrono::system_clock::time_point read_finish_time(std::chrono::system_clock::now());
	std::chrono::steady_clock::time_point read_finish(std::chrono::steady_clock::now());

#ifndef NDEBUG
	uint32_t start_wire_bytes = current_block.wire_bytes;
#endif

	size_t read_pos = 0;
	std::function<bool(char*, size_t)> do_read = [&](char* buf, size_t count) {
		if (read_pos + count > read_buff.size() + read_buf_len)
			return false;

		ssize_t read_buff_read = std::min(ssize_t(read_buff.size()) - ssize_t(read_pos), ssize_t(count));
		if (read_buff_read > 0) {
			memcpy(buf, &read_buff[read_pos], read_buff_read);
			buf += read_buff_read;
			count -= read_buff_read;
			read_pos += read_buff_read;
		}
		if (count) {
			memcpy(buf, this_read_buf + read_pos - read_buff.size(), count);
			read_pos += count;
		}
		return true;
	};

	const char* err = compressor.do_partial_decompress(*current_block_locks, current_block, do_read);
	if (err) {
		current_block.clear();
		current_block_locks.reset(NULL);
		fail_msg(err);
		return -1;
	}

	size_t buf_consumed = std::max(ssize_t(0), ssize_t(read_pos) - ssize_t(read_buff.size()));

	if (current_block.is_finished()) {
		current_block_locks.reset(NULL);
		handle_block(current_block, read_finish_time, read_finish, current_block_read_start);
		current_block.clear();
		read_state = READ_STATE_NEW_MESSAGE;

		assert(read_pos >= read_buff.size());
		read_buff.clear();
	} else if (buf_consumed != read_buf_len) {
		if (read_pos) {
			assert(read_pos > read_buff.size()); // Otherwise the previous call to do_partial_decompress should have eaten these bytes
			read_buff.clear();
			read_buff.insert(read_buff.begin(), this_read_buf + buf_consumed, this_read_buf + read_buf_len);
		} else
			read_buff.insert(read_buff.end(), this_read_buf, this_read_buf + read_buf_len);
		return read_buf_len;
	} else
		read_buff.clear();

	assert(current_block.wire_bytes == start_wire_bytes + read_pos);
	return buf_consumed;
}

bool RelayConnectionProcessor::process_transaction_message(bool outOfBand) {
	if (ntohl(current_msg.length) > 1000000)
		return fail_msg("got transaction too large");

	if (!outOfBand && !compressor.maybe_recv_tx_of_size(ntohl(current_msg.length), false))
		return fail_msg("got freely relayed transaction too large");

	auto tx = std::make_shared<std::vector<unsigned char> > (ntohl(current_msg.length));
	memcpy(&(*tx)[0], &read_buff[0], ntohl(current_msg.length));

	if (!outOfBand)
		compressor.recv_tx(tx);
	handle_transaction(tx);

	return true;
}

bool RelayConnectionProcessor::process_ping_message() {
	if (ntohl(current_msg.length) != 8)
		return fail_msg("got ping message of non-8 length");

	relay_msg_header pong_msg_header = { RELAY_MAGIC_BYTES, PONG_TYPE, htonl(8) };
	char data[8 + sizeof(pong_msg_header)];
	memcpy(data + sizeof(pong_msg_header), &read_buff[0], 8);
	memcpy(data, &pong_msg_header, sizeof(pong_msg_header));

	do_send_bytes(data, sizeof(data));

	return true;
}

bool RelayConnectionProcessor::process_pong_message() {
	if (ntohl(current_msg.length) != 8)
		return fail_msg("got pong message of non-8 length");

	uint64_t nonce;
	memcpy(&nonce, &read_buff[0], 8);
	handle_pong(nonce);

	return true;
}

bool RelayConnectionProcessor::check_message_header() {
	if (current_msg.magic != RELAY_MAGIC_BYTES)
		return fail_msg("invalid magic bytes");

	if (ntohl(current_msg.length) > 1000000)
		return fail_msg("got message too large");

	if (have_received_version_msg != true && current_msg.type != VERSION_TYPE)
		return fail_msg("got non-version before version");

	return true;
}

void RelayConnectionProcessor::recv_bytes(char* buf, size_t len) {
	while (len) {
		if (read_state == READ_STATE_NEW_MESSAGE || read_state == READ_STATE_IN_SIZED_MESSAGE) {
			size_t msg_size;
			if (read_state == READ_STATE_NEW_MESSAGE)
				msg_size = sizeof(current_msg);
			else
				msg_size = ntohl(current_msg.length);

			size_t read = std::min(msg_size - read_buff.size(), len);
			read_buff.insert(read_buff.end(), buf, buf + read);
			len -= read;
			buf += read;
		}

		switch (read_state) {
			case READ_STATE_DISCONNECTED:
				return;
			case READ_STATE_NEW_MESSAGE:
				if (read_buff.size() < sizeof(current_msg))
					return;
				memcpy(&current_msg, &read_buff[0], sizeof(current_msg));

				if (!check_message_header())
					return;

				if (current_msg.type == BLOCK_TYPE) {
					start_block_message();
					read_state = READ_STATE_IN_BLOCK_MESSAGE;
				} else
					read_state = READ_STATE_IN_SIZED_MESSAGE;
				read_buff.clear();
				break;
			case READ_STATE_IN_SIZED_MESSAGE:
				if (read_buff.size() < ntohl(current_msg.length))
					return;

				if (current_msg.type == VERSION_TYPE) {
					if (!process_version_message())
						return;
				} else if (current_msg.type == MAX_VERSION_TYPE) {
					if (!process_max_version_message())
						return;
				} else if (current_msg.type == SPONSOR_TYPE) {
					if (!process_sponsor_message())
						return;
				} else if (current_msg.type == END_BLOCK_TYPE) {
					if (ntohl(current_msg.length) != 0) {
						disconnect("got non-0-length END_BLOCK message");
						read_state = READ_STATE_DISCONNECTED;
						return;
					}
				} else if (current_msg.type == TRANSACTION_TYPE) {
					if (!process_transaction_message(false))
						return;
				} else if (current_msg.type == OOB_TRANSACTION_TYPE) {
					if (!process_transaction_message(true))
						return;
				} else if (current_msg.type == PING_TYPE) {
					if (!process_ping_message())
						return;
				} else if (current_msg.type == PONG_TYPE) {
					if (!process_pong_message())
						return;
				} else {
					disconnect("got unknown message type");
					read_state = READ_STATE_DISCONNECTED;
					return;
				}

				read_buff.clear();
				read_state = READ_STATE_NEW_MESSAGE;

				break;
			case READ_STATE_IN_BLOCK_MESSAGE:
				ssize_t res = process_block_message(buf, len);
				if (res <= 0)
					return;
				else if (size_t(res) == len)
					return;
				else {
					assert(read_state != READ_STATE_IN_BLOCK_MESSAGE);
					len -= res;
					buf += res;
				}
				break;
		}
	}
}

void RelayConnectionProcessor::reset_read_state() {
	read_state = READ_STATE_NEW_MESSAGE;
	have_received_version_msg = false;
	read_buff.clear();
	read_buff.shrink_to_fit();
	current_block.clear();
	current_block_locks.reset(NULL);
}
