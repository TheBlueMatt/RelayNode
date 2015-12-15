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

	void recv_bytes(char* buf, size_t len);

private:
	inline size_t fail_msg(const char* reason) {
		disconnect(reason);
		read_state = READ_STATE_DISCONNECTED;
		return 0;
	}

	bool process_version_message(size_t read_pos);
	bool process_max_version_message(size_t read_pos);
	void start_block_message();
	ssize_t process_block_message(size_t read_pos);
	bool process_transaction_message(size_t read_pos, bool outOfBand);
	bool process_ping_message(size_t read_pos);
	size_t process_messages();
};

#endif
