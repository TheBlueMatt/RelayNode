#ifndef _RELAY_RPCCLIENT_H
#define _RELAY_RPCCLIENT_H

#include <vector>
#include <string>
#include <stdint.h>

#include "connection.h"

void RPCClient_net_process(std::function<ssize_t(char*, size_t, millis_lu_type max_sleep)>& read_all,
							const std::function<void(std::string)>& disconnect,
							std::function<void (std::vector<std::vector<unsigned char> >& txhashes)> txn_for_block_func,
							std::atomic_bool& awaiting_response);

std::string RPCClient_get_request_string();

template <class Conn>
class RPCClient : public Conn {
private:
	const std::function<void (std::vector<std::vector<unsigned char> >& txhashes)> txn_for_block_func;

	std::atomic_bool connected;
	std::atomic_bool awaiting_response;

public:
	RPCClient(std::string hostIn, int16_t portIn, const std::function<void (std::vector<std::vector<unsigned char> >& txhashes)>& txn_for_block_func_in)
		: Conn(hostIn, portIn), txn_for_block_func(txn_for_block_func_in) { on_disconnect(); this->construction_done(); }

	void maybe_get_txn_for_block() {
		if (!connected || awaiting_response.exchange(true))
			return;
		std::string bytes(RPCClient_get_request_string());
		this->maybe_do_send_bytes(bytes.c_str(), bytes.length());
	}

private:
	void on_disconnect() {
		connected = false;
		awaiting_response = false;
	}

	void net_process(const std::function<void(std::string)>& disconnect) {
		connected = true;
		std::function<ssize_t(char*, size_t, millis_lu_type)> read_all = [&](char* buf, size_t count, millis_lu_type max_sleep) { return Conn::read_all(buf, count, max_sleep); };
		return RPCClient_net_process(read_all, disconnect, txn_for_block_func, awaiting_response);
	}
};

#endif
