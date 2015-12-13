#ifndef _RELAY_RPCCLIENT_H
#define _RELAY_RPCCLIENT_H

#include <vector>
#include <utility>
#include <string>
#include <stdint.h>

#include "connection.h"

class RPCClient : public OutboundPersistentConnection {
private:
	const std::function<void (std::vector<std::pair<std::vector<unsigned char>, size_t> >&, size_t)> txn_for_block_func;

	DECLARE_ATOMIC(bool, connected);
	DECLARE_ATOMIC(bool, awaiting_response);

	std::mutex read_mutex;
	std::condition_variable read_cv;
	size_t readpos;
	DECLARE_ATOMIC_INT(uint64_t, total_inbound_size);
	char inbound_queue[65536 + CONNECTION_MAX_READ_BYTES];

	DECLARE_NON_ATOMIC_PTR(std::thread, read_thread);

public:
	RPCClient(std::string hostIn, int16_t portIn, const std::function<void (std::vector<std::pair<std::vector<unsigned char>, size_t> >& txhashes, size_t total_mempool_size)>& txn_for_block_func_in)
		: OutboundPersistentConnection(hostIn, portIn), txn_for_block_func(txn_for_block_func_in) { on_disconnect(); construction_done(); }
	void maybe_get_txn_for_block();

private:
	void on_connect();
	void on_disconnect();
	bool readable();
	void recv_bytes(char* buf, size_t len);

	void disconnect(const char*);
	void disconnect(const std::string& reason) { disconnect(reason.c_str()); }
	ssize_t read_all(char *buf, size_t nbyte, millis_lu_type max_sleep = millis_lu_type::max());
	void net_process();
};

#endif
