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

public:
	RPCClient(std::string hostIn, int16_t portIn, const std::function<void (std::vector<std::pair<std::vector<unsigned char>, size_t> >& txhashes, size_t total_mempool_size)>& txn_for_block_func_in)
		: OutboundPersistentConnection(hostIn, portIn), txn_for_block_func(txn_for_block_func_in) { on_disconnect(); construction_done(); }
	void maybe_get_txn_for_block();

private:
	void on_disconnect();
	void net_process(const std::function<void(std::string)>& disconnect);
};

#endif
