#ifndef _RELAY_RPCCLIENT_H
#define _RELAY_RPCCLIENT_H

#include <vector>
#include <string>
#include <stdint.h>

#include "connection.h"

class RPCClient : public OutboundPersistentConnection {
private:
	const std::function<void (std::vector<std::vector<unsigned char> >& txhashes)> txn_for_block_func;

	std::atomic_bool connected;
	std::atomic_bool awaiting_response;

public:
	RPCClient(std::string hostIn, int16_t portIn, const std::function<void (std::vector<std::vector<unsigned char> >& txhashes)>& txn_for_block_func_in)
		: OutboundPersistentConnection(hostIn, portIn), txn_for_block_func(txn_for_block_func_in) { on_disconnect(); construction_done(); }
	void maybe_get_txn_for_block();

private:
	void send_request(const std::string& call, const std::vector<std::string>& params, int id);

	void on_disconnect();
	void net_process(const std::function<void(std::string)>& disconnect);
};

#endif
