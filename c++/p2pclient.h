#ifndef _RELAY_P2PCLIENT_H
#define _RELAY_P2PCLIENT_H

#include <vector>
#include <set>
#include <string>
#include <thread>
#include <chrono>
#include <mutex>
#include <atomic>

#include "utils.h"
#include "mruset.h"
#include "connection.h"


class P2PRelayer : public OutboundPersistentConnection {
private:
	const std::function<void (std::vector<unsigned char>&, const std::chrono::system_clock::time_point&)> provide_block;
	const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)> provide_transaction;

	const std::function<void (std::vector<unsigned char>&)> provide_headers;
	const std::function<void (void)> mempools_done;

	static const uint8_t CONNECTED_FLAG_REQUEST_MEMPOOL = 0x80;
	static const uint8_t CONNECTED_FLAGS = CONNECTED_FLAG_REQUEST_MEMPOOL;
	std::atomic<uint8_t> connected;

	std::mutex ping_nonce_mutex;
	unsigned int ping_nonce_max = 0;
	std::set<uint64_t> ping_nonce_set;
	bool inv_recvd;
	uint64_t mempool_start_ping = 0, mempool_end_ping = 0;

	const bool accept_loose_txn, regularly_request_mempool;
	std::chrono::steady_clock::time_point last_mempool_request;
	mruset<std::vector<unsigned char> > send_txn_set;
	bool mempool_failed;

public:
	P2PRelayer(const char* serverHostIn, uint16_t serverPortIn,
				const std::function<void (std::vector<unsigned char>&, const std::chrono::system_clock::time_point&)>& provide_block_in,
				const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)>& provide_transaction_in,
				const std::function<void (std::vector<unsigned char>&)> provide_headers_in = std::function<void (std::vector<unsigned char>&)>(),
				const std::function<void (void)> mempools_done_in = std::function<void(void)>(),
				bool accept_loose_txn_in=true, bool regularly_request_mempool_in=false)
			: OutboundPersistentConnection(serverHostIn, serverPortIn),
			provide_block(provide_block_in), provide_transaction(provide_transaction_in), provide_headers(provide_headers_in),
			mempools_done(mempools_done_in), connected(0), accept_loose_txn(accept_loose_txn_in), regularly_request_mempool(regularly_request_mempool_in),
			last_mempool_request(std::chrono::steady_clock::time_point::min()), send_txn_set(MAX_TXN_IN_FAS), mempool_failed(false)
	{}

protected:
	virtual std::vector<unsigned char> generate_version() =0;

	void on_disconnect();
	void net_process(const std::function<void(const char*)>& disconnect);
	void send_message(const char* command, unsigned char* headerAndData, size_t datalen);

public:
	void receive_transaction(const std::shared_ptr<std::vector<unsigned char> >& tx);
	void receive_block(std::vector<unsigned char>& block);
	void request_mempool();
	bool maybe_supports_mempool() { return !mempool_failed; }

private:
	void maybe_request_mempool();
	uint64_t do_send_ping(bool track_nonce);
	void do_request_mempool(bool track_nonce);
};

#endif
