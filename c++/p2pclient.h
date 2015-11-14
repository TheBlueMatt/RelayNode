#ifndef _RELAY_P2PCLIENT_H
#define _RELAY_P2PCLIENT_H

#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <mutex>

#include "utils.h"
#include "mruset.h"
#include "connection.h"


class P2PRelayer : public KeepaliveOutboundPersistentConnection {
private:
	const std::function<void (std::vector<unsigned char>&, const std::chrono::system_clock::time_point&)> provide_block;
	const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)> provide_transaction;

	const std::function<void (std::vector<unsigned char>&)> provide_headers;

	DECLARE_ATOMIC_INT(uint8_t, connected);

	std::mutex seen_mutex;
	mruset<std::vector<unsigned char> > txnAlreadySeen;
	mruset<std::vector<unsigned char> > blocksAlreadySeen;

	const bool check_block_msghash;

public:
	P2PRelayer(const char* serverHostIn, uint16_t serverPortIn, uint64_t ping_time_nonce,
				const std::function<void (std::vector<unsigned char>&, const std::chrono::system_clock::time_point&)>& provide_block_in,
				const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)>& provide_transaction_in,
				const std::function<void (std::vector<unsigned char>&)> provide_headers_in = std::function<void (std::vector<unsigned char>&)>(),
				bool check_block_msghash_in=true)
			: KeepaliveOutboundPersistentConnection(serverHostIn, serverPortIn, ping_time_nonce),
			provide_block(provide_block_in), provide_transaction(provide_transaction_in), provide_headers(provide_headers_in),
			connected(0), txnAlreadySeen(2000), blocksAlreadySeen(100), check_block_msghash(check_block_msghash_in)
	{}

protected:
	virtual std::vector<unsigned char> generate_version() =0;

	void on_disconnect();
	void net_process(const std::function<void(std::string)>& disconnect);
	void send_message(const char* command, unsigned char* headerAndData, size_t datalen);

	void send_ping(uint64_t nonce);

public:
	void receive_transaction(const std::shared_ptr<std::vector<unsigned char> >& tx);
	void receive_block(std::vector<unsigned char>& block);
	void request_transaction(const std::vector<unsigned char>& txhash);

	bool is_connected() const;
};

#endif
