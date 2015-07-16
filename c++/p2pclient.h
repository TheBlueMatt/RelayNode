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

	std::atomic<uint8_t> connected;

	std::mutex sent_mutex;
	mruset<std::vector<unsigned char> > txnAlreadySent;

public:
	P2PRelayer(const char* serverHostIn, uint16_t serverPortIn,
				const std::function<void (std::vector<unsigned char>&, const std::chrono::system_clock::time_point&)>& provide_block_in,
				const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)>& provide_transaction_in,
				const std::function<void (std::vector<unsigned char>&)> provide_headers_in = std::function<void (std::vector<unsigned char>&)>())
			: OutboundPersistentConnection(serverHostIn, serverPortIn, 10000000),
			provide_block(provide_block_in), provide_transaction(provide_transaction_in), provide_headers(provide_headers_in),
			connected(0), txnAlreadySent(2000)
	{}

protected:
	virtual std::vector<unsigned char> generate_version() =0;

	void on_disconnect();
	void net_process(const std::function<void(std::string)>& disconnect);
	void send_message(const char* command, unsigned char* headerAndData, size_t datalen);

public:
	void receive_transaction(const std::shared_ptr<std::vector<unsigned char> >& tx);
	void receive_block(std::vector<unsigned char>& block);
	void request_transaction(const std::vector<unsigned char>& txhash);
};

#endif
