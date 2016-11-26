#ifndef _RELAY_P2PCLIENT_H
#define _RELAY_P2PCLIENT_H

#include <vector>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <chrono>
#include <mutex>

#include "utils.h"
#include "mruset.h"
#include "connection.h"


class P2PPipe : public KeepaliveOutboundPersistentConnection {
private:
	const std::function<void (std::vector<unsigned char>&)> provide_msg;

	std::atomic<uint8_t> connected;

	const bool check_block_msghash;

	struct bitcoin_msg_header read_header;
	std::shared_ptr<std::vector<unsigned char> > read_msg;
	uint32_t read_hash[8];
	std::chrono::system_clock::time_point read_start;
	size_t read_pos;

	std::map<std::string, std::vector<unsigned char> > statefulMessagesSent;

public:
	P2PPipe(const char* serverHostIn, uint16_t serverPortIn, uint64_t ping_time_nonce,
				const std::function<void (std::vector<unsigned char>&)>& provide_msg_in,
				bool check_block_msghash_in=false, uint32_t max_outbound_buffer_size=10000000)
			: KeepaliveOutboundPersistentConnection(serverHostIn, serverPortIn, ping_time_nonce, max_outbound_buffer_size),
			provide_msg(provide_msg_in), connected(0), check_block_msghash(check_block_msghash_in), read_pos(0)
	{}

private:
	void on_disconnect();
	void net_process(const std::function<void(std::string)>& disconnect);

protected:
	virtual std::vector<unsigned char> generate_version() =0;
	void send_message(const char* command, unsigned char* headerAndData, size_t datalen);
	void send_ping(uint64_t nonce);

public:
	bool is_connected() const;
	void send_hashed_message(const unsigned char* headerAndData, size_t totallen);
};

#endif
