#ifndef _RELAY_RELAYPROCESS_H
#define _RELAY_RELAYPROCESS_H

#include <vector>
#include <tuple>
#include <thread>
#include <mutex>

#include "mruset.h"
#include "flaggedarrayset.h"
#include "utils.h"

#ifdef WIN32
	#include <winsock.h>
#else
	#include <arpa/inet.h>
#endif

#define RELAY_DECLARE_CLASS_VARS \
private: \
	const uint32_t VERSION_TYPE, BLOCK_TYPE, TRANSACTION_TYPE, END_BLOCK_TYPE, MAX_VERSION_TYPE;

#define RELAY_DECLARE_CONSTRUCTOR_EXTENDS \
	VERSION_TYPE(htonl(0)), BLOCK_TYPE(htonl(1)), TRANSACTION_TYPE(htonl(2)), END_BLOCK_TYPE(htonl(3)), MAX_VERSION_TYPE(htonl(4))

class RelayNodeCompressor {
	RELAY_DECLARE_CLASS_VARS

private:
	FlaggedArraySet send_tx_cache, recv_tx_cache;
	mruset<std::vector<unsigned char> > blocksAlreadySeen;
	std::mutex mutex;

public:
	RelayNodeCompressor() : RELAY_DECLARE_CONSTRUCTOR_EXTENDS, send_tx_cache(1525), recv_tx_cache(1525), blocksAlreadySeen(10) {}
	void reset();

	inline std::shared_ptr<std::vector<unsigned char> > tx_to_msg(const std::shared_ptr<std::vector<unsigned char> >& tx) {
		auto msg = std::make_shared<std::vector<unsigned char> > (sizeof(struct relay_msg_header));
		struct relay_msg_header *header = (struct relay_msg_header*)&(*msg)[0];
		header->magic = RELAY_MAGIC_BYTES;
		header->type = TRANSACTION_TYPE;
		header->length = htonl(tx->size());
		msg->insert(msg->end(), tx->begin(), tx->end());
		return msg;
	}
	std::shared_ptr<std::vector<unsigned char> > get_relay_transaction(const std::shared_ptr<std::vector<unsigned char> >& tx);

	bool maybe_recv_tx_of_size(uint32_t tx_size, bool debug_print);
	void recv_tx(std::shared_ptr<std::vector<unsigned char > > tx);

	void for_each_sent_tx(const std::function<void (std::shared_ptr<std::vector<unsigned char> >)> callback);

	std::shared_ptr<std::vector<unsigned char> > maybe_compress_block(const std::vector<unsigned char>& hash, const std::vector<unsigned char>& block);
	std::tuple<uint32_t, std::shared_ptr<std::vector<unsigned char> >, const char*, std::shared_ptr<std::vector<unsigned char> > > decompress_relay_block(int sock, uint32_t message_size);

private:
	bool check_recv_tx(uint32_t tx_size);
	std::shared_ptr<std::vector<unsigned char> > compressRelayBlock(const std::vector<unsigned char>& block);
	std::tuple<uint32_t, std::shared_ptr<std::vector<unsigned char> >, const char*> decompressRelayBlock(int sock, uint32_t message_size);
};

#endif
