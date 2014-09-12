#ifndef _RELAY_RELAYPROCESS_H
#define _RELAY_RELAYPROCESS_H

#include <vector>
#include <tuple>
#include <thread>

#ifdef WIN32
	#include <winsock.h>
#else
	#include <arpa/inet.h>
#endif

#define RELAY_DECLARE_CLASS_VARS \
private: \
	FlaggedArraySet recv_tx_cache, send_tx_cache; \
	const uint32_t VERSION_TYPE, BLOCK_TYPE, TRANSACTION_TYPE, END_BLOCK_TYPE, MAX_VERSION_TYPE;

#define RELAY_DECLARE_CONSTRUCTOR_EXTENDS \
	recv_tx_cache(1525), send_tx_cache(1525), \
	VERSION_TYPE(htonl(0)), BLOCK_TYPE(htonl(1)), TRANSACTION_TYPE(htonl(2)), END_BLOCK_TYPE(htonl(3)), MAX_VERSION_TYPE(htonl(4))

#define RELAY_DECLARE_FUNCTIONS \
private: \
	std::shared_ptr<std::vector<unsigned char> > compressRelayBlock(const std::vector<unsigned char>& block) { \
		auto compressed_block = std::make_shared<std::vector<unsigned char> >(); \
		compressed_block->reserve(1100000); \
		struct relay_msg_header header; \
 \
		try { \
			std::vector<unsigned char>::const_iterator readit = block.begin(); \
			move_forward(readit, sizeof(struct bitcoin_msg_header), block.end()); \
			move_forward(readit, 80, block.end()); \
			uint32_t txcount = read_varint(readit, block.end()); \
 \
			header.magic = RELAY_MAGIC_BYTES; \
			header.type = BLOCK_TYPE; \
			header.length = htonl(txcount); \
			compressed_block->insert(compressed_block->end(), (unsigned char*)&header, ((unsigned char*)&header) + sizeof(header)); \
			compressed_block->insert(compressed_block->end(), block.begin() + sizeof(struct bitcoin_msg_header), block.begin() + 80 + sizeof(struct bitcoin_msg_header)); \
 \
			for (uint32_t i = 0; i < txcount; i++) { \
				std::vector<unsigned char>::const_iterator txstart = readit; \
 \
				move_forward(readit, 4, block.end()); \
 \
				uint32_t txins = read_varint(readit, block.end()); \
				for (uint32_t j = 0; j < txins; j++) { \
					move_forward(readit, 36, block.end()); \
					uint32_t scriptlen = read_varint(readit, block.end()); \
					move_forward(readit, scriptlen + 4, block.end()); \
				} \
 \
				uint32_t txouts = read_varint(readit, block.end()); \
				for (uint32_t j = 0; j < txouts; j++) { \
					move_forward(readit, 8, block.end()); \
					uint32_t scriptlen = read_varint(readit, block.end()); \
					move_forward(readit, scriptlen, block.end()); \
				} \
 \
				move_forward(readit, 4, block.end()); \
 \
				auto lookupVector = std::make_shared<std::vector<unsigned char> >(txstart, readit); \
				int index = send_tx_cache.remove(lookupVector); \
				if (index < 0) { \
					compressed_block->push_back(0xff); \
					compressed_block->push_back(0xff); \
 \
					uint32_t txlen = readit - txstart; \
					compressed_block->push_back((txlen >> 16) & 0xff); \
					compressed_block->push_back((txlen >>  8) & 0xff); \
					compressed_block->push_back((txlen      ) & 0xff); \
 \
					compressed_block->insert(compressed_block->end(), txstart, readit); \
				} else { \
					compressed_block->push_back((index >> 8) & 0xff); \
					compressed_block->push_back((index     ) & 0xff); \
				} \
			} \
		} catch(read_exception) { \
			return std::make_shared<std::vector<unsigned char> >(); \
		} \
		return compressed_block; \
	} \
 \
	std::tuple<uint32_t, std::shared_ptr<std::vector<unsigned char> >, const char*> decompressRelayBlock(int sock, uint32_t message_size) { \
		if (message_size > 100000) \
			return std::make_tuple(0, std::shared_ptr<std::vector<unsigned char> >(NULL), "got a BLOCK message with far too many transactions"); \
 \
		uint32_t wire_bytes = 4*3; \
 \
		auto block = std::make_shared<std::vector<unsigned char> > (sizeof(bitcoin_msg_header) + 80); \
		block->reserve(1000000); \
 \
		if (read_all(sock, (char*)&(*block)[sizeof(bitcoin_msg_header)], 80) != 80) \
			return std::make_tuple(0, std::shared_ptr<std::vector<unsigned char> >(NULL), "failed to read block header"); \
 \
		auto vartxcount = varint(message_size); \
		block->insert(block->end(), vartxcount.begin(), vartxcount.end()); \
 \
		for (uint32_t i = 0; i < message_size; i++) { \
			uint16_t index; \
			if (read_all(sock, (char*)&index, 2) != 2) \
				return std::make_tuple(0, std::shared_ptr<std::vector<unsigned char> >(NULL), "failed to read tx index"); \
			index = ntohs(index); \
			wire_bytes += 2; \
 \
			if (index == 0xffff) { \
				union intbyte { \
					uint32_t i; \
					char c[4]; \
				} tx_size {0}; \
 \
				if (read_all(sock, tx_size.c + 1, 3) != 3) \
					return std::make_tuple(0, std::shared_ptr<std::vector<unsigned char> >(NULL), "failed to read tx length"); \
				tx_size.i = ntohl(tx_size.i); \
 \
				if (tx_size.i > 1000000) \
					return std::make_tuple(0, std::shared_ptr<std::vector<unsigned char> >(NULL), "got unreasonably large tx "); \
 \
				block->insert(block->end(), tx_size.i, 0); \
				if (read_all(sock, (char*)&(*block)[block->size() - tx_size.i], tx_size.i) != int64_t(tx_size.i)) \
					return std::make_tuple(0, std::shared_ptr<std::vector<unsigned char> >(NULL), "failed to read transaction data"); \
				wire_bytes += 3 + tx_size.i; \
			} else { \
				std::shared_ptr<std::vector<unsigned char> > transaction_data = recv_tx_cache.remove(index); \
				if (!transaction_data->size()) \
					return std::make_tuple(0, std::shared_ptr<std::vector<unsigned char> >(NULL), "failed to find referenced transaction"); \
				block->insert(block->end(), transaction_data->begin(), transaction_data->end()); \
			} \
		} \
		return std::make_tuple(wire_bytes, block, (const char*) NULL); \
	}

#endif
