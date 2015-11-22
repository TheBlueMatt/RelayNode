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
	const uint32_t VERSION_TYPE, BLOCK_TYPE, TRANSACTION_TYPE, END_BLOCK_TYPE, MAX_VERSION_TYPE, \
					OOB_TRANSACTION_TYPE, SPONSOR_TYPE, PING_TYPE, PONG_TYPE;

#define RELAY_DECLARE_CONSTRUCTOR_EXTENDS \
	VERSION_TYPE(htonl(0)), BLOCK_TYPE(htonl(1)), TRANSACTION_TYPE(htonl(2)), END_BLOCK_TYPE(htonl(3)), \
	MAX_VERSION_TYPE(htonl(4)), OOB_TRANSACTION_TYPE(htonl(5)), SPONSOR_TYPE(htonl(6)), PING_TYPE(htonl(7)), PONG_TYPE(htonl(8))

class DecompressState;

class RelayNodeCompressor {
	RELAY_DECLARE_CLASS_VARS

private:
	bool useOldFlags;
	FlaggedArraySet send_tx_cache, recv_tx_cache;
	mruset<std::vector<unsigned char> > blocksAlreadySeen;
	std::mutex mutex;

	class MerkleTreeBuilder {
	public:
		std::vector<unsigned char> hashlist;
		MerkleTreeBuilder(uint32_t tx_count) : hashlist(tx_count * 32) {}
		MerkleTreeBuilder() {}
		void resize(uint32_t tx_count) { hashlist.resize(tx_count * 32); }
		inline unsigned char* getTxHashLoc(uint32_t tx) { return &hashlist[tx * 32]; }
		bool merkleRootMatches(const unsigned char* match);
	};

	struct IndexVector {
		uint16_t index;
		std::vector<unsigned char> data;
	};
	struct IndexPtr {
		uint16_t index;
		size_t pos;
		IndexPtr(uint16_t index_in, size_t pos_in) : index(index_in), pos(pos_in) {}
		bool operator< (const IndexPtr& o) const { return index < o.index; }
	};

public:
	class DecompressState {
		bool check_merkle;
		uint32_t tx_count;

	public:
		uint32_t wire_bytes = 4*3;
		std::shared_ptr<std::vector<unsigned char> > block;
		std::shared_ptr<std::vector<unsigned char> > fullhashptr;

	private:
		MerkleTreeBuilder merkleTree;
		std::vector<IndexVector> txn_data;
		std::vector<IndexPtr> txn_ptrs;

		enum ReadState {
			READ_STATE_INVALID, // Set after clear()
			READ_STATE_START,
			READ_STATE_START_TX,
			READ_STATE_TX_DATA_LEN,
			READ_STATE_TX_DATA,
			READ_STATE_TX_READ_DONE,
			READ_STATE_DONE,
		};
		ReadState state;
		uint32_t txn_read;

		friend class RelayNodeCompressor;

	public:
		DecompressState(bool check_merkle_in, uint32_t tx_count_in) { reset(check_merkle_in, tx_count_in); }
		void clear();
		void reset(bool check_merkle_in, uint32_t tx_count_in);
		bool is_finished();
	};

	class DecompressLocks {
	private:
		std::lock_guard<std::mutex> lock;
		FASLockHint faslock;
	public:
		const RelayNodeCompressor* compressor;
		DecompressLocks(RelayNodeCompressor* compressor_in) : lock(compressor_in->mutex), faslock(compressor_in->recv_tx_cache), compressor(compressor_in) {}
	};

	RelayNodeCompressor(bool useOldFlagsIn)
		: RELAY_DECLARE_CONSTRUCTOR_EXTENDS, useOldFlags(useOldFlagsIn),
		  send_tx_cache(useOldFlagsIn ? OLD_MAX_TXN_IN_FAS : 65000, useOldFlagsIn ? uint32_t(-1) : MAX_FAS_TOTAL_SIZE),
		  recv_tx_cache(useOldFlagsIn ? OLD_MAX_TXN_IN_FAS : 65000, useOldFlagsIn ? uint32_t(-1) : MAX_FAS_TOTAL_SIZE),
		  blocksAlreadySeen(1000000) {}
	RelayNodeCompressor& operator=(const RelayNodeCompressor& c) {
		useOldFlags = c.useOldFlags;
		send_tx_cache = c.send_tx_cache;
		recv_tx_cache = c.recv_tx_cache;
		blocksAlreadySeen = c.blocksAlreadySeen;
		return *this;
	}
	void reset();

	inline std::shared_ptr<std::vector<unsigned char> > tx_to_msg(const std::shared_ptr<std::vector<unsigned char> >& tx, bool send_oob=false, bool include_data=true) const {
		auto msg = std::make_shared<std::vector<unsigned char> > (sizeof(struct relay_msg_header));
		struct relay_msg_header *header = (struct relay_msg_header*)&(*msg)[0];
		header->magic = RELAY_MAGIC_BYTES;
		if (send_oob)
			header->type = OOB_TRANSACTION_TYPE;
		else
			header->type = TRANSACTION_TYPE;
		header->length = htonl(tx->size());
		if (include_data)
			msg->insert(msg->end(), tx->begin(), tx->end());
		return msg;
	}
	std::shared_ptr<std::vector<unsigned char> > get_relay_transaction(const std::shared_ptr<std::vector<unsigned char> >& tx);

	bool maybe_recv_tx_of_size(uint32_t tx_size, bool debug_print);
	void recv_tx(std::shared_ptr<std::vector<unsigned char > > tx);

	void for_each_sent_tx(const std::function<void (const std::shared_ptr<std::vector<unsigned char> >&)> callback);

	std::tuple<std::shared_ptr<std::vector<unsigned char> >, const char*> maybe_compress_block(const std::vector<unsigned char>& hash, const std::vector<unsigned char>& block, bool check_merkle);
	std::tuple<uint32_t, std::shared_ptr<std::vector<unsigned char> >, const char*, std::shared_ptr<std::vector<unsigned char> > > decompress_relay_block(std::function<ssize_t(char*, size_t)>& read_all, uint32_t message_size, bool check_merkle);

	const char* do_partial_decompress(DecompressLocks& locks, DecompressState& state, std::function<bool(char*, size_t)>& read_all);

	bool block_sent(std::vector<unsigned char>& hash);
	uint32_t blocks_sent();

	bool was_tx_sent(const unsigned char* txhash);

private:
	bool check_recv_tx(uint32_t tx_size);

	const char* read_block_header(DecompressState& state, std::function<bool(char*, size_t)>& read_all);
	const char* read_tx_index(DecompressState& state, std::function<bool(char*, size_t)>& read_all);
	const char* read_tx_data_len(DecompressState& state, std::function<bool(char*, size_t)>& read_all);
	const char* read_tx_data(DecompressState& state, std::function<bool(char*, size_t)>& read_all);
	const char* decompress_block_finish(DecompressState& state);

	friend void test_compress_block(std::vector<unsigned char>&, std::vector<std::shared_ptr<std::vector<unsigned char> > >);
	friend void tweak_sort(std::vector<RelayNodeCompressor::IndexPtr>& ptrs, size_t start, size_t end);
};

#endif
