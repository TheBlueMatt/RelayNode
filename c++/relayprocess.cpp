#include "preinclude.h"

#include "relayprocess.h"

#include "crypto/sha2.h"

#include <string.h>

std::shared_ptr<std::vector<unsigned char> > RelayNodeCompressor::get_relay_transaction(const std::shared_ptr<std::vector<unsigned char> >& tx) {
	std::lock_guard<std::mutex> lock(mutex);

	if (send_tx_cache.contains(tx))
		return std::shared_ptr<std::vector<unsigned char> >();

	if (!useOldFlags) {
		if (tx->size() > MAX_RELAY_TRANSACTION_BYTES)
			return std::shared_ptr<std::vector<unsigned char> >();
		send_tx_cache.add(tx, tx->size());

	}

	if (useOldFlags) {
		if (tx->size() > OLD_MAX_RELAY_TRANSACTION_BYTES &&
				(send_tx_cache.flagCount() >= OLD_MAX_EXTRA_OVERSIZE_TRANSACTIONS || tx->size() > OLD_MAX_RELAY_OVERSIZE_TRANSACTION_BYTES))
			return std::shared_ptr<std::vector<unsigned char> >();
		send_tx_cache.add(tx, tx->size() > OLD_MAX_RELAY_TRANSACTION_BYTES);
	}

	return tx_to_msg(tx);
}

void RelayNodeCompressor::reset() {
	std::lock_guard<std::mutex> lock(mutex);

	recv_tx_cache.clear();
	send_tx_cache.clear();
}

bool RelayNodeCompressor::check_recv_tx(uint32_t tx_size) {
	return (!useOldFlags && tx_size <= MAX_RELAY_TRANSACTION_BYTES) ||
			(useOldFlags && (tx_size <= OLD_MAX_RELAY_TRANSACTION_BYTES || (recv_tx_cache.flagCount() < OLD_MAX_EXTRA_OVERSIZE_TRANSACTIONS && tx_size <= OLD_MAX_RELAY_OVERSIZE_TRANSACTION_BYTES)));
}

bool RelayNodeCompressor::maybe_recv_tx_of_size(uint32_t tx_size, bool debug_print) {
	std::lock_guard<std::mutex> lock(mutex);

	if (!check_recv_tx(tx_size)) {
		if (debug_print)
			printf("Freely relayed tx of size %u, with %lu oversize txn already present\n", tx_size, (long unsigned)recv_tx_cache.flagCount());
		return false;
	}
	return true;
}

void RelayNodeCompressor::recv_tx(std::shared_ptr<std::vector<unsigned char > > tx) {
	std::lock_guard<std::mutex> lock(mutex);

	uint32_t tx_size = tx.get()->size();
	assert(check_recv_tx(tx_size));
	recv_tx_cache.add(tx, useOldFlags ? tx_size > OLD_MAX_RELAY_TRANSACTION_BYTES : tx_size);
}

void RelayNodeCompressor::for_each_sent_tx(const std::function<void (const std::shared_ptr<std::vector<unsigned char> >&)> callback) {
	std::lock_guard<std::mutex> lock(mutex);
	send_tx_cache.for_all_txn(callback);
}

bool RelayNodeCompressor::block_sent(std::vector<unsigned char>& hash) {
	std::lock_guard<std::mutex> lock(mutex);
	return blocksAlreadySeen.insert(hash).second;
}

uint32_t RelayNodeCompressor::blocks_sent() {
	std::lock_guard<std::mutex> lock(mutex);
	return blocksAlreadySeen.size();
}

bool RelayNodeCompressor::was_tx_sent(const unsigned char* txhash) {
	std::lock_guard<std::mutex> lock(mutex);
	return send_tx_cache.contains(txhash);
}

bool RelayNodeCompressor::MerkleTreeBuilder::merkleRootMatches(const unsigned char* match) {
	uint32_t txcount = hashlist.size() / 32;
	uint32_t stepCount = 1, lastMax = txcount - 1;
	for (uint32_t rowSize = txcount; rowSize > 1; rowSize = (rowSize + 1) / 2) {
		if (!memcmp(&hashlist[32 * (lastMax - stepCount)], &hashlist[32 * lastMax], 32))
			return false;

		for (uint32_t i = 0; i < rowSize; i += 2) {
			assert(i*stepCount < txcount && lastMax < txcount);
			double_sha256_two_32_inputs(&hashlist[32 * i*stepCount], &hashlist[32 * std::min((i + 1)*stepCount, lastMax)], &hashlist[32 * i*stepCount]);
		}
		lastMax = ((rowSize - 1) & 0xfffffffe) * stepCount;
		stepCount *= 2;
	}
	return !memcmp(match, &hashlist[0], 32);
}

std::tuple<std::shared_ptr<std::vector<unsigned char> >, const char*> RelayNodeCompressor::maybe_compress_block(const std::vector<unsigned char>& hash, const std::vector<unsigned char>& block, bool check_merkle) {
	std::lock_guard<std::mutex> lock(mutex);
	FASLockHint faslock(send_tx_cache);

	if (check_merkle && (hash[31] != 0 || hash[30] != 0 || hash[29] != 0 || hash[28] != 0 || hash[27] != 0 || hash[26] != 0 || hash[25] != 0))
		return std::make_tuple(std::shared_ptr<std::vector<unsigned char> >(), "BAD_WORK");

	if (blocksAlreadySeen.count(hash))
		return std::make_tuple(std::shared_ptr<std::vector<unsigned char> >(), "SEEN");

	auto compressed_block = std::make_shared<std::vector<unsigned char> >();
	compressed_block->reserve(1100000);
	struct relay_msg_header header;

	try {
		std::vector<unsigned char>::const_iterator readit = block.begin();
		move_forward(readit, sizeof(struct bitcoin_msg_header), block.end());
		move_forward(readit, 4, block.end());
#ifndef TEST_DATA
		int32_t block_version = ((*(readit-1) << 24) | (*(readit-2) << 16) | (*(readit-3) << 8) | *(readit-4));
		if (block_version < 4)
			return std::make_tuple(std::make_shared<std::vector<unsigned char> >(), "SMALL_VERSION");
#endif

		move_forward(readit, 32, block.end());
		auto merkle_hash_it = readit;
		move_forward(readit, 80 - (4 + 32), block.end());

		uint64_t txcount = read_varint(readit, block.end());
		if (txcount < 1 || txcount > 100000)
			return std::make_tuple(std::make_shared<std::vector<unsigned char> >(), "TXCOUNT_RANGE");

		header.magic = RELAY_MAGIC_BYTES;
		header.type = BLOCK_TYPE;
		header.length = htonl(txcount);
		compressed_block->insert(compressed_block->end(), (unsigned char*)&header, ((unsigned char*)&header) + sizeof(header));
		compressed_block->insert(compressed_block->end(), block.begin() + sizeof(struct bitcoin_msg_header), block.begin() + 80 + sizeof(struct bitcoin_msg_header));

		MerkleTreeBuilder merkleTree(check_merkle ? txcount : 0);

		for (uint32_t i = 0; i < txcount; i++) {
			std::vector<unsigned char>::const_iterator txstart = readit;

			move_forward(readit, 4, block.end());

			uint64_t txins = read_varint(readit, block.end());
			for (uint64_t j = 0; j < txins; j++) {
				move_forward(readit, 36, block.end());
				move_forward(readit, read_varint(readit, block.end()) + 4, block.end());
			}

			uint64_t txouts = read_varint(readit, block.end());
			for (uint64_t j = 0; j < txouts; j++) {
				move_forward(readit, 8, block.end());
				move_forward(readit, read_varint(readit, block.end()), block.end());
			}

			move_forward(readit, 4, block.end());

			int index = send_tx_cache.remove(&(*txstart), &(*readit));

			__builtin_prefetch(&(*readit), 0);
			__builtin_prefetch(&(*readit) + 64, 0);
			__builtin_prefetch(&(*readit) + 128, 0);
			__builtin_prefetch(&(*readit) + 196, 0);
			__builtin_prefetch(&(*readit) + 256, 0);

			if (check_merkle)
				double_sha256(&(*txstart), merkleTree.getTxHashLoc(i), readit - txstart);

			if (index < 0) {
				compressed_block->push_back(0xff);
				compressed_block->push_back(0xff);

				uint32_t txlen = readit - txstart;
				compressed_block->push_back((txlen >> 16) & 0xff);
				compressed_block->push_back((txlen >>  8) & 0xff);
				compressed_block->push_back((txlen      ) & 0xff);

				compressed_block->insert(compressed_block->end(), txstart, readit);
			} else {
				compressed_block->push_back((index >> 8) & 0xff);
				compressed_block->push_back((index     ) & 0xff);
			}
		}

		if (check_merkle && !merkleTree.merkleRootMatches(&(*merkle_hash_it)))
			return std::make_tuple(std::make_shared<std::vector<unsigned char> >(), "INVALID_MERKLE");
	} catch(read_exception) {
		return std::make_tuple(std::make_shared<std::vector<unsigned char> >(), "INVALID_SIZE");
	}

	if (!blocksAlreadySeen.insert(hash).second)
		return std::make_tuple(std::shared_ptr<std::vector<unsigned char> >(), "MUTEX_BROKEN???");

	return std::make_tuple(compressed_block, (const char*)NULL);
}

void tweak_sort(std::vector<RelayNodeCompressor::IndexPtr>& ptrs, size_t start, size_t end) {
	if (start + 1 >= end)
		return;
	size_t split = (end - start) / 2 + start;
	tweak_sort(ptrs, start, split);
	tweak_sort(ptrs, split, end);

	size_t j = 0, k = split;
	std::vector<RelayNodeCompressor::IndexPtr> left(ptrs.begin() + start, ptrs.begin() + split);
	for (size_t i = start; i < end; i++) {
		if (j < left.size() && (k >= end || left[j].index - (k - split) <= ptrs[k].index)) {
			ptrs[i] = left[j++];
			ptrs[i].index -= (k - split);
		} else
			ptrs[i] = ptrs[k++];
	}
}

void RelayNodeCompressor::DecompressState::clear() {
	tx_count = 0;
	for (int i = 0; i < COMPRESSOR_TYPES; i++)
		block[i].reset();
	fullhashptr.reset();
	merkleTree.resize(0);
	txn_data.clear();
	txn_data.shrink_to_fit();
	txn_ptrs.clear();
	txn_ptrs.shrink_to_fit();
	txn_data_block.reset();
	state = READ_STATE_INVALID;
}

void RelayNodeCompressor::DecompressState::reset(bool check_merkle_in, uint32_t tx_count_in) {
	check_merkle = check_merkle_in;
	tx_count = tx_count_in > 100000 ? 100001 : tx_count_in;
	wire_bytes = 4*3;
	for (int i = 0; i < COMPRESSOR_TYPES; i++) {
		block[i] = std::make_shared<std::vector<unsigned char> >(sizeof(bitcoin_msg_header) + 80);
		block[i]->reserve(1000000 + sizeof(bitcoin_msg_header));
	}
	fullhashptr = std::make_shared<std::vector<unsigned char> >(32);
	merkleTree.resize(check_merkle ? tx_count : 1);
	txn_data.resize(tx_count);
	txn_data_block.reset(new unsigned char[1000000]);
	txn_data_block_use = 0;
	state = READ_STATE_START;
	txn_read = 0;
	txn_ptrs.reserve(tx_count);
}

bool RelayNodeCompressor::DecompressState::is_finished() {
	return state == READ_STATE_DONE;
}

std::tuple<uint32_t, std::shared_ptr<std::vector<unsigned char> >, const char*, std::shared_ptr<std::vector<unsigned char> > > RelayNodeCompressor::decompress_relay_block(std::function<ssize_t(char*, size_t)>& read_all, uint32_t message_size, bool check_merkle) {
	DecompressLocks locks(this);

	DecompressState state(check_merkle, message_size);
	bool read_failed = false;
	std::function<bool(char* buf, size_t len)> read_fun =
			[&] (char* buf, size_t len) {
				if (read_all(buf, len) != ssize_t(len))
					read_failed = true;
				return !read_failed;
			};
	const char* err = do_partial_decompress(locks, state, read_fun);
	if (err)
		return std::make_tuple(0, std::shared_ptr<std::vector<unsigned char> >(NULL), err, std::shared_ptr<std::vector<unsigned char> >(NULL));
	if (read_failed)
		return std::make_tuple(0, std::shared_ptr<std::vector<unsigned char> >(NULL), "failed to read compressed block data", std::shared_ptr<std::vector<unsigned char> >(NULL));
	return std::make_tuple(state.wire_bytes, state.block[0], (const char*) NULL, state.fullhashptr);
}

inline const char* RelayNodeCompressor::read_block_header(DecompressState& state, std::function<bool(char*, size_t)>& read_all) {
	if (state.tx_count > 100000)
		return "got a BLOCK message with far too many transactions";

	if (!read_all((char*)&(*state.block[0])[sizeof(bitcoin_msg_header)], 80))
		return NULL;
	state.wire_bytes += 80;

#ifndef TEST_DATA
	int32_t block_version = (((*state.block[0])[sizeof(bitcoin_msg_header) + 3] << 24) | ((*state.block[0])[sizeof(bitcoin_msg_header) + 2] << 16) | ((*state.block[0])[sizeof(bitcoin_msg_header) + 1] << 8) | (*state.block[0])[sizeof(bitcoin_msg_header)]);
	if (block_version < 4)
		return "block had version < 4";
#endif

	getblockhash(*state.fullhashptr.get(), *state.block[0], sizeof(struct bitcoin_msg_header));
	blocksAlreadySeen.insert(*state.fullhashptr.get());

	if (state.check_merkle && ((*state.fullhashptr)[31] != 0 || (*state.fullhashptr)[30] != 0 || (*state.fullhashptr)[29] != 0 || (*state.fullhashptr)[28] != 0 || (*state.fullhashptr)[27] != 0 || (*state.fullhashptr)[26] != 0 || (*state.fullhashptr)[25] != 0))
		return "block hash did not meet minimum difficulty target";

	auto vartxcount = varint(state.tx_count);
	state.block[0]->insert(state.block[0]->end(), vartxcount.begin(), vartxcount.end());

	state.state = DecompressState::READ_STATE_START_TX;
	return NULL;
}

inline const char* RelayNodeCompressor::read_tx_index(DecompressState& state, std::function<bool(char*, size_t)>& read_all) {
	uint16_t index;
	if (!read_all((char*)&index, 2))
		return NULL;
	index = ntohs(index);
	state.wire_bytes += 2;

	state.txn_data[state.txn_read].index = index;

	if (index == 0xffff)
		state.state = DecompressState::READ_STATE_TX_DATA_LEN;
	else {
		state.txn_ptrs.emplace_back(index, state.txn_read++);
		if (state.txn_read == state.tx_count)
			state.state = DecompressState::READ_STATE_TX_READ_DONE;
	}

	return NULL;
}

inline const char* RelayNodeCompressor::read_tx_data_len(DecompressState& state, std::function<bool(char*, size_t)>& read_all) {
	union intbyte {
		uint32_t i;
		char c[4];
	} tx_size {0};

	if (!read_all(tx_size.c + 1, 3))
		return NULL;
	tx_size.i = ntohl(tx_size.i);
	state.wire_bytes += 3;

	if (tx_size.i > 1000000)
		return "got unreasonably large tx";

	state.txn_data[state.txn_read].data = &state.txn_data_block[state.txn_data_block_use];
	state.txn_data[state.txn_read].size = tx_size.i;
	state.txn_data_block_use += tx_size.i;
	state.state = DecompressState::READ_STATE_TX_DATA;

	return NULL;
}

inline const char* RelayNodeCompressor::read_tx_data(DecompressState& state, std::function<bool(char*, size_t)>& read_all) {
	IndexVector& v = state.txn_data[state.txn_read];
	if (!read_all((char*)v.data, v.size))
		return NULL;
	state.wire_bytes += v.size;

	if (state.check_merkle)
		double_sha256(v.data, state.merkleTree.getTxHashLoc(state.txn_read), v.size);

	state.txn_read++;
	if (state.txn_read == state.tx_count)
		state.state = DecompressState::READ_STATE_TX_READ_DONE;
	else
		state.state = DecompressState::READ_STATE_START_TX;
	return NULL;
}

inline const char* RelayNodeCompressor::decompress_block_finalize(DecompressState& state, std::vector<std::shared_ptr<std::vector<unsigned char> > >& data_ptrs) {
	tweak_sort(state.txn_ptrs, 0, state.txn_ptrs.size());
#ifndef NDEBUG
	int32_t last = -1;
#endif
	for (size_t i = 0; i < state.txn_ptrs.size(); i++) {
		const IndexPtr& ptr = state.txn_ptrs[i];
		assert(last <= int(ptr.index) && (last = ptr.index) != -1);

		data_ptrs.emplace_back(recv_tx_cache.remove(ptr.index, state.merkleTree.getTxHashLoc(state.check_merkle ? ptr.pos : 0)));
		if (!(data_ptrs.back()))
			return "failed to find referenced transaction";
		state.txn_data[ptr.pos].data = &(*data_ptrs.back())[0];
		state.txn_data[ptr.pos].size = data_ptrs.back()->size();
	}

	if (state.check_merkle && !state.merkleTree.merkleRootMatches(&(*state.block[0])[4 + 32 + sizeof(bitcoin_msg_header)]))
		return "merkle tree root did not match";

	return NULL;
}

inline const char* RelayNodeCompressor::decompress_block_finish(DecompressState& state) {
	std::vector<std::shared_ptr<std::vector<unsigned char> > > data_ptrs;
	const char* res = decompress_block_finalize(state, data_ptrs);
	if (res) return res;

	for (uint32_t i = 0; i < state.tx_count; i++)
		state.block[0]->insert(state.block[0]->end(), state.txn_data[i].data, state.txn_data[i].data + state.txn_data[i].size);


	state.state = DecompressState::READ_STATE_DONE;
	return NULL;
}

const char* RelayNodeCompressor::do_partial_decompress(DecompressLocks& locks, DecompressState& state, std::function<bool(char*, size_t)>& read_all) {
	assert(locks.compressor == this);
	while (state.state != DecompressState::READ_STATE_DONE) {
		const char* res;
		size_t start_bytes = state.wire_bytes;
		switch (state.state) {
			case DecompressState::READ_STATE_START:
				res = read_block_header(state, read_all);
				if (res)
					return res;
				if (start_bytes == state.wire_bytes)
					return NULL;
				break;
			case DecompressState::READ_STATE_START_TX:
				res = read_tx_index(state, read_all);
				if (res)
					return res;
				if (start_bytes == state.wire_bytes)
					return NULL;
				break;
			case DecompressState::READ_STATE_TX_DATA_LEN:
				res = read_tx_data_len(state, read_all);
				if (res)
					return res;
				if (start_bytes == state.wire_bytes)
					return NULL;
				break;
			case DecompressState::READ_STATE_TX_DATA:
				res = read_tx_data(state, read_all);
				if (res)
					return res;
				if (start_bytes == state.wire_bytes)
					return NULL;
				break;
			case DecompressState::READ_STATE_TX_READ_DONE:
				res = decompress_block_finish(state);
				return res;
			case DecompressState::READ_STATE_DONE:
				return NULL;
			case DecompressState::READ_STATE_INVALID:
				assert(0);
				return "Called do_partial_decompress after state.clear() without state.reset()";
		}
	}
	return NULL;
}
