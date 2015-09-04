#include "relayprocess.h"

#include "crypto/sha2.h"

#include <string.h>

std::shared_ptr<std::vector<unsigned char> > RelayNodeCompressor::get_relay_transaction(const std::shared_ptr<std::vector<unsigned char> >& tx) {
	std::lock_guard<std::mutex> lock(mutex);

	if (send_tx_cache.contains(tx) ||
			(tx->size() > MAX_RELAY_TRANSACTION_BYTES &&
				(send_tx_cache.flagCount() >= MAX_EXTRA_OVERSIZE_TRANSACTIONS || tx->size() > MAX_RELAY_OVERSIZE_TRANSACTION_BYTES)))
		return std::shared_ptr<std::vector<unsigned char> >();
	send_tx_cache.add(tx, tx->size() > MAX_RELAY_TRANSACTION_BYTES);
	return tx_to_msg(tx);
}

void RelayNodeCompressor::reset() {
	std::lock_guard<std::mutex> lock(mutex);

	recv_tx_cache.clear();
	send_tx_cache.clear();
}

bool RelayNodeCompressor::check_recv_tx(uint32_t tx_size) {
	return tx_size <= MAX_RELAY_TRANSACTION_BYTES || (recv_tx_cache.flagCount() < MAX_EXTRA_OVERSIZE_TRANSACTIONS && tx_size <= MAX_RELAY_OVERSIZE_TRANSACTION_BYTES);
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
	recv_tx_cache.add(tx, tx_size > MAX_RELAY_TRANSACTION_BYTES);
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

class MerkleTreeBuilder {
private:
	std::vector<unsigned char> hashlist;
public:
	MerkleTreeBuilder(uint32_t tx_count) : hashlist(tx_count * 32) {}
	inline unsigned char* getTxHashLoc(uint32_t tx) { return &hashlist[tx * 32]; }
	bool merkleRootMatches(const unsigned char* match) {
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
};

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
		if (block_version < 3)
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

			if (check_merkle)
				double_sha256(&(*txstart), merkleTree.getTxHashLoc(i), readit - txstart);

			int index = send_tx_cache.remove(txstart, readit);
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

void tweak_sort(std::vector<IndexPtr>& ptrs, size_t start, size_t end) {
	if (start + 1 >= end)
		return;
	size_t split = (end - start) / 2 + start;
	tweak_sort(ptrs, start, split);
	tweak_sort(ptrs, split, end);

	size_t j = 0, k = split;
	std::vector<IndexPtr> left(ptrs.begin() + start, ptrs.begin() + split);
	for (size_t i = start; i < end; i++) {
		if (j < left.size() && (k >= end || left[j].index - (k - split) <= ptrs[k].index)) {
			ptrs[i] = left[j++];
			ptrs[i].index -= (k - split);
		} else
			ptrs[i] = ptrs[k++];
	}
}

std::tuple<uint32_t, std::shared_ptr<std::vector<unsigned char> >, const char*, std::shared_ptr<std::vector<unsigned char> > > RelayNodeCompressor::decompress_relay_block(std::function<ssize_t(char*, size_t)>& read_all, uint32_t message_size, bool check_merkle) {
	std::lock_guard<std::mutex> lock(mutex);
	FASLockHint faslock(recv_tx_cache);

	if (message_size > 100000)
		return std::make_tuple(0, std::shared_ptr<std::vector<unsigned char> >(NULL), "got a BLOCK message with far too many transactions", std::shared_ptr<std::vector<unsigned char> >(NULL));

	uint32_t wire_bytes = 4*3;

	auto block = std::make_shared<std::vector<unsigned char> > (sizeof(bitcoin_msg_header) + 80);
	block->reserve(1000000 + sizeof(bitcoin_msg_header));

	if (read_all((char*)&(*block)[sizeof(bitcoin_msg_header)], 80) != 80)
		return std::make_tuple(0, std::shared_ptr<std::vector<unsigned char> >(NULL), "failed to read block header", std::shared_ptr<std::vector<unsigned char> >(NULL));

#ifndef TEST_DATA
	int32_t block_version = (((*block)[sizeof(bitcoin_msg_header) + 3] << 24) | ((*block)[sizeof(bitcoin_msg_header) + 2] << 16) | ((*block)[sizeof(bitcoin_msg_header) + 1] << 8) | (*block)[sizeof(bitcoin_msg_header)]);
	if (block_version < 3)
		return std::make_tuple(0, std::shared_ptr<std::vector<unsigned char> >(NULL), "block had version < 3", std::shared_ptr<std::vector<unsigned char> >(NULL));
#endif

	auto fullhashptr = std::make_shared<std::vector<unsigned char> > (32);
	getblockhash(*fullhashptr.get(), *block, sizeof(struct bitcoin_msg_header));
	blocksAlreadySeen.insert(*fullhashptr.get());

	if (check_merkle && ((*fullhashptr)[31] != 0 || (*fullhashptr)[30] != 0 || (*fullhashptr)[29] != 0 || (*fullhashptr)[28] != 0 || (*fullhashptr)[27] != 0 || (*fullhashptr)[26] != 0 || (*fullhashptr)[25] != 0))
		return std::make_tuple(0, std::shared_ptr<std::vector<unsigned char> >(NULL), "block hash did not meet minimum difficulty target", std::shared_ptr<std::vector<unsigned char> >(NULL));

	auto vartxcount = varint(message_size);
	block->insert(block->end(), vartxcount.begin(), vartxcount.end());

	MerkleTreeBuilder merkleTree(check_merkle ? message_size : 1);

	std::vector<IndexVector> txn_data(message_size);
	std::vector<IndexPtr> txn_ptrs;
	txn_ptrs.reserve(message_size);
	for (uint32_t i = 0; i < message_size; i++) {
		uint16_t index;
		if (read_all((char*)&index, 2) != 2)
			return std::make_tuple(0, std::shared_ptr<std::vector<unsigned char> >(NULL), "failed to read tx index", std::shared_ptr<std::vector<unsigned char> >(NULL));
		index = ntohs(index);
		wire_bytes += 2;

		txn_data[i].index = index;

		if (index == 0xffff) {
			union intbyte {
				uint32_t i;
				char c[4];
			} tx_size {0};

			if (read_all(tx_size.c + 1, 3) != 3)
				return std::make_tuple(0, std::shared_ptr<std::vector<unsigned char> >(NULL), "failed to read tx length", std::shared_ptr<std::vector<unsigned char> >(NULL));
			tx_size.i = ntohl(tx_size.i);

			if (tx_size.i > 1000000)
				return std::make_tuple(0, std::shared_ptr<std::vector<unsigned char> >(NULL), "got unreasonably large tx", std::shared_ptr<std::vector<unsigned char> >(NULL));

			txn_data[i].data.resize(tx_size.i);
			if (read_all((char*)&(txn_data[i].data[0]), tx_size.i) != int64_t(tx_size.i))
				return std::make_tuple(0, std::shared_ptr<std::vector<unsigned char> >(NULL), "failed to read transaction data", std::shared_ptr<std::vector<unsigned char> >(NULL));
			wire_bytes += 3 + tx_size.i;

			if (check_merkle)
				double_sha256(&(txn_data[i].data[0]), merkleTree.getTxHashLoc(i), tx_size.i);
		} else
			txn_ptrs.emplace_back(index, i);
	}

	tweak_sort(txn_ptrs, 0, txn_ptrs.size());
#ifndef NDEBUG
	int32_t last = -1;
#endif
	for (size_t i = 0; i < txn_ptrs.size(); i++) {
		const IndexPtr& ptr = txn_ptrs[i];
		assert(last <= int(ptr.index) && (last = ptr.index) != -1);

		if (!recv_tx_cache.remove(ptr.index, txn_data[ptr.pos].data, merkleTree.getTxHashLoc(check_merkle ? ptr.pos : 0)))
			return std::make_tuple(0, std::shared_ptr<std::vector<unsigned char> >(NULL), "failed to find referenced transaction", std::shared_ptr<std::vector<unsigned char> >(NULL));
	}

	for (uint32_t i = 0; i < message_size; i++)
		block->insert(block->end(), txn_data[i].data.begin(), txn_data[i].data.end());

	if (check_merkle && !merkleTree.merkleRootMatches(&(*block)[4 + 32 + sizeof(bitcoin_msg_header)]))
		return std::make_tuple(0, std::shared_ptr<std::vector<unsigned char> >(NULL), "merkle tree root did not match", std::shared_ptr<std::vector<unsigned char> >(NULL));

	return std::make_tuple(wire_bytes, block, (const char*) NULL, fullhashptr);
}

