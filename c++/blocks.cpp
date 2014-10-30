#include "blocks.h"

#include <set>
#include <string.h>
#include <algorithm>
#include <mutex>

#include "crypto/sha2.h"
#include "utils.h"

static std::mutex hashes_mutex;
static std::set<std::vector<unsigned char> > hashesSeen;

bool got_block_has_been_relayed(const std::vector<unsigned char>& hash) {
	std::lock_guard<std::mutex> lock(hashes_mutex);
	if (!hashesSeen.insert(hash).second)
		return true;
	return false;
}

static inline void doubleDoubleHash(std::vector<unsigned char>& first, std::vector<unsigned char>& second) {
	assert(first.size() == 32);
	CSHA256 hash; // Probably not BE-safe
	hash.Write(&first[0], first.size()).Write(&second[0], second.size()).Finalize(&first[0]);
	hash.Reset().Write(&first[0], 32).Finalize(&first[0]);
}

const char* is_block_sane(const std::vector<unsigned char>& hash, std::vector<unsigned char>::const_iterator readit, std::vector<unsigned char>::const_iterator end) {
	try {
		if (hash[31] != 0 || hash[30] != 0 || hash[29] != 0 || hash[28] != 0 || hash[27] != 0 || hash[26] != 0 || hash[25] != 0)
			return "BAD_WORK";

		move_forward(readit, 4 + 32, end);
		auto merkle_hash_it = readit;
		move_forward(readit, 80 - (4 + 32), end);
		uint64_t txcount = read_varint(readit, end);
		if (txcount < 1 || txcount > 100000)
			return "TXCOUNT_RANGE";

		std::vector<std::vector<unsigned char> > hashlist;
		hashlist.reserve(txcount);

		for (uint32_t i = 0; i < txcount; i++) {
			std::vector<unsigned char>::const_iterator txstart = readit;

			move_forward(readit, 4, end);

			uint32_t txins = read_varint(readit, end);
			for (uint32_t j = 0; j < txins; j++) {
				move_forward(readit, 36, end);
				uint32_t scriptlen = read_varint(readit, end);
				move_forward(readit, scriptlen + 4, end);
			}

			uint32_t txouts = read_varint(readit, end);
			for (uint32_t j = 0; j < txouts; j++) {
				move_forward(readit, 8, end);
				uint32_t scriptlen = read_varint(readit, end);
				move_forward(readit, scriptlen, end);
			}

			move_forward(readit, 4, end);

			hashlist.emplace_back(32);
			CSHA256 hash; // Probably not BE-safe
			hash.Write(&(*txstart), readit - txstart).Finalize(&hashlist.back()[0]);
			hash.Reset().Write(&hashlist.back()[0], 32).Finalize(&hashlist.back()[0]);
		}

		uint32_t stepCount = 1, lastMax = hashlist.size() - 1;
		for (uint32_t rowSize = hashlist.size(); rowSize > 1; rowSize = (rowSize + 1) / 2) {
			if (hashlist[lastMax - stepCount] == hashlist[lastMax])
				return "DUPLICATE_TX";

			for (uint32_t i = 0; i < rowSize; i += 2) {
				assert(i*stepCount < hashlist.size() && lastMax < hashlist.size());
				doubleDoubleHash(hashlist[i*stepCount], hashlist[std::min((i + 1)*stepCount, lastMax)]);
			}
			lastMax = ((rowSize - 1) & 0xfffffffe) * stepCount;
			stepCount *= 2;
		}

		if (memcmp(&(*merkle_hash_it), &hashlist[0][0], 32))
			return "INVALID_MERKLE";
	} catch (read_exception) {
		return "INVALID_SIZE";
	}

	// This must come after all merkle-related errors
	std::lock_guard<std::mutex> lock(hashes_mutex);
	if (!hashesSeen.insert(hash).second)
		return "SEEN";
	return NULL;
}

bool recv_headers_msg_from_trusted(const std::vector<unsigned char> headers) {
	bool wasUseful = false;
	try {
		std::lock_guard<std::mutex> lock(hashes_mutex);
		auto it = headers.begin();
		uint64_t count = read_varint(it, headers.end());

		for (uint64_t i = 0; i < count; i++) {
			move_forward(it, 81, headers.end());

			if (*(it - 1) != 0)
				return wasUseful;

			std::vector<unsigned char> fullhash(32);
			CSHA256 hash; // Probably not BE-safe
			hash.Write(&(*(it - 81)), 80).Finalize(&fullhash[0]);
			hash.Reset().Write(&fullhash[0], 32).Finalize(&fullhash[0]);
			wasUseful |= hashesSeen.insert(fullhash).second;
		}

		printf("Added headers from trusted peers, seen %lu blocks\n", hashesSeen.size());
	} catch (read_exception) { }
	return wasUseful;
}
