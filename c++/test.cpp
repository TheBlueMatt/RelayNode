#include "preinclude.h"
#include "utils.h"
#include "crypto/sha2.h"
#include "flaggedarrayset.h"
#include "relayprocess.h"

#include <stdio.h>
#include <sys/time.h>
#include <algorithm>
#include <random>
#include <string.h>
#include <unistd.h>

void do_nothing(...) {}

#ifdef BENCH
#define PRINT_TIME do_nothing
#else
#define PRINT_TIME printf
#endif

std::linear_congruential_engine<std::uint_fast32_t, 48271, 0, 2147483647> engine(42);

void fill_txv(std::vector<unsigned char>& block, std::vector<std::shared_ptr<std::vector<unsigned char> > >& txVectors, float includeP) {
	std::vector<unsigned char>::const_iterator readit = block.begin();
	move_forward(readit, sizeof(struct bitcoin_msg_header), block.end());
	move_forward(readit, 80, block.end());
	uint32_t txcount = read_varint(readit, block.end());

	std::uniform_real_distribution<double> distribution(0.0, 1.0);

	for (uint32_t i = 0; i < txcount; i++) {
		std::vector<unsigned char>::const_iterator txstart = readit;

		move_forward(readit, 4, block.end());

		uint32_t txins = read_varint(readit, block.end());
		for (uint32_t j = 0; j < txins; j++) {
			move_forward(readit, 36, block.end());
			uint32_t scriptlen = read_varint(readit, block.end());
			move_forward(readit, scriptlen + 4, block.end());
		}

		uint32_t txouts = read_varint(readit, block.end());
		for (uint32_t j = 0; j < txouts; j++) {
			move_forward(readit, 8, block.end());
			uint32_t scriptlen = read_varint(readit, block.end());
			move_forward(readit, scriptlen, block.end());
		}

		move_forward(readit, 4, block.end());

		if (distribution(engine) < includeP)
			txVectors.push_back(std::make_shared<std::vector<unsigned char> >(txstart, readit));
	}

	std::shuffle(txVectors.begin(), txVectors.end(), engine);
}

int pipefd[2];
uint32_t block_tx_count;

RelayNodeCompressor global_sender(false), global_receiver(false);
std::set<std::vector<unsigned char> > globalSeenSet;

static unsigned int compress_runs = 0, decompress_runs = 0, recompress_runs;
static std::chrono::nanoseconds total_compress_time, total_recompress_time, total_decompress_time, total_decompress_init_time, total_recompress_init_time;
static std::chrono::nanoseconds max_compress_time, max_recompress_time, max_decompress_time, max_decompress_init_time, max_recompress_init_time;
static std::chrono::nanoseconds min_compress_time = std::chrono::hours(1), min_recompress_time = std::chrono::hours(1), min_decompress_time = std::chrono::hours(1), min_decompress_init_time = std::chrono::hours(1), min_recompress_init_time = std::chrono::hours(1);

std::shared_ptr<std::vector<unsigned char> > __attribute__((noinline)) recv_block(std::shared_ptr<std::vector<unsigned char> >& data, RelayNodeCompressor& receiver, bool time) {
	size_t readpos = sizeof(struct relay_msg_header);

	auto init = std::chrono::steady_clock::now();

	RelayNodeCompressor::DecompressState state(true, block_tx_count, false);
	RelayNodeCompressor::DecompressLocks locks(&receiver);

	std::function<bool(char*, size_t)> do_read = [&](char* buf, size_t count) {
		memcpy(buf, &(*data)[readpos], count);
		readpos += count;
		assert(readpos <= data->size());
		return true;
	};
	auto start = std::chrono::steady_clock::now();
	const char* err = receiver.do_partial_decompress(locks, state, do_read);
	auto decompressed = std::chrono::steady_clock::now();
	if (time) {
		total_decompress_time += decompressed - start; decompress_runs++;
		if ((decompressed - start) > max_decompress_time) max_decompress_time = decompressed - start;
		if ((decompressed - start) < min_decompress_time) min_decompress_time = decompressed - start;

		total_decompress_init_time += start - init;
		if ((start - init) > max_decompress_init_time) max_decompress_init_time = start - init;
		if ((start - init) < min_decompress_init_time) min_decompress_init_time = start - init;
	}

	if (err) {
		printf("ERROR Decompressing block %s\n", err);
		exit(2);
	} else if (time)
		PRINT_TIME("Decompressed block in %lf ms\n", to_millis_double(decompressed - start));
	return state.block[0];
}

std::tuple<std::shared_ptr<std::vector<unsigned char> >, const char*> __attribute__((noinline)) do_compress_test(RelayNodeCompressor& sender, const std::vector<unsigned char>& fullhash, const std::vector<unsigned char>& data, uint32_t tx_count) {
	auto start = std::chrono::steady_clock::now();
	auto res = sender.maybe_compress_block(fullhash, data, true);
	auto compressed = std::chrono::steady_clock::now();
	total_compress_time += compressed - start; compress_runs++;
	if ((compressed - start) > max_compress_time) max_compress_time = compressed - start;
	if ((compressed - start) < min_compress_time) min_compress_time = compressed - start;
	if(std::get<0>(res))
		PRINT_TIME("Compressed from %lu to %lu in %lf ms with %u txn pre-relayed\n", data.size(), std::get<0>(res)->size(), to_millis_double(compressed - start), tx_count);
	return res;
}

std::shared_ptr<std::vector<unsigned char> > __attribute__((noinline)) do_recompress_test(std::vector<unsigned char>& data, RelayNodeCompressor& receiver, RelayNodeCompressor* sender[COMPRESSOR_TYPES]) {
	size_t readpos = sizeof(struct relay_msg_header);

	auto init = std::chrono::steady_clock::now();

	RelayNodeCompressor::DecompressState state(true, block_tx_count, true);
	RelayNodeCompressor::DecompressLocks locks(&receiver);

	std::function<bool(char*, size_t)> do_read = [&](char* buf, size_t count) {
		memcpy(buf, &data[readpos], count);
		readpos += count;
		assert(readpos <= data.size());
		return true;
	};
	auto start = std::chrono::steady_clock::now();
	const char* err = receiver.do_partial_recompress(locks, state, do_read, sender);
	auto recompressed = std::chrono::steady_clock::now();

	total_recompress_time += recompressed - start; recompress_runs++;
	if ((recompressed - start) > max_recompress_time) max_recompress_time = recompressed - start;
	if ((recompressed - start) < min_recompress_time) min_recompress_time = recompressed - start;

	total_recompress_init_time += start - init;
	if ((start - init) > max_recompress_init_time) max_recompress_init_time = start - init;
	if ((start - init) < min_recompress_init_time) min_recompress_init_time = start - init;

	if (err) {
		printf("ERROR Recompressing block %s\n", err);
		exit(2);
	} else
		PRINT_TIME("Recompressed block in %lf ms\n", to_millis_double(recompressed - start));
	return state.block[0];
}

void test_compress_block(std::vector<unsigned char>& data, std::vector<std::shared_ptr<std::vector<unsigned char> > > txVectors) {
	std::vector<unsigned char> fullhash(32);
	getblockhash(fullhash, data, sizeof(struct bitcoin_msg_header));

	static_assert(COMPRESSOR_TYPES == 2, "There are two compressor types used in test");
	RelayNodeCompressor *senders_recompress[COMPRESSOR_TYPES];
	senders_recompress[0] = new RelayNodeCompressor(false);
	senders_recompress[1] = new RelayNodeCompressor(true);

	RelayNodeCompressor sender(false), tester(false), tester2(false), receiver(false), receiver_recompress(false);

	for (auto v : txVectors) {
		unsigned int made = sender.get_relay_transaction(v).use_count();
#ifndef PRECISE_BENCH
		v = std::make_shared<std::vector<unsigned char> >(*v); // Copy the vector to give the deduper something to do
#endif
		if (made) {
			receiver.recv_tx(v);
			receiver_recompress.recv_tx(v);
		}
#ifndef PRECISE_BENCH
		v = std::make_shared<std::vector<unsigned char> >(*v);
#endif
		if (made != tester.get_relay_transaction(v).use_count() ||
				made != tester2.get_relay_transaction(v).use_count() ||
				made != senders_recompress[0]->get_relay_transaction(v).use_count()) {
			printf("get_relay_transaction behavior not consistent???\n");
			exit(5);
		}
		senders_recompress[1]->get_relay_transaction(v);
#ifndef PRECISE_BENCH
		v = std::make_shared<std::vector<unsigned char> >(*v);
#endif
		made = global_sender.get_relay_transaction(v).use_count();
#ifndef PRECISE_BENCH
		v = std::make_shared<std::vector<unsigned char> >(*v);
#endif
		if (made)
			global_receiver.recv_tx(v);
	}

	unsigned int i = 0;
	sender.for_each_sent_tx([&](std::shared_ptr<std::vector<unsigned char> > tx) {
		if (*tx != *txVectors[i]) {
			printf("for_each_sent_tx was not in order!\n");
			exit(6);
		}
		std::vector<unsigned char> tx_hash(32);
		std::shared_ptr<std::vector<unsigned char> > tx_data = tester.send_tx_cache.remove(0, &tx_hash[0]);
		if (!tx_data || *tx_data != *txVectors[i++]) {
			printf("for_each_sent_tx output did not match remove(0)\n");
			exit(7);
		}
	});

	auto res = do_compress_test(sender, fullhash, data, txVectors.size());

	if (std::get<1>(res)) {
		printf("Failed to compress block %s\n", std::get<1>(res));
		exit(8);
	}
	std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Let the deduper thread run...
	if (*std::get<0>(tester2.maybe_compress_block(fullhash, data, true)) != *std::get<0>(res)) {
		printf("maybe_compress_block not consistent???\n");
		exit(9);
	}

	struct relay_msg_header header;
	memcpy(&header, &(*std::get<0>(res))[0], sizeof(header));
	block_tx_count = ntohl(header.length);

	auto decompressed_block = recv_block(std::get<0>(res), receiver, true);

	if (*decompressed_block != data) {
		printf("Re-constructed block did not match!\n");
		exit(4);
	}

	auto recompressed_block = do_recompress_test(*std::get<0>(res), receiver_recompress, senders_recompress);

	if (*recompressed_block != *std::get<0>(res)) {
		printf("Re-compressed block did not match compressed block!\n");
		exit(10);
	}


	if (globalSeenSet.insert(fullhash).second) {
		res = global_sender.maybe_compress_block(fullhash, data, true);
		if (std::get<1>(res)) {
			printf("Failed to compress block globally %s\n", std::get<1>(res));
			exit(8);
		}
		decompressed_block = recv_block(std::get<0>(res), global_receiver, false);

		if (*decompressed_block != data) {
			printf("Global re-constructed block did not match!\n");
			exit(4);
		}
	}

	delete senders_recompress[0];
	delete senders_recompress[1];
}

void run_test(std::vector<unsigned char>& data) {
	std::vector<std::shared_ptr<std::vector<unsigned char> > > txVectors;
	test_compress_block(data, txVectors);

	fill_txv(data, txVectors, 1.0);
	test_compress_block(data, txVectors);

	txVectors.clear();
	fill_txv(data, txVectors, 0.5);
	test_compress_block(data, txVectors);

	txVectors.clear();
	fill_txv(data, txVectors, 0.9);
	test_compress_block(data, txVectors);
}

int main() {
	std::vector<unsigned char> data(sizeof(struct bitcoin_msg_header));
	std::vector<unsigned char> lastBlock;

	std::vector<std::shared_ptr<std::vector<unsigned char> > > allTxn;

	FILE* f = fopen("block.txt", "r");
	while (true) {
		char hex[2];
		if (fread(hex, 1, 1, f) != 1)
			break;
		else if (hex[0] == '\n') {
			if (data.size()) {
#ifdef BENCH
				for (int i = 0; i < 100; i++)
#endif
					run_test(data);
				fill_txv(data, allTxn, 0.9);
				lastBlock = data;
			}
			data = std::vector<unsigned char>(sizeof(struct bitcoin_msg_header));
		} else if (fread(hex + 1, 1, 1, f) != 1)
			break;
		else {
			if (hex[0] >= 'a')
				hex[0] -= 'a' - '9' - 1;
			if (hex[1] >= 'a')
				hex[1] -= 'a' - '9' - 1;
			data.push_back((hex[0] - '0') << 4 | (hex[1] - '0'));
		}
	}

#ifdef BENCH
	for (int i = 0; i < 100; i++)
#endif
		test_compress_block(lastBlock, allTxn);

	printf("Total time spent compressing %u blocks: %lf ms (avg %lf, min %lf, max %lf)\n", compress_runs, to_millis_double(total_compress_time), to_millis_double(total_compress_time / compress_runs), to_millis_double(min_compress_time), to_millis_double(max_compress_time));
	printf("Total time spent decompressing %u blocks: %lf ms (avg %lf, min %lf, max %lf)\n", decompress_runs, to_millis_double(total_decompress_time), to_millis_double(total_decompress_time / decompress_runs), to_millis_double(min_decompress_time), to_millis_double(max_decompress_time));
	printf("Total time spent initializing decompresstion of %u blocks: %lf ms (avg %lf, min %lf, max %lf)\n", decompress_runs, to_millis_double(total_decompress_init_time), to_millis_double(total_decompress_init_time / decompress_runs), to_millis_double(min_decompress_init_time), to_millis_double(max_decompress_init_time));
	printf("Total time spent recompressing %u blocks: %lf ms (avg %lf, min %lf, max %lf)\n", recompress_runs, to_millis_double(total_recompress_time), to_millis_double(total_recompress_time / recompress_runs), to_millis_double(min_recompress_time), to_millis_double(max_recompress_time));
	printf("Total time spent initializing recompresstion of %u blocks: %lf ms (avg %lf, min %lf, max %lf)\n", recompress_runs, to_millis_double(total_recompress_init_time), to_millis_double(total_recompress_init_time / recompress_runs), to_millis_double(min_recompress_init_time), to_millis_double(max_recompress_init_time));
	return 0;
}
