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
std::shared_ptr<std::vector<unsigned char> > decompressed_block;
RelayNodeCompressor receiver(false);

void recv_block() {
	struct timeval start, decompressed;
	gettimeofday(&start, NULL);
	auto res = receiver.decompress_relay_block(pipefd[0], block_tx_count);
	gettimeofday(&decompressed, NULL);

	if (std::get<2>(res)) {
		printf("ERROR Decompressing block %s\n", std::get<2>(res));
		exit(2);
	} else
		PRINT_TIME("Decompressed block in %lu ms\n", int64_t(decompressed.tv_sec - start.tv_sec)*1000 + (int64_t(decompressed.tv_usec) - start.tv_usec)/1000);
	decompressed_block = std::get<1>(res);
}

void test_compress_block(std::vector<unsigned char>& data, std::vector<std::shared_ptr<std::vector<unsigned char> > > txVectors) {
	std::vector<unsigned char> fullhash(32);
	getblockhash(fullhash, data, sizeof(struct bitcoin_msg_header));

	RelayNodeCompressor sender(false), tester(false);
	receiver.reset();

	for (auto& v : txVectors) {
		unsigned int made = sender.get_relay_transaction(v).use_count();
		if (made)
			receiver.recv_tx(v);
		if (made != tester.get_relay_transaction(v).use_count()) {
			printf("get_relay_transaction behavior not consistent???\n");
			exit(5);
		}
	}

	unsigned int i = 0;
	unsigned int oversize_txn = 0;
	sender.for_each_sent_tx([&](std::shared_ptr<std::vector<unsigned char> > tx) {
		ssize_t index = std::max((ssize_t)0, (ssize_t)txVectors.size() - 5025) + i++;
		if (txVectors[index]->size() > MAX_RELAY_OVERSIZE_TRANSACTION_BYTES || (txVectors[index]->size() > MAX_RELAY_TRANSACTION_BYTES && oversize_txn++ >= MAX_EXTRA_OVERSIZE_TRANSACTIONS))
			index = std::max((ssize_t)0, (ssize_t)txVectors.size() - 5025) + i++;
		if (tx != txVectors[index]) {
			printf("for_each_sent_tx was not in order!\n");
			exit(6);
		}
		if (tester.send_tx_cache.remove(0) != txVectors[index]) {
			printf("for_each_sent_tx output did not match remove(0)\n");
			exit(7);
		}
	});

	struct timeval start, compressed;
	gettimeofday(&start, NULL);
	auto res = sender.maybe_compress_block(fullhash, data, true);
	gettimeofday(&compressed, NULL);
	if (std::get<1>(res)) {
		printf("Failed to compress block %s\n", std::get<1>(res));
		exit(8);
	}
	PRINT_TIME("Compressed from %lu to %lu in %ld ms with %lu txn pre-relayed\n", data.size(), std::get<0>(res)->size(), int64_t(compressed.tv_sec - start.tv_sec)*1000 + (int64_t(compressed.tv_usec) - start.tv_usec)/1000, txVectors.size());

	struct relay_msg_header header;
	memcpy(&header, &(*std::get<0>(res))[0], sizeof(header));
	block_tx_count = ntohl(header.length);

	if (pipe(pipefd)) {
		printf("Failed to create pipe?\n");
		exit(3);
	}

	std::thread recv(recv_block);
	write(pipefd[1], &(*std::get<0>(res))[sizeof(header)], std::get<0>(res)->size() - sizeof(header));
	recv.join();

	if (*decompressed_block != data) {
		printf("Re-constructed block did not match!\n");
		exit(4);
	}

	close(pipefd[0]);
	close(pipefd[1]);
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
				for (int i = 0; i < 300; i++)
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
	for (int i = 0; i < 300; i++)
#endif
		test_compress_block(lastBlock, allTxn);
	return 0;
}
