#include "blocks.h"
#include "utils.h"
#include "crypto/sha2.h"
#include "flaggedarrayset.h"
#include "relayprocess.h"

#include <stdio.h>
#include <sys/time.h>
#include <algorithm>
#include <random>

void fill_txn(std::vector<unsigned char>& block, RelayNodeCompressor& compressor, float includeP) {
	std::vector<unsigned char>::const_iterator readit = block.begin();
	move_forward(readit, sizeof(struct bitcoin_msg_header), block.end());
	move_forward(readit, 80, block.end());
	uint32_t txcount = read_varint(readit, block.end());

	std::vector<std::shared_ptr<std::vector<unsigned char> > > txVectors;

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

		txVectors.push_back(std::make_shared<std::vector<unsigned char> >(txstart, readit));
	}

	std::shuffle(txVectors.begin(), txVectors.end(), std::default_random_engine());
	std::default_random_engine engine; std::uniform_real_distribution<double> distribution(0.0, 1.0);
	for (auto& v : txVectors) {
		if (distribution(engine) < includeP)
			compressor.get_relay_transaction(v);
	}
}

void run_test(std::vector<unsigned char>& data) {
	RelayNodeCompressor compressor1, compressor2, compressor3, compressor4;

	struct timeval start, hash, sane, compress1, compress2start, compress2, compress3start, compress3, compress4start, compress4;
	gettimeofday(&start, NULL);

	std::vector<unsigned char> fullhash(32);
	getblockhash(fullhash, data, sizeof(struct bitcoin_msg_header));
	gettimeofday(&hash, NULL);

	const char* saneerr = is_block_sane(fullhash, data.begin() + sizeof(struct bitcoin_msg_header), data.end());
	if (saneerr) {
		fprintf(stderr, "ERROR: %s\n", saneerr);
		exit(-1);
	}
	gettimeofday(&sane, NULL);

	auto res = compressor1.maybe_compress_block(fullhash, data);
	gettimeofday(&compress1, NULL);
	printf("Compressed from %lu to %lu\n", data.size(), res->size());

	fill_txn(data, compressor2, 1.0);
	gettimeofday(&compress2start, NULL);
	auto res2 = compressor2.maybe_compress_block(fullhash, data);
	gettimeofday(&compress2, NULL);
	printf("Compressed from %lu to %lu\n", data.size(), res2->size());

	fill_txn(data, compressor3, 0.5);
	gettimeofday(&compress3start, NULL);
	auto res3 = compressor3.maybe_compress_block(fullhash, data);
	gettimeofday(&compress3, NULL);
	printf("Compressed from %lu to %lu\n", data.size(), res3->size());

	fill_txn(data, compressor4, 0.9);
	gettimeofday(&compress4start, NULL);
	auto res4 = compressor4.maybe_compress_block(fullhash, data);
	gettimeofday(&compress4, NULL);
	printf("Compressed from %lu to %lu\n", data.size(), res4->size());

	printf("Hash: %ld ms\n", int64_t(hash.tv_sec - start.tv_sec)*1000 + (int64_t(hash.tv_usec) - start.tv_usec)/1000);
	printf("Sane: %ld ms\n", int64_t(sane.tv_sec - hash.tv_sec)*1000 + (int64_t(sane.tv_usec) - hash.tv_usec)/1000);
	printf("Compress (no tx compressed): %ld ms\n", int64_t(compress1.tv_sec - sane.tv_sec)*1000 + (int64_t(compress1.tv_usec) - sane.tv_usec)/1000);
	printf("Compress (all tx compressed): %ld ms\n", int64_t(compress2.tv_sec - compress2start.tv_sec)*1000 + (int64_t(compress2.tv_usec) - compress2start.tv_usec)/1000);
	printf("Compress (0.5 tx compressed): %ld ms\n", int64_t(compress3.tv_sec - compress3start.tv_sec)*1000 + (int64_t(compress3.tv_usec) - compress3start.tv_usec)/1000);
	printf("Compress (0.9 tx compressed): %ld ms\n", int64_t(compress4.tv_sec - compress4start.tv_sec)*1000 + (int64_t(compress4.tv_usec) - compress4start.tv_usec)/1000);
}

int main() {
	std::vector<unsigned char> data(sizeof(struct bitcoin_msg_header));

	FILE* f = fopen("block.txt", "r");
	while (true) {
		char hex[2];
		if (fread(hex, 1, 1, f) != 1)
			break;
		else if (hex[0] == '\n') {
			if (data.size())
				run_test(data);
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
}
