#include "blocks.h"
#include "crypto/sha2.h"

#include <stdio.h>

int main() {
	std::vector<unsigned char> data;

	FILE* f = fopen("block.txt", "r");
	while (true) {
		char hex[2];
		if (fread(hex, 1, 2, f) != 2)
			break;
		else {
			if (hex[0] >= 'a')
				hex[0] -= 'a' - '9' - 1;
			if (hex[1] >= 'a')
				hex[1] -= 'a' - '9' - 1;
			data.push_back((hex[0] - '0') << 4 | (hex[1] - '0'));
			fprintf(stderr, "%02x", data[data.size() - 1]);
		}
	}

	std::vector<unsigned char> fullhash(32);
	CSHA256 hash; // Probably not BE-safe
	hash.Write(&data[0], 80).Finalize(&fullhash[0]);
	hash.Reset().Write(&fullhash[0], fullhash.size()).Finalize(&fullhash[0]);

	const char* sane = is_block_sane(fullhash, data.begin(), data.end());
	fprintf(stderr, "%s\n", sane == NULL ? "SANE" : sane);
}
