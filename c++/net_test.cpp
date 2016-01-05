#include "relayconnection.h"
#include "connection.h"

#ifdef NDEBUG
#error "Must compile with variant=test"
#endif

class ConnectionTest : public RelayConnectionProcessor {
public:
	std::set<std::vector<unsigned char> > blocks_recvd;

	ConnectionTest() { compressor = RelayNodeCompressor(false, false); }

	const char* handle_peer_version(const std::string& peer_version) {
		assert(peer_version == std::string("spammy memeater"));
		return NULL;
	}

	const char* handle_max_version(const std::string& max_version) {
		assert(0);
		return NULL;
	}

	const char* handle_sponsor(const std::string& sponsor) {
		assert(sponsor == std::string("donations to 1NRuqMJAzUGwvFigukLa3UZqcJXix1dETM"));
		return NULL;
	}

	void handle_pong(uint64_t nonce) {}

	void handle_block(RelayNodeCompressor::DecompressState& block,
			std::chrono::system_clock::time_point& read_end_time,
			std::chrono::steady_clock::time_point& read_end,
			std::chrono::steady_clock::time_point& read_start) {
		assert(block.is_finished());

		std::shared_ptr<std::vector<unsigned char> > block_data = block.get_block_data();
		assert(block_data);

		std::vector<unsigned char> hash(32);
		getblockhash(hash, *block_data, sizeof(struct bitcoin_msg_header));
		assert(hash[31] == 0 && hash[30] == 0 && hash[29] == 0 && hash[28] == 0 && hash[27] == 0 && hash[26] == 0 && hash[25] == 0);
		blocks_recvd.insert(hash);
	}

	void handle_transaction(std::shared_ptr<std::vector<unsigned char> >& tx) {}

	void disconnect(const char* reason) {
		printf("Failed read, got disconnect because %s\n", reason);
		assert(0);
	}
	void do_send_bytes(const char* buf, size_t nbyte) {
	}

	void recv_bytes(char* buf, size_t size) { RelayConnectionProcessor::recv_bytes(buf, size); }
};

void test(int size) {
	ConnectionTest tester;

	FILE* f = fopen("conn_recv.dump", "r");
	while (true) {
		char buf[size];
		size_t read = fread(buf, 1, sizeof(buf), f);
		if (read == 0) {
			assert(feof(f));
			assert(tester.blocks_recvd.size() == 6);
			fclose(f);
			return;
		}
		tester.recv_bytes(buf, read);
	}
}

int main(int argc, char **argv) {
	// We test reading various numbers of bytes at a time to tickle various partial-read bugs
	test(1);
	test(2);
	test(3);
	test(4);
	test(7);
	test(11);
	test(12);
	test(13);
	test(65536);
	return 0;
}
