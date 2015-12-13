#include "preinclude.h"

#include "p2pclient.h"
#include "utils.h"
#include "crypto/sha2.h"

#include <thread>
#include <chrono>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdio.h>

#ifdef WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
#else // WIN32
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <netinet/tcp.h>
	#include <netdb.h>
	#include <fcntl.h>
#endif // !WIN32

void P2PRelayer::send_message(const char* command, unsigned char* headerAndData, size_t datalen) {
	prepare_message(command, headerAndData, datalen);
	maybe_do_send_bytes((char*)headerAndData, sizeof(struct bitcoin_msg_header) + datalen);
}

void P2PRelayer::on_disconnect() {
	connected = 0;
	read_msg.reset();
	read_pos = 0;
}

void P2PRelayer::on_connect() {
	connected = 0;

	{
		std::vector<unsigned char> version_msg(generate_version());
		send_message("version", &version_msg[0], version_msg.size() - sizeof(struct bitcoin_msg_header));
	}
}

static ssize_t read_err(P2PRelayer* peer, const char* err_msg) {
	peer->disconnect(err_msg);
	return -1;
}

ssize_t P2PRelayer::read_msg_header(char* buf, size_t len) {
	if (read_pos == 0)
		read_start = std::chrono::system_clock::now();

	size_t read_bytes = std::min(sizeof(read_header) - read_pos, len);
	memcpy(((char*)&read_header) + read_pos, buf, read_bytes);
	read_pos += read_bytes;

	if (read_pos == sizeof(read_header)) {
		if (read_header.magic != BITCOIN_MAGIC)
			return read_err(this, "invalid magic bytes");

		read_header.length = le32toh(read_header.length);
		if (read_header.length > 5000000)
			return read_err(this, "got message too large");

		read_msg_start_offset = (!strncmp(read_header.command, "block", strlen("block"))) ? sizeof(struct bitcoin_msg_header) : 0;
		read_msg = std::make_shared<std::vector<unsigned char> >(read_msg_start_offset + read_header.length);
	}
	return read_bytes;
}

ssize_t P2PRelayer::process_msg() {
	if (!strncmp(read_header.command, "version", strlen("version"))) {
		if (connected != 0)
			return read_err(this, "got invalid version");
		connected = 1;

		if (read_header.length < sizeof(struct bitcoin_version_start))
			return read_err(this, "got short version");
		struct bitcoin_version_start their_version;
		memcpy(&their_version, &(*read_msg)[0], sizeof(their_version));

		struct bitcoin_msg_header new_header;
		send_message("verack", (unsigned char*)&new_header, 0);

		STAMPOUT();
		printf("Connected to bitcoind with version %u\n", le32toh(their_version.protocol_version));
		return 0;
	} else if (!strncmp(read_header.command, "verack", strlen("verack"))) {
		if (connected != 1)
			return read_err(this, "got invalid verack");
		STAMPOUT();
		printf("Finished connect handshake with bitcoind\n");
		connected = 2;

		if (provide_headers) {
			std::vector<unsigned char> msg(sizeof(struct bitcoin_msg_header));
			struct bitcoin_version_start sent_version;
			msg.insert(msg.end(), (unsigned char*)&sent_version.protocol_version, ((unsigned char*)&sent_version.protocol_version) + sizeof(sent_version.protocol_version));
			msg.insert(msg.end(), 1, 1);
			msg.insert(msg.end(), 64, 0);
			send_message("getheaders", &msg[0], msg.size() - sizeof(struct bitcoin_msg_header));
		}
		return 0;
	}

	if (connected != 2)
		return read_err(this, "got non-version, non-verack before version+verack");

	if (!strncmp(read_header.command, "ping", strlen("ping"))) {
		std::vector<unsigned char> resp(sizeof(struct bitcoin_msg_header) + read_header.length);
		resp.insert(resp.begin() + sizeof(struct bitcoin_msg_header), read_msg->begin(), read_msg->end());
		send_message("pong", &resp[0], read_header.length);
	} else if (!strncmp(read_header.command, "pong", strlen("pong"))) {
		if (read_msg->size() != 8)
			return read_err(this, "got pong without nonce");
		uint64_t nonce;
		memcpy(&nonce, &(*read_msg)[0], 8);
		pong_received(nonce);
	} else if (!strncmp(read_header.command, "inv", strlen("inv"))) {
		std::vector<unsigned char>::const_iterator it = read_msg->begin();
		const std::vector<unsigned char>::const_iterator end = read_msg->end();
		uint64_t inv_count = read_varint(it, end);
		if (inv_count > 50001)
			return read_err(this, "got invalid inv message");

		static const uint32_t MSG_TX = htole32(1);
		static const uint32_t MSG_BLOCK = htole32(2);

		std::vector<unsigned char> resp(sizeof(struct bitcoin_msg_header));
		{
			std::lock_guard<std::mutex> lock(seen_mutex);
			for (uint64_t i = 0; i < inv_count; i++) {
				move_forward(it, 36, end);
				uint32_t type;
				memcpy(&type, &(*(it-36)), 4);

				if (type == MSG_TX && txnAlreadySeen.insert(std::vector<unsigned char>(it-32, it)).second)
					resp.insert(resp.end(), it-36, it);
				else if (type == MSG_BLOCK && blocksAlreadySeen.insert(std::vector<unsigned char>(it-32, it)).second)
					resp.insert(resp.begin() + sizeof(struct bitcoin_msg_header), it-36, it);
				else if (type != MSG_TX && type != MSG_BLOCK)
					return read_err(this, "got unexpected inv type");
			}
		}
		assert((resp.size() - sizeof(struct bitcoin_msg_header)) % 36 == 0);
		std::vector<unsigned char> v = varint((resp.size() - sizeof(struct bitcoin_msg_header)) / 36);
		resp.insert(resp.begin() + sizeof(struct bitcoin_msg_header), v.begin(), v.end());
		send_message("getdata", &resp[0], resp.size() - sizeof(struct bitcoin_msg_header));
	} else if (!strncmp(read_header.command, "block", strlen("block"))) {
		provide_block(*read_msg, read_start);
	} else if (!strncmp(read_header.command, "tx", strlen("tx"))) {
		provide_transaction(read_msg);
	} else if (!strncmp(read_header.command, "headers", strlen("headers"))) {
		if (read_msg->size() <= 1 + 82 || !provide_headers)
			return 0; // Probably last one
		provide_headers(*read_msg);

		std::vector<unsigned char> req(sizeof(struct bitcoin_msg_header));
		struct bitcoin_version_start sent_version;
		req.insert(req.end(), (unsigned char*)&sent_version.protocol_version, ((unsigned char*)&sent_version.protocol_version) + sizeof(sent_version.protocol_version));
		req.insert(req.end(), 1, 1);

		std::vector<unsigned char> fullhash(32);
		getblockhash(fullhash, *read_msg, read_msg->size() - 81);
		req.insert(req.end(), fullhash.begin(), fullhash.end());
		req.insert(req.end(), 32, 0);

		send_message("getheaders", &req[0], req.size() - sizeof(struct bitcoin_msg_header));
	}

	return 0;
}

ssize_t P2PRelayer::read_msg_contents(char* buf, size_t len) {
	size_t read_loc = read_pos - sizeof(read_header);

	size_t read_bytes = std::min(read_header.length - read_loc, len);
	memcpy(&(*read_msg)[read_loc + read_msg_start_offset], buf, read_bytes);
	read_pos += read_bytes;
	if (read_bytes == 0 && read_header.length != 0)
		return read_bytes;

	bool check_msg_hash = check_block_msghash || strncmp(read_header.command, "block", strlen("block"));
	if (check_msg_hash) {
		if (read_loc == 0)
			double_sha256_init(read_hash);

		size_t blocks = ((read_loc + read_bytes) / 64) - (read_loc / 64);
		if (blocks > 0)
			double_sha256_step(&(*read_msg)[(read_loc / 64) * 64 + read_msg_start_offset], blocks * 64, read_hash);
	}

	if (read_bytes == read_header.length - read_loc) {
		if (check_msg_hash) {
			size_t remainder = read_header.length % 64;
			double_sha256_done(&(*read_msg)[read_msg->size() - remainder], remainder, read_header.length, read_hash);

			if (memcmp((char*)read_hash, read_header.checksum, sizeof(read_header.checksum)))
				return read_err(this, "got invalid message checksum");
		}

		if (process_msg() < 0)
			return -1;
		read_pos = 0; // Signal new message
	}

	return read_bytes;
}

void P2PRelayer::recv_bytes(char* buf, size_t len) {
	while (len) {
		ssize_t size_read;
		if (read_pos < sizeof(read_header))
			size_read = read_msg_header(buf, len);
		else {
			assert(read_pos < sizeof(read_header) + read_msg->size() - read_msg_start_offset ||
					(read_pos == sizeof(read_header) && read_msg->size() - read_msg_start_offset == 0));
			size_read = read_msg_contents(buf, len);
		}
		if (size_read < 0)
			return;
		len -= size_read;
		buf += size_read;
	}
}

void P2PRelayer::receive_transaction(const std::shared_ptr<std::vector<unsigned char> >& tx) {
	if (connected != 2)
		return;

	bool seen;
	{
		std::lock_guard<std::mutex> lock(seen_mutex);
		std::vector<unsigned char> hash(32);
		double_sha256(&(*tx)[0], &hash[0], tx->size());
		seen = !txnAlreadySeen.insert(hash).second;
	}
	if (!seen) {
		auto msg = std::vector<unsigned char>(sizeof(struct bitcoin_msg_header));
		msg.insert(msg.end(), tx->begin(), tx->end());
		send_message("tx", &msg[0], tx->size());
	}
}

void P2PRelayer::receive_block(std::vector<unsigned char>& block) {
	if (connected != 2)
		return;
	bool seen;
	{
		std::lock_guard<std::mutex> lock(seen_mutex);
		std::vector<unsigned char> hash(32);
		getblockhash(hash, block, sizeof(bitcoin_msg_header));
		seen = !blocksAlreadySeen.insert(hash).second;
	}
	if (!seen)
		send_message("block", &block[0], block.size() - sizeof(bitcoin_msg_header));
}

void P2PRelayer::request_transaction(const std::vector<unsigned char>& tx_hash) {
	if (connected != 2)
		return;
	assert(tx_hash.size() == 32);
	std::vector<unsigned char> msg(sizeof(struct bitcoin_msg_header) + 5);
	msg[sizeof(struct bitcoin_msg_header)] = 1;
	msg[sizeof(struct bitcoin_msg_header) + 1] = 1;
	msg.insert(msg.end(), tx_hash.begin(), tx_hash.end());
	send_message("getdata", &msg[0], msg.size() - sizeof(struct bitcoin_msg_header));
}

void P2PRelayer::send_ping(uint64_t nonce) {
	std::vector<unsigned char> msg(sizeof(struct bitcoin_msg_header) + 8);
	memcpy(&msg[sizeof(struct bitcoin_msg_header)], &nonce, 8);
	send_message("ping", &msg[0], 8);
}

bool P2PRelayer::is_connected() const {
	return connected == 2;
}
