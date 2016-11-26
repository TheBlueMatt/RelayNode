#include "preinclude.h"

#include "p2ppipe.h"
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

void P2PPipe::send_message(const char* command, unsigned char* headerAndData, size_t datalen) {
	prepare_message(command, headerAndData, datalen);
	maybe_do_send_bytes((char*)headerAndData, sizeof(struct bitcoin_msg_header) + datalen);
}

static std::string statefulMessages[] = {"sendheaders", "feefilter" /*, "sendcmpct" - but gets its own processing */};

void P2PPipe::send_hashed_message(const unsigned char* headerAndData, size_t totallen) {
	if (!strncmp(((struct bitcoin_msg_header*)headerAndData)->command, "version", strlen("version"))) {
		std::vector<unsigned char> message(headerAndData, headerAndData + totallen);
		bool insert = !statefulMessagesSent.count("version");
		if (!insert) {
			const unsigned char* oldMessage = statefulMessagesSent["version"].data();

			uint32_t oldMsgLength, newMsgLength;
			memcpy(&oldMsgLength, &((struct bitcoin_msg_header*)oldMessage   )->length, sizeof(oldMsgLength));
			memcpy(&newMsgLength, &((struct bitcoin_msg_header*)headerAndData)->length, sizeof(newMsgLength));
			insert = oldMsgLength != newMsgLength;

			if (!insert && le32toh(newMsgLength) >= sizeof(struct bitcoin_version_start)) {
				struct bitcoin_version_start oldVersion, newVersion;
				memcpy(&oldVersion, oldMessage    + sizeof(struct bitcoin_msg_header), sizeof(oldVersion));
				memcpy(&newVersion, headerAndData + sizeof(struct bitcoin_msg_header), sizeof(newVersion));

				insert = oldVersion.protocol_version != newVersion.protocol_version ||
						oldVersion.services != newVersion.services ||
						memcmp(oldVersion.addr_recv, newVersion.addr_recv, sizeof(oldVersion.addr_recv) - 2) ||
						memcmp(oldVersion.addr_from, newVersion.addr_from, sizeof(oldVersion.addr_from) - 2) ||
						oldVersion.user_agent_length != newVersion.user_agent_length;
			}
		}

		if (insert) {
			statefulMessagesSent["version"] = std::move(message);
			disconnect("new outbound version");
		}
		return;
	}

	if (is_connected())
		maybe_do_send_bytes((char*)headerAndData, totallen);
	assert(totallen >= sizeof(struct bitcoin_msg_header));

	for (size_t i = 0; i < sizeof(statefulMessages) / sizeof(std::string); i++)
		if (!strncmp(((struct bitcoin_msg_header*)headerAndData)->command, statefulMessages[i].c_str(), statefulMessages[i].length()))
			statefulMessagesSent[statefulMessages[i]] = std::vector<unsigned char>(headerAndData, headerAndData + totallen);
	if (!strncmp(((struct bitcoin_msg_header*)headerAndData)->command, "sendcmpct", strlen("sendcmpct")) &&
			totallen >= sizeof(struct bitcoin_msg_header) + 9) {
		uint64_t cmpctVersion;
		memcpy(&cmpctVersion, headerAndData + sizeof(struct bitcoin_msg_header) + 1, sizeof(cmpctVersion));
		cmpctVersion = le64toh(cmpctVersion);
		statefulMessagesSent[std::string("sendcmpct") + std::to_string(cmpctVersion)] = std::vector<unsigned char>(headerAndData, headerAndData + totallen);
	}
}

void P2PPipe::on_disconnect() {
	connected = 0;
	read_msg.reset();
	read_pos = 0;
}

void P2PPipe::on_connect() {
	connected = 0;

	if (statefulMessagesSent.count("version")) {
		//Rehash the message because send_hashed_message has special processing for version messages
		send_message("version", statefulMessagesSent["version"].data(), statefulMessagesSent["version"].size() - sizeof(struct bitcoin_msg_header));
	} else {
		std::vector<unsigned char> version_msg(generate_version());
		send_message("version", &version_msg[0], version_msg.size() - sizeof(struct bitcoin_msg_header));
	}
}

static ssize_t read_err(P2PPipe* peer, const char* err_msg) {
	peer->disconnect(err_msg);
	return -1;
}

ssize_t P2PPipe::read_msg_header(char* buf, size_t len) {
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

		read_msg = std::make_shared<std::vector<unsigned char> >(sizeof(struct bitcoin_msg_header) + read_header.length);
		memcpy(read_msg->data(), &read_header, sizeof(read_header));
	}
	return read_bytes;
}

ssize_t P2PPipe::process_msg() {
	if (!strncmp(read_header.command, "version", strlen("version"))) {
		if (connected != 0)
			return read_err(this, "got invalid version");
		connected = 1;

		if (read_header.length < sizeof(struct bitcoin_version_start))
			return read_err(this, "got short version");
		struct bitcoin_version_start their_version;
		memcpy(&their_version, &(*read_msg)[sizeof(read_header)], sizeof(their_version));

		struct bitcoin_msg_header new_header;
		send_message("verack", (unsigned char*)&new_header, 0);

		STAMPOUT();
		printf("Connected to bitcoind with version %u\n", le32toh(their_version.protocol_version));

		provide_msg(*read_msg);

		return 0;
	} else if (!strncmp(read_header.command, "verack", strlen("verack"))) {
		if (connected != 1)
			return read_err(this, "got invalid verack");
		STAMPOUT();
		printf("Finished connect handshake with bitcoind\n");
		connected = 2;

		for (auto& p : statefulMessagesSent)
			if (p.first != "version")
				send_message(p.first.c_str(), p.second.data(), p.second.size() - sizeof(struct bitcoin_msg_header));

		return 0;
	}

	if (connected != 2)
		return read_err(this, "got non-version, non-verack before version+verack");

	if (!strncmp(read_header.command, "ping", strlen("ping"))) {
		std::vector<unsigned char> resp(sizeof(struct bitcoin_msg_header) + read_header.length);
		resp.insert(resp.begin() + sizeof(struct bitcoin_msg_header), read_msg->begin() + sizeof(read_header), read_msg->end());
		send_message("pong", &resp[0], read_header.length);
	} else if (!strncmp(read_header.command, "pong", strlen("pong"))) {
		if (read_msg->size() != 8 + sizeof(read_header))
			return read_err(this, "got pong without nonce");
		uint64_t nonce;
		memcpy(&nonce, &(*read_msg)[sizeof(read_header)], 8);
		pong_received(nonce);
	} else
		provide_msg(*read_msg);

	return 0;
}

ssize_t P2PPipe::read_msg_contents(char* buf, size_t len) {
	size_t read_loc = read_pos - sizeof(read_header);

	size_t read_bytes = std::min(read_header.length - read_loc, len);
	memcpy(&(*read_msg)[read_loc + sizeof(read_header)], buf, read_bytes);
	read_pos += read_bytes;
	if (read_bytes == 0 && read_header.length != 0)
		return read_bytes;

	bool check_msg_hash = check_block_msghash || strncmp(read_header.command, "block", strlen("block")) ||
			strncmp(read_header.command, "blocktxn", strlen("blocktxn")) || strncmp(read_header.command, "cmpctblock", strlen("cmpctblock"));
	if (check_msg_hash) {
		if (read_loc == 0)
			double_sha256_init(read_hash);

		size_t blocks = ((read_loc + read_bytes) / 64) - (read_loc / 64);
		if (blocks > 0)
			double_sha256_step(&(*read_msg)[(read_loc / 64) * 64 + sizeof(read_header)], blocks * 64, read_hash);
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

void P2PPipe::recv_bytes(char* buf, size_t len) {
	while (len) {
		ssize_t size_read;
		if (read_pos < sizeof(read_header))
			size_read = read_msg_header(buf, len);
		else {
			assert(read_pos < read_msg->size() ||
					(read_pos == sizeof(read_header) && read_msg->size() - sizeof(read_header) == 0));
			size_read = read_msg_contents(buf, len);
		}
		if (size_read < 0)
			return;
		len -= size_read;
		buf += size_read;
	}
}

void P2PPipe::send_ping(uint64_t nonce) {
	std::vector<unsigned char> msg(sizeof(struct bitcoin_msg_header) + 8);
	memcpy(&msg[sizeof(struct bitcoin_msg_header)], &nonce, 8);
	send_message("ping", &msg[0], 8);
}

bool P2PPipe::is_connected() const {
	return connected == 2;
}
