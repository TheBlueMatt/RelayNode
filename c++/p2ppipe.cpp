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
			disconnect_from_outside("new outbound version");
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

void P2PPipe::net_process(const std::function<void(std::string)>& disconnect) {
	connected = 0;

	if (statefulMessagesSent.count("version")) {
		//Rehash the message because send_hashed_message has special processing for version messages
		send_message("version", statefulMessagesSent["version"].data(), statefulMessagesSent["version"].size() - sizeof(struct bitcoin_msg_header));
	} else {
		std::vector<unsigned char> version_msg(generate_version());
		send_message("version", &version_msg[0], version_msg.size() - sizeof(struct bitcoin_msg_header));
	}

	while (true) {
		struct bitcoin_msg_header header;
		if (read_all((char*)&header, sizeof(header)) != sizeof(header))
			return disconnect("failed to read message header");

		if (header.magic != BITCOIN_MAGIC)
			return disconnect("invalid magic bytes");

		header.length = le32toh(header.length);
		if (header.length > 5000000)
			return disconnect("got message too large");

		auto msg = std::make_shared<std::vector<unsigned char> > (sizeof(header) + uint32_t(header.length));
		memcpy(msg->data(), &header, sizeof(header));

		bool check_msg_hash = check_block_msghash || (strncmp(header.command, "block", strlen("block")) &&
			strncmp(header.command, "blocktxn", strlen("blocktxn")) && strncmp(header.command, "cmpctblock", strlen("cmpctblock")));
		if (check_msg_hash) {
			uint32_t hash[8];
			double_sha256_init(hash);

			uint32_t steps = header.length / 64;
			for (uint32_t i = 0; i < steps; i++) {
				unsigned char* writepos = &((*msg)[sizeof(header) + i*64]);
				if (read_all((char*)writepos, 64) != 64)
					return disconnect("failed to read message");
				double_sha256_step(writepos, 64, hash);
			}

			unsigned char* writepos = &((*msg)[sizeof(header) + steps*64]);
			if (read_all((char*)writepos, header.length - steps*64) != ssize_t(header.length - steps*64))
				return disconnect("failed to read message");
			double_sha256_done(writepos, header.length - steps*64, header.length, hash);

			if (memcmp((char*)hash, header.checksum, sizeof(header.checksum)))
				return disconnect("got invalid message checksum");
		} else
			if (read_all((char*)&(*msg)[sizeof(header)], header.length) != ssize_t(header.length))
				return disconnect("failed to read message");

		if (!strncmp(header.command, "version", strlen("version"))) {
			if (connected != 0)
				return disconnect("got invalid version");
			connected = 1;

			if (header.length < sizeof(struct bitcoin_version_start))
				return disconnect("got short version");

			struct bitcoin_version_start their_version;
			memcpy(&their_version, &(*msg)[sizeof(header)], sizeof(their_version));

			struct bitcoin_msg_header new_header;
			send_message("verack", (unsigned char*)&new_header, 0);

			STAMPOUT();
			printf("Connected to bitcoind with version %u\n", le32toh(their_version.protocol_version));

			provide_msg(*msg);

			continue;
		} else if (!strncmp(header.command, "verack", strlen("verack"))) {
			if (connected != 1)
				return disconnect("got invalid verack");
			STAMPOUT();
			printf("Finished connect handshake with bitcoind\n");
			connected = 2;

			for (auto& p : statefulMessagesSent)
				if (p.first != "version") {
					std::string cmpct("sendcmpct");
					if (!p.first.compare(0, cmpct.length(), cmpct))
						send_message("sendcmpct", p.second.data(), p.second.size() - sizeof(struct bitcoin_msg_header));
					else
						send_message(p.first.c_str(), p.second.data(), p.second.size() - sizeof(struct bitcoin_msg_header));
				}

			continue;
		}

		if (connected != 2)
			return disconnect("got non-version, non-verack before version+verack");

		if (!strncmp(header.command, "ping", strlen("ping"))) {
			std::vector<unsigned char> resp(sizeof(struct bitcoin_msg_header) + header.length);
			resp.insert(resp.begin() + sizeof(struct bitcoin_msg_header), msg->begin() + sizeof(header), msg->end());
			send_message("pong", &resp[0], header.length);
		} else if (!strncmp(header.command, "pong", strlen("pong"))) {
			if (msg->size() != 8 + sizeof(header))
				return disconnect("got pong without nonce");
			uint64_t nonce;
			memcpy(&nonce, &(*msg)[sizeof(read_header)], 8);
			pong_received(nonce);
		} else
			provide_msg(*msg);
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
