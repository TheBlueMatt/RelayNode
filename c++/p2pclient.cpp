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
}

void P2PRelayer::net_process(const std::function<void(std::string)>& disconnect) {
	connected = 0;

	{
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

		uint32_t prependedHeaderSize = (!strncmp(header.command, "block", strlen("block"))) ? sizeof(struct bitcoin_msg_header) : 0;

		std::chrono::system_clock::time_point read_start(std::chrono::system_clock::now());

		auto msg = std::make_shared<std::vector<unsigned char> > (prependedHeaderSize + uint32_t(header.length));
		if (read_all((char*)&(*msg)[prependedHeaderSize], header.length) != int(header.length))
			return disconnect("failed to read message");

		unsigned char fullhash[32];
		double_sha256(&(*msg)[prependedHeaderSize], fullhash, header.length);
		if (memcmp((char*)fullhash, header.checksum, sizeof(header.checksum)))
			return disconnect("got invalid message checksum");

		if (!strncmp(header.command, "version", strlen("version"))) {
			if (connected != 0)
				return disconnect("got invalid version");
			connected = 1;

			if (header.length < sizeof(struct bitcoin_version_start))
				return disconnect("got short version");
			struct bitcoin_version_start *their_version = (struct bitcoin_version_start*) &(*msg)[0];

			struct bitcoin_msg_header new_header;
			send_message("verack", (unsigned char*)&new_header, 0);

			printf("Connected to bitcoind with version %u\n", le32toh(their_version->protocol_version));
			continue;
		} else if (!strncmp(header.command, "verack", strlen("verack"))) {
			if (connected != 1)
				return disconnect("got invalid verack");
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
			continue;
		}

		if (connected != 2)
			return disconnect("got non-version, non-verack before version+verack");

		if (!strncmp(header.command, "ping", strlen("ping"))) {
			std::vector<unsigned char> resp(sizeof(struct bitcoin_msg_header) + header.length);
			resp.insert(resp.begin() + sizeof(struct bitcoin_msg_header), msg->begin(), msg->end());
			send_message("pong", &resp[0], header.length);
		} else if (!strncmp(header.command, "inv", strlen("inv"))) {
			std::vector<unsigned char> resp(sizeof(struct bitcoin_msg_header));
			resp.insert(resp.end(), msg->begin(), msg->end());
			send_message("getdata", &resp[0], resp.size() - sizeof(struct bitcoin_msg_header));
		} else if (!strncmp(header.command, "block", strlen("block"))) {
			provide_block(*msg, read_start);
		} else if (!strncmp(header.command, "tx", strlen("tx"))) {
			provide_transaction(msg);
		} else if (!strncmp(header.command, "headers", strlen("headers"))) {
			if (msg->size() <= 1 + 82 || !provide_headers)
				continue; // Probably last one
			provide_headers(*msg);

			std::vector<unsigned char> req(sizeof(struct bitcoin_msg_header));
			struct bitcoin_version_start sent_version;
			req.insert(req.end(), (unsigned char*)&sent_version.protocol_version, ((unsigned char*)&sent_version.protocol_version) + sizeof(sent_version.protocol_version));
			req.insert(req.end(), 1, 1);

			std::vector<unsigned char> fullhash(32);
			getblockhash(fullhash, *msg, msg->size() - 81);
			req.insert(req.end(), fullhash.begin(), fullhash.end());
			req.insert(req.end(), 32, 0);

			send_message("getheaders", &req[0], req.size() - sizeof(struct bitcoin_msg_header));
		}
	}
}

void P2PRelayer::receive_transaction(const std::shared_ptr<std::vector<unsigned char> >& tx) {
	if (connected != 2)
		return;

	{
		std::lock_guard<std::mutex> lock(sent_mutex);
		if (txnAlreadySent.insert(*tx).second) {
			auto msg = std::vector<unsigned char>(sizeof(struct bitcoin_msg_header));
			msg.insert(msg.end(), tx->begin(), tx->end());
			send_message("tx", &msg[0], tx->size());
		}
	}
}

void P2PRelayer::receive_block(std::vector<unsigned char>& block) {
	if (connected != 2)
		return;
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
