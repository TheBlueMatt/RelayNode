#include <list>
#include <set>
#include <vector>
#include <thread>
#include <mutex>

#include <assert.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/time.h>

#define BITCOIN_UA_LENGTH 27 + 9
#define BITCOIN_UA {'/', 'R', 'e', 'l', 'a', 'y', 'N', 'e', 't', 'w', 'o', 'r', 'k', 'T', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'o', 'r', ':', '4', '2', '/', '0', '0', '0', '0', '0', '0', '0', '/', '\0'}

#include "crypto/sha2.h"
#include "mruset.h"
#include "utils.h"
#include "connection.h"



char* location;
/************************
 **** P2P Connection ****
 ************************/
class P2PConnection : public ThreadedConnection {
private:
	std::atomic_int connected;

	const std::function<void (P2PConnection*, std::shared_ptr<std::vector<unsigned char> >&, struct timeval)> provide_block;
	const std::function<void (P2PConnection*, std::shared_ptr<std::vector<unsigned char> >&)> provide_transaction;

	std::mutex seen_mutex;
	mruset<std::vector<unsigned char> > txnAlreadySeen;
	mruset<std::vector<unsigned char> > blocksAlreadySeen;

public:
	P2PConnection(int sockIn, std::string hostIn,
				const std::function<void (P2PConnection*, std::shared_ptr<std::vector<unsigned char> >&, struct timeval)>& provide_block_in,
				const std::function<void (P2PConnection*, std::shared_ptr<std::vector<unsigned char> >&)>& provide_transaction_in)
			: ThreadedConnection(sockIn, hostIn, NULL), connected(0), provide_block(provide_block_in), provide_transaction(provide_transaction_in),
			txnAlreadySeen(2000), blocksAlreadySeen(1000)
		{ construction_done(); }

private:
	void net_process(const std::function<void(std::string)>& disconnect) {
		while (true) {
			struct bitcoin_msg_header header;
			if (read_all((char*)&header, sizeof(header)) != sizeof(header))
				return disconnect("failed to read message header");

			if (header.magic != BITCOIN_MAGIC)
				return disconnect("invalid magic bytes");

			struct timeval start_read;
			gettimeofday(&start_read, NULL);

			header.length = le32toh(header.length);
			if (header.length > 5000000)
				return disconnect("got message too large");

			auto msg = std::make_shared<std::vector<unsigned char> > (sizeof(struct bitcoin_msg_header) + uint32_t(header.length));
			{
				uint32_t hash[8];
				double_sha256_init(hash);

				uint32_t steps = header.length / 64;
				for (uint32_t i = 0; i < steps; i++) {
					unsigned char* writepos = &((*msg)[sizeof(struct bitcoin_msg_header) + i*64]);
					if (read_all((char*)writepos, 64) != 64)
						return disconnect("failed to read message");
					double_sha256_step(writepos, 64, hash);
				}

				unsigned char* writepos = &((*msg)[sizeof(struct bitcoin_msg_header) + steps*64]);
				if (read_all((char*)writepos, header.length - steps*64) != ssize_t(header.length - steps*64))
					return disconnect("failed to read message");
				double_sha256_done(writepos, header.length - steps*64, header.length, hash);

				if (memcmp((char*)hash, header.checksum, sizeof(header.checksum)))
					return disconnect("got invalid message checksum");
			}

			if (!strncmp(header.command, "version", strlen("version"))) {
				if (connected != 0)
					return disconnect("got invalid version");
				connected = 1;

				if (header.length < sizeof(struct bitcoin_version_start))
					return disconnect("got short version");
				struct bitcoin_version_start *their_version = (struct bitcoin_version_start*) &(*msg)[sizeof(struct bitcoin_msg_header)];

				printf("%s Protocol version %u\n", host.c_str(), le32toh(their_version->protocol_version));

				struct bitcoin_version_with_header version_msg;
				version_msg.version.start.timestamp = htole64(time(0));
				memcpy(((char*)&version_msg.version.end.user_agent) + 27, location, 7);
				static_assert(BITCOIN_UA_LENGTH == 27 + 7 + 2 /* 27 + 7 + '/' + '\0' */, "BITCOIN_UA changed in header but file not updated");

				prepare_message("version", (unsigned char*)&version_msg, sizeof(struct bitcoin_version));
				do_send_bytes((char*)&version_msg, sizeof(struct bitcoin_version_with_header));

				struct bitcoin_msg_header verack_header;
				prepare_message("verack", (unsigned char*)&verack_header, 0);
				do_send_bytes((char*)&verack_header, sizeof(struct bitcoin_msg_header));

				continue;
			} else if (!strncmp(header.command, "verack", strlen("verack"))) {
				if (connected != 1)
					return disconnect("got invalid verack");
				connected = 2;
				continue;
			}

			if (connected != 2)
				return disconnect("got non-version, non-verack before version+verack");

			if (!strncmp(header.command, "ping", strlen("ping"))) {
				memcpy(&header.command, "pong", sizeof("pong"));
				memcpy(&(*msg)[0], &header, sizeof(struct bitcoin_msg_header));
				do_send_bytes((char*)&(*msg)[0], sizeof(struct bitcoin_msg_header) + header.length);
				continue;
			} else if (!strncmp(header.command, "inv", strlen("inv"))) {
				std::lock_guard<std::mutex> lock(seen_mutex);

				try {
					std::set<std::vector<unsigned char> > setRequestBlocks;
					std::set<std::vector<unsigned char> > setRequestTxn;

					std::vector<unsigned char>::const_iterator it = msg->begin();
					it += sizeof(struct bitcoin_msg_header);
					uint64_t count = read_varint(it, msg->end());
					if (count > 50000)
						return disconnect("inv count > MAX_INV_SZ");

					uint32_t MSG_TX = htole32(1);
					uint32_t MSG_BLOCK = htole32(2);

					for (uint64_t i = 0; i < count; i++) {
						move_forward(it, 4 + 32, msg->end());
						std::vector<unsigned char> hash(it-32, it);

						const uint32_t type = (*(it-(1+32)) << 24) | (*(it-(2+32)) << 16) | (*(it-(3+32)) << 8) | *(it-(4+32));
						if (type == MSG_TX) {
							if (!txnAlreadySeen.insert(hash).second)
								continue;
							setRequestTxn.insert(hash);
						} else if (type == MSG_BLOCK) {
							if (!blocksAlreadySeen.insert(hash).second)
								continue;
							setRequestBlocks.insert(hash);
						} else
							return disconnect("unknown inv type");
					}

					if (setRequestBlocks.size()) {
						std::vector<unsigned char> getdataMsg;
						std::vector<unsigned char> invCount = varint(setRequestBlocks.size());
						getdataMsg.reserve(sizeof(struct bitcoin_msg_header) + invCount.size() + setRequestBlocks.size()*36);

						getdataMsg.insert(getdataMsg.end(), sizeof(struct bitcoin_msg_header), 0);
						getdataMsg.insert(getdataMsg.end(), invCount.begin(), invCount.end());

						for (auto& hash : setRequestBlocks) {
							getdataMsg.insert(getdataMsg.end(), (unsigned char*)&MSG_BLOCK, ((unsigned char*)&MSG_BLOCK) + 4);
							getdataMsg.insert(getdataMsg.end(), hash.begin(), hash.end());
						}

						prepare_message("getdata", (unsigned char*)&getdataMsg[0], invCount.size() + setRequestBlocks.size()*36);
						do_send_bytes((char*)&getdataMsg[0], sizeof(struct bitcoin_msg_header) + invCount.size() + setRequestBlocks.size()*36);

						for (auto& hash : setRequestBlocks) {
							struct timeval tv;
							gettimeofday(&tv, NULL);
							for (unsigned int i = 0; i < hash.size(); i++)
								printf("%02x", hash[hash.size() - i - 1]);
							printf(" requested from %s at %lu\n", host.c_str(), uint64_t(tv.tv_sec) * 1000 + uint64_t(tv.tv_usec) / 1000);
						}
					}

					if (setRequestTxn.size()) {
						std::vector<unsigned char> getdataMsg;
						std::vector<unsigned char> invCount = varint(setRequestTxn.size());
						getdataMsg.reserve(sizeof(struct bitcoin_msg_header) + invCount.size() + setRequestTxn.size()*36);

						getdataMsg.insert(getdataMsg.end(), sizeof(struct bitcoin_msg_header), 0);
						getdataMsg.insert(getdataMsg.end(), invCount.begin(), invCount.end());

						for (const std::vector<unsigned char>& hash : setRequestTxn) {
							getdataMsg.insert(getdataMsg.end(), (unsigned char*)&MSG_TX, ((unsigned char*)&MSG_TX) + 4);
							getdataMsg.insert(getdataMsg.end(), hash.begin(), hash.end());
						}

						prepare_message("getdata", (unsigned char*)&getdataMsg[0], invCount.size() + setRequestTxn.size()*36);
						do_send_bytes((char*)&getdataMsg[0], sizeof(struct bitcoin_msg_header) + invCount.size() + setRequestTxn.size()*36);
					}
				} catch (read_exception) {
					return disconnect("failed to process inv");
				}
				continue;
			}

			memcpy(&(*msg)[0], &header, sizeof(struct bitcoin_msg_header));
			if (!strncmp(header.command, "block", strlen("block"))) {
				provide_block(this, msg, start_read);
			} else if (!strncmp(header.command, "tx", strlen("tx"))) {
				provide_transaction(this, msg);
			}
		}
	}

public:
	void receive_transaction(const std::vector<unsigned char> hash, const std::shared_ptr<std::vector<unsigned char> >& tx) {
		if (connected != 2)
			return;
		maybe_send_bytes(tx);
	}

	void receive_block(const std::vector<unsigned char> hash, const std::shared_ptr<std::vector<unsigned char> >& block) {
		if (connected != 2)
			return;

		{
			std::lock_guard<std::mutex> lock(seen_mutex);
			if (!blocksAlreadySeen.insert(hash).second)
				return;
		}
		do_send_bytes(block);
	}
};




int main(int argc, char** argv) {
	if (argc != 2 || strlen(argv[1]) != 7) {
		printf("USAGE %s 7-char-LOCATION\n", argv[0]);
		return -1;
	}
	location = argv[1];

	int blockonly_fd, txes_fd, new_fd;
	struct sockaddr_in6 addr;

	fd_set twofds;
	FD_ZERO(&twofds);

	if ((blockonly_fd = socket(AF_INET6, SOCK_STREAM, 0)) < 0 ||
		     (txes_fd = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
		printf("Failed to create socket\n");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_any;
	addr.sin6_port = htons(8334);

	int reuse = 1;

	if (setsockopt(blockonly_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) ||
			bind(blockonly_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
			listen(blockonly_fd, 3) < 0) {
		printf("Failed to bind 8334: %s\n", strerror(errno));
		return -1;
	}

	addr.sin6_port = htons(8335);
	if (setsockopt(txes_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) ||
			bind(txes_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
			listen(txes_fd, 3) < 0) {
		printf("Failed to bind 8335: %s\n", strerror(errno));
		return -1;
	}

	std::mutex list_mutex;
	std::set<P2PConnection*> blockSet;
	std::set<P2PConnection*> txesSet;
	std::set<P2PConnection*> localSet;

	std::function<void (P2PConnection*, std::shared_ptr<std::vector<unsigned char> >&, struct timeval)> relayBlock =
		[&](P2PConnection* from, std::shared_ptr<std::vector<unsigned char>> & bytes, struct timeval start_recv) {
			struct timeval start_send, finish_send;
			gettimeofday(&start_send, NULL);

			if (bytes->size() < 80)
				return;
			std::vector<unsigned char> fullhash(32);
			getblockhash(fullhash, *bytes, sizeof(struct bitcoin_msg_header));

			{
				std::lock_guard<std::mutex> lock(list_mutex);
				std::set<P2PConnection*> *set;
				if (localSet.count(from))
					set = &blockSet;
				else
					set = &localSet;
				for (auto it = set->begin(); it != set->end(); it++) {
					if (!(*it)->getDisconnectFlags())
						(*it)->receive_block(fullhash, bytes);
				}
			}

			gettimeofday(&finish_send, NULL);
			for (unsigned int i = 0; i < fullhash.size(); i++)
				printf("%02x", fullhash[fullhash.size() - i - 1]);
			printf(" BLOCK %lu %s %s %u / %u TIMES: %ld %ld\n", uint64_t(start_send.tv_sec) * 1000 + uint64_t(start_send.tv_usec) / 1000, from->host.c_str(),
					localSet.count(from) ? "LOCALRELAY" : "REMOTEP2P", (unsigned)bytes->size(), (unsigned)bytes->size(),
					int64_t(start_send.tv_sec - start_recv.tv_sec)*1000 + (int64_t(start_send.tv_usec) - start_recv.tv_usec)/1000,
					int64_t(finish_send.tv_sec - start_send.tv_sec)*1000 + (int64_t(finish_send.tv_usec) - start_send.tv_usec)/1000);
		};
	std::function<void (P2PConnection*, std::shared_ptr<std::vector<unsigned char> >&)> relayTx =
		[&](P2PConnection* from, std::shared_ptr<std::vector<unsigned char> >& bytes) {
			std::vector<unsigned char> fullhash(32);
			double_sha256(&(*bytes)[sizeof(struct bitcoin_msg_header)], &fullhash[0], bytes->size() - sizeof(struct bitcoin_msg_header));

			std::lock_guard<std::mutex> lock(list_mutex);
			std::set<P2PConnection*> *set;
			if (localSet.count(from))
				set = &txesSet;
			else
				set = &localSet;
			for (auto it = set->begin(); it != set->end(); it++) {
				if (!(*it)->getDisconnectFlags())
					(*it)->receive_transaction(fullhash, bytes);
			}
		};

	printf("Awaiting connections\n");

	while (true) {
		FD_SET(blockonly_fd, &twofds);
		FD_SET(txes_fd, &twofds);
		struct timeval timeout;
		timeout.tv_sec = 30;
		timeout.tv_usec = 0;

		if (select(FD_SETSIZE, &twofds, NULL, NULL, &timeout) < 0) {
			printf("Failed to select (%s)\n", strerror(errno));
			return -1;
		}

		socklen_t addr_size = sizeof(addr);
		std::string localhost("::ffff:127.0.0.1/");
		std::string droppostfix(".uptimerobot.com");
		if (FD_ISSET(blockonly_fd, &twofds)) {
			if ((new_fd = accept(blockonly_fd, (struct sockaddr *) &addr, &addr_size)) < 0) {
				printf("Failed to accept\n");
				return -1;
			}

			std::string host = gethostname(&addr);
			if (host.length() > droppostfix.length() && !host.compare(host.length() - droppostfix.length(), droppostfix.length(), droppostfix))
				close(new_fd);
			else {
				std::lock_guard<std::mutex> lock(list_mutex);
				P2PConnection *relay = new P2PConnection(new_fd, host, relayBlock, relayTx);
				if (!host.compare(0, localhost.size(), localhost))
					localSet.insert(relay);
				else
					blockSet.insert(relay);
			}
		}
		if (FD_ISSET(txes_fd, &twofds)) {
			if ((new_fd = accept(txes_fd, (struct sockaddr *) &addr, &addr_size)) < 0) {
				printf("Failed to accept\n");
				return -1;
			}

			std::string host = gethostname(&addr);
			if (host.length() > droppostfix.length() && !host.compare(host.length() - droppostfix.length(), droppostfix.length(), droppostfix))
				close(new_fd);
			else {
				std::lock_guard<std::mutex> lock(list_mutex);
				P2PConnection *relay = new P2PConnection(new_fd, host, relayBlock, relayTx);
				if (!host.compare(0, localhost.size(), localhost))
					localSet.insert(relay);
				else {
					blockSet.insert(relay);
					txesSet.insert(relay);
				}
			}
		}

		std::lock_guard<std::mutex> lock(list_mutex);
		for (auto it = blockSet.begin(); it != blockSet.end();) {
			if ((*it)->getDisconnectFlags() & DISCONNECT_COMPLETE) {
				auto rm = it++; auto item = *rm;
				txesSet.erase(item);
				blockSet.erase(rm);
				delete item;
			} else
				it++;
		}
		for (auto it = localSet.begin(); it != localSet.end();) {
			if ((*it)->getDisconnectFlags() & DISCONNECT_COMPLETE) {
				auto rm = it++; auto item = *rm;
				localSet.erase(rm);
				delete item;
			} else
				it++;
		}
		fprintf(stderr, "Have %lu local connection(s), %lu block connection(s) and %lu txes conenction(s)\n", localSet.size(), blockSet.size() - txesSet.size(), txesSet.size());
	}
}
