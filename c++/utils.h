#ifndef _RELAY_UTILS_H
#define _RELAY_UTILS_H

#include <vector>
#include <string>
#include <assert.h>

/**********************************
 **** Things missing on !Linux ****
 **********************************/
#ifdef WIN32
	#undef errno
	#define errno WSAGetLastError()
#endif

#if defined(WIN32) || defined(X86_BSD)
	// Windows is LE-only anyway...
	#ifdef htole16
		#undef htole16
		#undef htole32
		#undef htole64
	#endif
	#define htole16(val) (val)
	#define htole32(val) (val)
	#define htole64(val) (val)
	#ifdef le16toh
		#undef le64toh
		#undef le32toh
		#undef le16toh
	#endif
	#define le64toh(val) (val)
	#define le32toh(val) (val)
	#define le16toh(val) (val)

	#define MSG_NOSIGNAL 0
#else
	#include <endian.h>
#endif

/**************************************************
 **** Message structs and constant definitions ****
 **************************************************/
struct relay_msg_header {
	uint32_t magic, type, length;
};

#define RELAY_MAGIC_BYTES htonl(0xF2BEEF42)
#define VERSION_STRING "toucan twink"
#define MAX_RELAY_TRANSACTION_BYTES 10000
#define MAX_RELAY_OVERSIZE_TRANSACTION_BYTES 200000
#define MAX_EXTRA_OVERSIZE_TRANSACTIONS 25


#define BITCOIN_MAGIC htonl(0xf9beb4d9)
struct __attribute__((packed)) bitcoin_msg_header {
	uint32_t magic;
	char command[12];
	uint32_t length;
	unsigned char checksum[4];
};
static_assert(sizeof(struct bitcoin_msg_header) == 4 + 12 + 4 + 4, "__attribute__((packed)) must work");

struct __attribute__((packed)) bitcoin_version_start {
	uint32_t protocol_version = 70000;
	uint64_t services = 0;
	uint64_t timestamp;
	unsigned char addr_recv[26] = {0};
	unsigned char addr_from[26] = {0};
	uint64_t nonce = 0xBADCAFE0DEADBEEF;
#ifdef BITCOIN_UA_LENGTH
	uint8_t user_agent_length = BITCOIN_UA_LENGTH;
#else
	uint8_t user_agent_length;
#endif
};
static_assert(sizeof(struct bitcoin_version_start) == 4 + 8 + 8 + 26 + 26 + 8 + 1, "__attribute__((packed)) must work");

#ifdef BITCOIN_UA
	struct __attribute__((packed)) bitcoin_version_end {
		// Begins with what is (usually) the UA
		char user_agent[BITCOIN_UA_LENGTH] = BITCOIN_UA;
		int32_t start_height = 0;
	};
	static_assert(sizeof(struct bitcoin_version_end) == BITCOIN_UA_LENGTH + 4, "__attribute__((packed)) must work");

	struct __attribute__((packed)) bitcoin_version {
		struct bitcoin_version_start start;
		struct bitcoin_version_end end;
	};
	static_assert(sizeof(struct bitcoin_version) == (4 + 8 + 8 + 26 + 26 + 8 + 1) + (BITCOIN_UA_LENGTH + 4), "__attribute__((packed)) must work");

	struct __attribute__((packed)) bitcoin_version_with_header {
		struct bitcoin_msg_header header;
		struct bitcoin_version version;
	};
	static_assert(sizeof(struct bitcoin_version_with_header) == (4 + 12 + 4 + 4) + (4 + 8 + 8 + 26 + 26 + 8 + 1) + (BITCOIN_UA_LENGTH + 4), "__attribute__((packed)) must work");
#endif // BITCOIN_UA


/***************************
 **** Varint processing ****
 ***************************/
class read_exception : std::exception {};
void move_forward(std::vector<unsigned char>::const_iterator& it, size_t i, const std::vector<unsigned char>::const_iterator& end);
uint64_t read_varint(std::vector<unsigned char>::const_iterator& it, const std::vector<unsigned char>::const_iterator& end);
std::vector<unsigned char> varint(uint32_t size);

/***********************
 **** Network utils ****
 ***********************/
ssize_t read_all(int filedes, char *buf, size_t nbyte);
ssize_t send_all(int filedes, const char *buf, size_t nbyte);
std::string gethostname(struct sockaddr_in6 *addr);
bool lookup_address(const char* addr, struct sockaddr_in6* res);
void prepare_message(const char* command, unsigned char* headerAndData, size_t datalen);

#endif
