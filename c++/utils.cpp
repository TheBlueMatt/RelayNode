#include "preinclude.h"
#include "utils.h"
#include "crypto/sha2.h"

#include <vector>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#ifdef WIN32
	// MinGW doesnt have this line (copied from Wine) for licensing reasons
	#define AI_V4MAPPED 0x00000800
	#include <winsock2.h>
	#include <ws2tcpip.h>
#else // WIN32
	#include <arpa/inet.h>
	#include <netinet/in.h>
	#include <netinet/tcp.h>
	#include <netdb.h>
	#include <fcntl.h>
	#include <sys/socket.h>
	#include <arpa/nameser.h>
	#include <resolv.h>
#endif // !WIN32

#ifdef __APPLE__
	#include <arpa/nameser_compat.h>
#endif

/***************************
 **** Varint processing ****
 ***************************/
uint64_t read_varint(std::vector<unsigned char>::const_iterator& it, const std::vector<unsigned char>::const_iterator& end) {
	move_forward(it, 1, end);
	uint8_t first = *(it-1);
	if (first < 0xfd)
		return first;
	else if (first == 0xfd) {
		move_forward(it, 2, end);
		return ((*(it-1) << 8) | *(it-2));
	} else if (first == 0xfe) {
		move_forward(it, 4, end);
		return ((*(it-1) << 24) | (*(it-2) << 16) | (*(it-3) << 8) | *(it-4));
	} else {
		move_forward(it, 8, end);
		return ((uint64_t(*(it-1)) << 56) |
						(uint64_t(*(it-2)) << 48) |
						(uint64_t(*(it-3)) << 40) |
						(uint64_t(*(it-4)) << 32) |
						(uint64_t(*(it-5)) << 24) |
						(uint64_t(*(it-6)) << 16) |
						(uint64_t(*(it-7)) << 8) |
						 uint64_t(*(it-8)));
	}
}

uint32_t varint_length(uint32_t num) {
	if (num < 0xfd)
		return 1;
	else if (num < 0xffff)
		return 3;
	else if (num < 0xffffffff)
		return 5;
	else
		return 9;
}

std::vector<unsigned char> varint(uint32_t num) {
	if (num < 0xfd) {
		uint8_t lenum = num;
		return std::vector<unsigned char>(&lenum, &lenum + sizeof(lenum));
	} else {
		std::vector<unsigned char> res;
		if (num <= 0xffff) {
			res.push_back(0xfd);
			uint16_t lenum = htole16(num);
			res.insert(res.end(), (unsigned char*)&lenum, ((unsigned char*)&lenum) + sizeof(lenum));
		} else if (num <= 0xffffffff) {
			res.push_back(0xfe);
			uint32_t lenum = htole32(num);
			res.insert(res.end(), (unsigned char*)&lenum, ((unsigned char*)&lenum) + sizeof(lenum));
		} else {
			res.push_back(0xff);
			uint64_t lenum = htole64(num);
			res.insert(res.end(), (unsigned char*)&lenum, ((unsigned char*)&lenum) + sizeof(lenum));
		}
		return res;
	}
}




/***********************
 **** Network utils ****
 ***********************/
ssize_t read_all(int filedes, char *buf, size_t nbyte) {
	if (nbyte <= 0)
		return 0;

	ssize_t count = 0;
	size_t total = 0;
#ifndef WIN32
	// We use read here so that tests can read from a pipe
	while (total < nbyte && (count = read(filedes, buf + total, nbyte-total)) > 0)
#else
	// But mingw/win32 suck terribly, so we have to use recv here
	while (total < nbyte && (count = recv(filedes, buf + total, nbyte-total, 0)) > 0)
#endif
		total += count;
	if (count <= 0)
		return count;
	else
		return total;
}

ssize_t send_all(int filedes, const char *buf, size_t nbyte) {
	ssize_t count = 0;
	size_t total = 0;
	while (total < nbyte && (count = send(filedes, buf + total, nbyte-total, MSG_NOSIGNAL)) > 0)
		total += count;
	if (count <= 0)
		return count;
	else
		return total;
}

std::string gethostname(struct sockaddr_in6 *addr) {
	char hbuf[NI_MAXHOST];
	if (getnameinfo((struct sockaddr*) addr, sizeof(*addr), hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST))
		return "Unknown host";

	std::string res(hbuf);
	res += "/";
	if (getnameinfo((struct sockaddr*) addr, sizeof(*addr), hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD))
		return res;
	else
		return res + std::string(hbuf);
}

#ifdef FOR_VALGRIND
//getaddrinfo is detected by helgrind/drd as having a data race in it.
//I haven't actually checked if this is the case, but the manpage says it doesn't, so lets just work around that :)
static std::mutex getaddrinfo_mutex;
#endif

bool lookup_address(const char* addr, struct sockaddr_in6* res) {
	struct addrinfo hints,*server = NULL;

	memset(&hints, 0, sizeof(hints));
#ifdef X86_BSD
	hints.ai_flags = 0;
	hints.ai_family = AF_INET;
#else
	hints.ai_flags = AI_V4MAPPED;
	hints.ai_family = AF_INET6;
#endif

	int gaires
#ifdef FOR_VALGRIND
		;
	{
		std::lock_guard<std::mutex> lock(getaddrinfo_mutex);
		gaires
#endif
		= getaddrinfo(addr, NULL, &hints, &server);
#ifdef FOR_VALGRIND
		}
#endif
	if (gaires) {
		printf("Unable to lookup hostname: %d (%s)\n", gaires, gai_strerror(gaires));
		if (server)
			freeaddrinfo(server);
		return false;
	}
	memset((void*)res, 0, sizeof(*res));
	res->sin6_family = AF_INET6;
#ifdef X86_BSD
	struct sockaddr_in * in4 = (struct sockaddr_in *)server->ai_addr;
	uint8_t * p4 = (uint8_t *) &(in4->sin_addr);
	uint8_t * p6 = (uint8_t *) &(res->sin6_addr);
	for (int i=0; i < 10; i++)
		p6[i] = 0x00;
	p6[10] = 0xff;
	p6[11] = 0xff;
	for (int i=0; i < 4; i++)
		p6[12+i] = p4[i];
	res->sin6_family = AF_INET6;
#else
	if (server->ai_addrlen != sizeof(*res)) {
		freeaddrinfo(server);
		return false;
	}
	res->sin6_addr = ((struct sockaddr_in6*)server->ai_addr)->sin6_addr;
#endif

	freeaddrinfo(server);
	return true;
}

void prepare_message(const char* command, unsigned char* headerAndData, size_t datalen) {
	struct bitcoin_msg_header *header = (struct bitcoin_msg_header*)headerAndData;

	memset(header->command, 0, sizeof(header->command));
	strcpy(header->command, command);

	header->length = htole32(datalen);
	header->magic = BITCOIN_MAGIC;

	unsigned char fullhash[32];
	double_sha256(headerAndData + sizeof(struct bitcoin_msg_header), fullhash, datalen);
	memcpy(header->checksum, fullhash, sizeof(header->checksum));
}

#ifndef WIN32
static int read_dn_name(unsigned char* answer, unsigned char* answerend, unsigned char*& it, char buf[1024]) {
	int len = dn_expand(answer, answerend, it, buf, 1024);
	if (len <= 0)
		return len;
	it += len;
	return len;
}
#endif

bool lookup_cname(const char* host, std::string& cname) {
#ifndef WIN32
	unsigned char answer[4096];
	char buf[1024];

	int size = res_search(host, C_IN, T_CNAME, answer, sizeof(answer));
	if (size <= 2*6)
		return false;
	unsigned char *it = answer + 2*6;

	if (read_dn_name(answer, answer + size, it, buf) < 0)
		return false;
	it += 4;
	if (it >= answer + size)
		return false;
	if (*(it-4) != 0x00 || *(it-3) != 0x05 || *(it-2) != 0x00 || *(it-1) != 0x01)
		return false;

	if (read_dn_name(answer, answer + size, it, buf) < 0)
		return false;
	it += 4;
	if (it >= answer + size)
		return false;
	if (*(it-4) != 0x00 || *(it-3) != 0x05 || *(it-2) != 0x00 || *(it-1) != 0x01)
		return false;

	it += 6;
	if (read_dn_name(answer, answer + size, it, buf) < 0)
		return false;
	cname = std::string(buf);
	return true;
#endif
	return false;
}

int create_connect_socket(const std::string& serverHost, const uint16_t serverPort, std::string& error) {
	int sock = socket(AF_INET6, SOCK_STREAM, 0);
	if (sock <= 0) {
		error = "unable to create socket";
		return sock;
	}

	sockaddr_in6 addr;
	if (!lookup_address(serverHost.c_str(), &addr)) {
		close(sock);
		error = "unable to lookup host";
		return -1;
	}

	int v6only = 0;
	setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&v6only, sizeof(v6only));

	addr.sin6_port = htons(serverPort);
	if (connect(sock, (struct sockaddr*)&addr, sizeof(addr))) {
		close(sock);
		error = "failed to connect()";
		return -1;
	}

	return sock;
}

/********************
 *** Random stuff ***
 ********************/
#ifdef SHA256
extern "C" void SHA256(const void *, uint32_t[8], uint64_t);
#endif

void static inline WriteBE64(unsigned char *ptr, uint64_t x) {
	ptr[0] = x >> 56; ptr[1] = x >> 48; ptr[2] = x >> 40; ptr[3] = x >> 32;
	ptr[4] = x >> 24; ptr[5] = x >> 16; ptr[6] = x >> 8; ptr[7] = x;
}

void static inline WriteBE32(unsigned char *ptr, uint32_t x) {
	ptr[0] = x >> 24; ptr[1] = x >> 16; ptr[2] = x >> 8; ptr[3] = x;
}

void static inline sha256_init(uint32_t state[8]) {
	state[0] = 0x6a09e667ul;
	state[1] = 0xbb67ae85ul;
	state[2] = 0x3c6ef372ul;
	state[3] = 0xa54ff53aul;
	state[4] = 0x510e527ful;
	state[5] = 0x9b05688cul;
	state[6] = 0x1f83d9abul;
	state[7] = 0x5be0cd19ul;
}

void static inline sha256_done(unsigned char* res, uint32_t state[8]) {
	WriteBE32(res     , state[0]);
	WriteBE32(res +  4, state[1]);
	WriteBE32(res +  8, state[2]);
	WriteBE32(res + 12, state[3]);
	WriteBE32(res + 16, state[4]);
	WriteBE32(res + 20, state[5]);
	WriteBE32(res + 24, state[6]);
	WriteBE32(res + 28, state[7]);
}

void double_sha256(const unsigned char* input, unsigned char* res, uint64_t byte_count) {
#ifndef SHA256
	CSHA256 hash;
	if (byte_count)
		hash.Write(input, byte_count);
	hash.Finalize(res);
	hash.Reset().Write(res, 32).Finalize(res);
#else
	uint32_t state[8];
	sha256_init(state);
	uint64_t bytes_read = byte_count / 64;
	if (bytes_read)
		SHA256(&input[0], state, bytes_read);

	bytes_read *= 64;
	uint64_t bytes_left = byte_count - bytes_read;

	unsigned char data[128];

	uint64_t pad_count = 1 + ((119 - bytes_left) % 64);
	assert((byte_count + pad_count + 8) % 64 == 0);

	memcpy(&data[0], input + bytes_read, bytes_left);
	data[bytes_left] = 0x80;
	memset(&data[bytes_left + 1], 0, pad_count-1);
	WriteBE64(&data[bytes_left + pad_count], byte_count << 3);

	SHA256(&data[0], state, (bytes_left + pad_count + 8) / 64);
	sha256_done(&data[0], state);

	data[32] = 0x80;
	memset(&data[32 + 1], 0, 32 - 8 - 1);
	WriteBE64(&data[64 - 8], 32 << 3);
	sha256_init(state);

	SHA256(&data[0], state, 1);
	sha256_done(res, state);
#endif
}

void double_sha256_two_32_inputs(const unsigned char* input, const unsigned char* input2, unsigned char* res) {
#ifndef SHA256
	CSHA256 hash;
	hash.Write(input, 32).Write(input2, 32).Finalize(res);
	hash.Reset().Write(res, 32).Finalize(res);
#else
	unsigned char data[128];

	memcpy(data,      input,  32);
	memcpy(data + 32, input2, 32);
	data[64] = 0x80;
	memset(data + 64 + 1, 0, 64 - 8 - 1);
	WriteBE64(data + 128 - 8, 64 << 3);

	uint32_t state[8];
	sha256_init(state);

	SHA256(&data[0], state, 2);
	sha256_done(data, state);

	data[32] = 0x80;
	memset(data + 32 + 1, 0, 32 - 8 - 1);
	WriteBE64(data + 64 - 8, 32 << 3);
	sha256_init(state);

	SHA256(data, state, 1);
	sha256_done(res, state);
#endif
}

void double_sha256_init(uint32_t state[8]) {
#ifndef SHA256
	CSHA256 hash;
	for (uint8_t i = 0; i < 8; i++)
		state[i] = hash.s[i];
#else
	sha256_init(state);
#endif
}

void double_sha256_step(const unsigned char* input, uint64_t byte_count, uint32_t state[8]) {
	assert(byte_count % 64 == 0);
	if (byte_count) {
#ifndef SHA256
		CSHA256 hash;
		for (uint8_t i = 0; i < 8; i++)
			hash.s[i] = state[i];
		hash.Write(input, byte_count);
		for (uint8_t i = 0; i < 8; i++)
			state[i] = hash.s[i];
#else
		SHA256(const_cast<unsigned char*>(input), state, byte_count / 64);
#endif
	}
}

void double_sha256_done(const unsigned char* input, uint64_t byte_count, uint64_t total_byte_count, uint32_t state[8]) {
	assert((total_byte_count - byte_count) % 64 == 0);
#ifndef SHA256
	CSHA256 hash;
	if ((total_byte_count - byte_count) != 0) {
		for (uint8_t i = 0; i < 8; i++)
			hash.s[i] = state[i];
		hash.bytes = total_byte_count - byte_count;
	}
	if (byte_count)
		hash.Write(input, byte_count);
	hash.Finalize((unsigned char*)state);
	hash.Reset().Write((unsigned char*)state, 32).Finalize((unsigned char*)state);
#else
	uint64_t pad_count = 1 + ((119 - (total_byte_count % 64)) % 64);
	assert(1 + ((119 - (byte_count % 64)) % 64) == pad_count);
	unsigned char data[byte_count + pad_count + 8];

	memcpy(data, input, byte_count);
	data[byte_count] = 0x80;
	memset(&data[byte_count+1], 0, pad_count-1);
	WriteBE64(&data[byte_count + pad_count], total_byte_count << 3);

	assert((byte_count + pad_count + 8) % 64 == 0);
	SHA256(&data[0], state, (byte_count + pad_count + 8) / 64);
	sha256_done(&data[0], state);

	data[32] = 0x80;
	memset(&data[32 + 1], 0, 32 - 8 - 1);
	WriteBE64(&data[64 - 8], 32 << 3);
	sha256_init(state);

	SHA256(&data[0], state, 1);
	sha256_done((unsigned char*)state, state);
#endif
}

void getblockhash(std::vector<unsigned char>& hashRes, const unsigned char* headerptr) {
	assert(hashRes.size() == 32);
	double_sha256(headerptr, &hashRes[0], 80);
}

void getblockhash(std::vector<unsigned char>& hashRes, const std::vector<unsigned char>& block, size_t offset) {
	assert(hashRes.size() == 32);
	assert(block.size() >= offset + 80);
	double_sha256(&block[offset], &hashRes[0], 80);
}

class not_hex : public std::exception {};
static inline unsigned char h2c(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	throw not_hex();
}
bool hex_str_to_reverse_vector(const std::string& str, std::vector<unsigned char>& vec) {
	assert(vec.empty());
	if (str.length() % 2 != 0)
		return false;
	try {
		for (ssize_t i = str.length() - 2; i >= 0; i -= 2)
			vec.push_back((h2c(str[i]) << 4) | h2c(str[i + 1]));
		return true;
	} catch (const not_hex& e) {
		return false;
	}
}

std::string asciifyString(const std::string& str) {
	std::string res;
	res.reserve(str.length());
	for (size_t i = 0; i < str.length(); i++) {
		if (str[i] >= 0x20 && str[i] <= 0x7e)
			res.push_back(str[i]);
	}
	return res;
}

void do_assert(bool flag, const char* file, unsigned long line) {
	if (!flag) {
		fprintf(stderr, "Assertion failed: %s:%lu\n", file, line);
		exit(1);
	}
}
