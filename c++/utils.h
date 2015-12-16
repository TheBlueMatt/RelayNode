#ifndef _RELAY_UTILS_H
#define _RELAY_UTILS_H

#include "preinclude.h"

#include <vector>
#include <string>
#include <assert.h>
#include <unistd.h>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <sys/time.h>

#define likely(x)   __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

/**********************************
 **** Things missing on !Linux ****
 **********************************/
#ifdef WIN32
	#undef errno
	#define errno WSAGetLastError()
	#undef close
	#define close closesocket
#endif

#if defined(WIN32) || (defined(__APPLE__) && defined(__MACH__) && defined(FORCE_LE))
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

	#ifndef MSG_NOSIGNAL
		#define MSG_NOSIGNAL 0
	#endif
#elif defined(__FreeBSD__)
	#include <sys/endian.h>
	#ifndef MSG_NOSIGNAL
		#define MSG_NOSIGNAL 0
	#endif
#else
	#include <endian.h>
#endif

/**************************************************
 **** Message structs and constant definitions ****
 **************************************************/
struct relay_msg_header {
	uint32_t magic, type, length;
};
static_assert(sizeof(struct relay_msg_header) == 3*4, "relay_msg_header is 12 bytes");

#define RELAY_MAGIC_BYTES htonl(0xF2BEEF42)
#define VERSION_STRING "what i should have done"
#define MAX_RELAY_TRANSACTION_BYTES 100000
#define MAX_FAS_TOTAL_SIZE 5000000

#define OLD_MAX_RELAY_TRANSACTION_BYTES 10000
#define OLD_MAX_RELAY_OVERSIZE_TRANSACTION_BYTES 200000
#define OLD_MAX_EXTRA_OVERSIZE_TRANSACTIONS 25
#define OLD_MAX_TXN_IN_FAS 5025

// Limit outbound to avg 2Mbps worst-case (2Mb / 1000 ms)
#define OUTBOUND_THROTTLE_BYTES_PER_MS 250

// Number of types of compressors there are (see server)
#define COMPRESSOR_TYPES 3


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
inline void move_forward(std::vector<unsigned char>::const_iterator& it, size_t i, const std::vector<unsigned char>::const_iterator& end) {
	if (unlikely(it > end-i))
		throw read_exception();
	std::advance(it, i);
}
uint64_t read_varint(std::vector<unsigned char>::const_iterator& it, const std::vector<unsigned char>::const_iterator& end);
uint32_t varint_length(uint32_t num);
std::vector<unsigned char> varint(uint32_t size);

/***********************
 **** Network utils ****
 ***********************/
ssize_t read_all(int filedes, char *buf, size_t nbyte);
ssize_t send_all(int filedes, const char *buf, size_t nbyte);
std::string gethostname(struct sockaddr_in6 *addr);
bool lookup_address(const char* addr, struct sockaddr_in6* res);
bool lookup_cname(const char* host, std::string& cname);
void prepare_message(const char* command, unsigned char* headerAndData, size_t datalen);
int create_connect_socket(const std::string& serverHost, const uint16_t serverPort, std::string& error);

/*********************
 *** Hashing utils ***
 *********************/
void double_sha256(const unsigned char* input, unsigned char* res, uint64_t byte_count);
void double_sha256_two_32_inputs(const unsigned char* input, const unsigned char* input2, unsigned char* res);
void getblockhash(std::vector<unsigned char>& hashRes, const std::vector<unsigned char>& block, size_t offset);
void getblockhash(std::vector<unsigned char>& hashRes, const unsigned char* headerptr);

void double_sha256_init(uint32_t state[8]);
void double_sha256_step(const unsigned char* input, uint64_t byte_count, uint32_t state[8]);
void double_sha256_done(const unsigned char* input, uint64_t byte_count, uint64_t total_byte_count, uint32_t state[8]);

/********************
 *** Random stuff ***
 ********************/
#define HASH_FORMAT "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
#define HASH_PRINT(var) (unsigned char)(var)[31], (unsigned char)(var)[30], \
						(unsigned char)(var)[29], (unsigned char)(var)[28], (unsigned char)(var)[27], (unsigned char)(var)[26], (unsigned char)(var)[25], \
						(unsigned char)(var)[24], (unsigned char)(var)[23], (unsigned char)(var)[22], (unsigned char)(var)[21], (unsigned char)(var)[20], \
						(unsigned char)(var)[19], (unsigned char)(var)[18], (unsigned char)(var)[17], (unsigned char)(var)[16], (unsigned char)(var)[15], \
						(unsigned char)(var)[14], (unsigned char)(var)[13], (unsigned char)(var)[12], (unsigned char)(var)[11], (unsigned char)(var)[10], \
						(unsigned char)(var)[ 9], (unsigned char)(var)[ 8], (unsigned char)(var)[ 7], (unsigned char)(var)[ 6], (unsigned char)(var)[ 5], \
						(unsigned char)(var)[ 4], (unsigned char)(var)[ 3], (unsigned char)(var)[ 2], (unsigned char)(var)[ 1], (unsigned char)(var)[ 0]
bool hex_str_to_reverse_vector(const std::string& str, std::vector<unsigned char>& vec);
std::string asciifyString(const std::string& str);

#define millis_lu_type std::chrono::duration<long unsigned, std::chrono::milliseconds::period>
#define to_millis_double(t) (std::chrono::duration_cast<std::chrono::duration<double, std::chrono::milliseconds::period> >(t).count())
#define to_millis_lu(t) (std::chrono::duration_cast<std::chrono::duration<long unsigned, std::chrono::milliseconds::period> >(t).count())
#define to_micros_lu(t) (std::chrono::duration_cast<std::chrono::duration<long unsigned, std::chrono::microseconds::period> >(t).count())
#define epoch_millis_lu(t) to_millis_lu((t).time_since_epoch())

void do_assert(bool flag, const char* file, unsigned long line);
#ifdef NDEBUG
#define ALWAYS_ASSERT(cond) do_assert((cond), __FILE__, __LINE__)
#else
#define ALWAYS_ASSERT assert
#endif

#define STAMPOUT() do { \
		struct timeval now_tv; \
		struct tm tm; \
		int ms; \
		gettimeofday(&now_tv, NULL); \
		ms = (int)(now_tv.tv_usec / 1000); \
		gmtime_r(&(now_tv.tv_sec), &tm); \
		printf("[%d-%02d-%02d %02d:%02d:%02d.%03d+00] ", \
			tm.tm_year + 1900, \
			tm.tm_mon + 1, \
			tm.tm_mday, \
			tm.tm_hour, \
			tm.tm_min, \
			tm.tm_sec, \
			ms); \
	} while(0)

/****************************************************************
 *** A mutex that gives acess to the count of waiting threads ***
 ****************************************************************/
class WaitCountMutex {
private:
	std::mutex mutex;
	DECLARE_ATOMIC_INT(int, waitCount);

	friend class WaitCountHint;
public:
	WaitCountMutex() { waitCount = 0; }
	void lock() {
		if (unlikely(!mutex.try_lock())) {
			waitCount.fetch_add(1, std::memory_order_release);
			mutex.lock();
			waitCount.fetch_sub(1, std::memory_order_relaxed);
		}
	}
	bool try_lock() { return mutex.try_lock(); }
	void unlock() { return mutex.unlock(); }
	int wait_count() { return waitCount.load(std::memory_order_acquire); }
};

class WaitCountHint {
private:
	WaitCountMutex* mutex;
public:
	WaitCountHint(WaitCountMutex& mutexIn)
		: mutex(&mutexIn)
		{ mutex->waitCount.fetch_add(1, std::memory_order_release); }
	~WaitCountHint() { mutex->waitCount.fetch_sub(1, std::memory_order_relaxed); }
};

/*****************************************
 *** A R-W Mutex (no upgrades for now) ***
 *****************************************/
class ReadWriteMutex {
private:
	std::mutex mutex;
	std::condition_variable write_done_cv, read_done_cv;
	int readers = 0;
	bool writer_waiting = false;
public:
	void read_lock() {
		std::unique_lock<std::mutex> lock(mutex);
		while (writer_waiting)
			write_done_cv.wait(lock);
		readers++;
	}
	void read_unlock() {
		std::lock_guard<std::mutex> lock(mutex);
		readers--;
		read_done_cv.notify_all();
	}

	void write_lock() {
		std::unique_lock<std::mutex> lock(mutex);
		writer_waiting = true;
		while (readers)
			read_done_cv.wait(lock);
		writer_waiting = false;
		lock.release();
	}
	void write_unlock() {
		write_done_cv.notify_all();
		mutex.unlock();
	}
};

class ReadWriteMutexReader {
private:
	ReadWriteMutex* mutex;
public:
	ReadWriteMutexReader(ReadWriteMutex* mutex_in) : mutex(mutex_in) {}
	void lock() { mutex->read_lock(); }
	void unlock() { mutex->read_unlock(); }
};

class ReadWriteMutexWriter {
private:
	ReadWriteMutex* mutex;
public:
	ReadWriteMutexWriter(ReadWriteMutex* mutex_in) : mutex(mutex_in) {}
	void lock() { mutex->write_lock(); }
	void unlock() { mutex->write_unlock(); }
};

#endif
