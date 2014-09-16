#ifndef _RELAY_P2PCLIENT_H
#define _RELAY_P2PCLIENT_H

#include <thread>
#include <vector>
#include <string>
#include <mutex>
#include <atomic>

class P2PRelayer {
private:
	const char* server_host;
	uint16_t server_port;

	const std::function<void (std::vector<unsigned char>&, struct timeval)> provide_block;
	const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)> provide_transaction;

	int sock;
	std::atomic<bool> connected;
	std::mutex send_mutex;
	std::thread* net_thread, *new_thread;

protected:
	typedef bool (header_func_type) (std::vector<unsigned char>&);
private:
	header_func_type *provide_headers;
	bool requestAfterSend;

public:
	P2PRelayer(const char* serverHostIn, uint16_t serverPortIn,
				const std::function<void (std::vector<unsigned char>&, struct timeval)>& provide_block_in,
				const std::function<void (std::shared_ptr<std::vector<unsigned char> >&)>& provide_transaction_in,
				header_func_type *provide_headers_in=NULL, bool requestAfterSendIn=false)
			: server_host(serverHostIn), server_port(serverPortIn), provide_block(provide_block_in), provide_transaction(provide_transaction_in),
			sock(0), connected(false), net_thread(NULL), new_thread(NULL),
			provide_headers(provide_headers_in), requestAfterSend(requestAfterSendIn) {
		new_thread = new std::thread(do_connect, this);
	}

protected:
	bool send_message(const char* command, unsigned char* headerAndData, size_t datalen);
	virtual bool send_version()=0;
private:
	void reconnect(std::string disconnectReason);
	static void do_connect(P2PRelayer* me);
	void net_process();

public:
	void receive_transaction(const std::shared_ptr<std::vector<unsigned char> >& tx);
	void receive_block(std::vector<unsigned char>& block);
};

#endif
