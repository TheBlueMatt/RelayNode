#include "preinclude.h"
#include "rpcclient.h"

#include <sstream>
#include <string.h>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>

#include "utils.h"

void RPCClient::on_disconnect() {
	connected = false;
	awaiting_response = false;
	std::lock_guard<std::mutex> lock(read_mutex);
	read_cv.notify_all();
}

void RPCClient::on_connect() {
	connected = true;
	read_thread = new std::thread([&]() { this->net_process(); });
}

void RPCClient::disconnect(const char* reason) {
	assert(std::this_thread::get_id() == ((std::thread*)read_thread)->get_id());
	std::thread([&]() {
		((std::thread*)read_thread)->join();
		delete read_thread;
		OutboundPersistentConnection::disconnect(reason);
	}).detach();
}

bool RPCClient::readable() {
	return total_inbound_size < sizeof(inbound_queue) - CONNECTION_MAX_READ_BYTES;
}

void RPCClient::recv_bytes(char* buf, size_t len) {
	assert(readable());
	assert(len <= CONNECTION_MAX_READ_BYTES);
	std::lock_guard<std::mutex> lock(read_mutex);

	size_t writepos = (readpos + total_inbound_size) % sizeof(inbound_queue);
	size_t writelen = std::min(len, sizeof(inbound_queue) - writepos);
	memcpy(inbound_queue + readpos, buf, writelen);

	if (writelen < len) {
		assert((writepos + writelen) % sizeof(inbound_queue) == 0);
		assert(len - writelen <= readpos);
		memcpy(inbound_queue, buf + writelen, len - writelen);
	}
	total_inbound_size += len;

	read_cv.notify_all();
}

ssize_t RPCClient::read_all(char *buf, size_t nbyte, millis_lu_type max_sleep) {
	size_t total = 0;
	std::chrono::system_clock::time_point stop_time;
	if (max_sleep == millis_lu_type::max())
		stop_time = std::chrono::system_clock::time_point::max();
	else
		stop_time = std::chrono::system_clock::now() + max_sleep;
	while (total < nbyte) {
		std::unique_lock<std::mutex> lock(read_mutex);
		while (connected && !total_inbound_size && std::chrono::system_clock::now() < stop_time)
			read_cv.wait_until(lock, stop_time);

		if (std::chrono::system_clock::now() >= stop_time)
			return total;

		if (!connected)
			return -1;

		size_t readamt = std::min({size_t(nbyte - total), size_t(total_inbound_size), size_t(sizeof(inbound_queue) - readpos)});
		memcpy(buf + total, inbound_queue + readpos, readamt);
		readpos = (readpos + readamt) % sizeof(inbound_queue);
		total += readamt;

		bool was_readable = readable();
		total_inbound_size -= readamt;
		if (!was_readable && readable())
			notify_readable_change();
	}
	assert(total == nbyte);
	return nbyte;
}

struct CTxMemPoolEntry {
	uint64_t feePerKb;
	uint32_t size;
	double prio;
	uint32_t reqCount;
	std::vector<unsigned char> hash;
	std::unordered_set<CTxMemPoolEntry*> setDeps;
	CTxMemPoolEntry(uint64_t feeIn, uint32_t sizeIn, double prioIn, std::vector<unsigned char> hashIn, uint32_t reqCountIn) : feePerKb(feeIn * 1000 / sizeIn), size(sizeIn), prio(prioIn), reqCount(reqCountIn), hash(hashIn) {
		//TODO: Parse hash?
	}
};

void RPCClient::net_process() {
	uint8_t count = 0;
	while (true) {
		int content_length = -2;
		bool close_after_read = false;
		int max_read;
		char buf[2048];
		std::string line;

		while (true) {
			std::string::size_type line_break;
			while ((line_break = line.find("\r\n")) == std::string::npos) {
				if (line.find("\r") != std::string::npos)
					max_read = 1;
				else
					max_read = 2;

				if (read_all(buf, max_read, std::chrono::seconds(10)) != max_read)
					return disconnect("Failed to read server response");
				line.append(buf, buf + max_read);

				if (line.length() > 16384)
					return disconnect("Got header longer than 16k!");
			}

			std::string current_line(line.substr(0, line_break));
			line = line.substr(line_break + 2);

			if (content_length == -2) {
				if (current_line != std::string("HTTP/1.1 200 OK"))
					return disconnect("Got HTTP error message: " + asciifyString(current_line));
				content_length++;
			} else if (current_line.length()) {
				std::string::size_type colon(current_line.find(':'));
				if (colon == std::string::npos)
					return disconnect("Got Bad HTTP header line: " + asciifyString(current_line));
				if (current_line.compare(0, strlen("Connection: "), "Connection: ") == 0) {
					if (current_line.compare(strlen("Connection: "), strlen("close"), "close") == 0)
						close_after_read = true;
					else if (current_line.compare(strlen("Connection: "), strlen("keep-alive"), "keep-alive") != 0)
						return disconnect("Got Bad HTTP Connection header line: " + asciifyString(current_line));
				} else if (current_line.compare(0, strlen("Content-Length: "), "Content-Length: ") == 0) {
					try {
						size_t endpos;
						content_length = std::stoi(&(current_line.c_str())[strlen("Content-Length: ")], &endpos);
						if (content_length < 0 || endpos != current_line.length() - strlen("Content-Length: "))
							return disconnect("Got Bad HTTP Content-Length header line: " + asciifyString(current_line));
					} catch (std::exception& e) {
						return disconnect("Got Bad HTTP Content-Length header line: " + asciifyString(current_line));
					}
				}
			} else if (content_length < 0)
				return disconnect("Got to end of HTTP headers without a Content-Length");
			else
				break;
		}

		if (content_length < 0 || content_length > 1024*1024*100)
			return disconnect("Got unreasonably large response size");

		//Dumb JSON parser that mostly assumes valid (minimal-size) JSON...
		static const std::string expected_start("{\"result\":{");
		{
			char resp[expected_start.length()];
			if (read_all(resp, expected_start.length()) != (ssize_t)expected_start.length())
				return disconnect("Failed to read response");
			if (memcmp(resp, &expected_start[0], expected_start.length()) != 0)
				return disconnect("Got result which was not an object");
		}

		std::vector<unsigned char> resp(content_length - expected_start.length());
		if (read_all((char*)&resp[0], content_length - expected_start.length()) != content_length - (ssize_t)expected_start.length())
			return disconnect("Failed to read response");
		auto it = resp.begin();

		//These do not move
		std::list<CTxMemPoolEntry> txn;
		//These index into txn
		std::vector<CTxMemPoolEntry*> vectorToSort;
		std::unordered_map<std::string, CTxMemPoolEntry*> hashToEntry;
		std::unordered_multimap<std::string, CTxMemPoolEntry*> txnWaitingOnDeps;

		// These are values/flags about the current status of the parser
		int32_t stringStart = -1, fieldValueStart = -1;
		std::string txHash, fieldString;
		long tx_size = -1; uint64_t tx_fee = -1; double tx_prio = -1;
		bool inTx = false, inFieldString = false, inFieldValue = false;
		std::unordered_set<std::string> txDeps;

		static const std::string expected_end("},\"error\":null,\"id\":1}\n");
		while (it < resp.end() - expected_end.length()) {
			while ((*it == ' ') && it < resp.end() - 1) it++;
			switch(*it) {
			case '"':
				if (stringStart != -1) {
					if (!inTx)
						txHash = std::string(resp.begin() + stringStart, it);
					else if (inFieldString)
						fieldString = std::string(resp.begin() + stringStart, it);
					else if (inFieldValue)
						return disconnect("got string as a field value");
					stringStart = -1;
				} else
					stringStart = it - resp.begin() + 1;
				break;
			case ':':
				if (stringStart != -1)
					return disconnect("Got : in a string (all strings should have been hex");
				if (inFieldString) {
					inFieldValue = true;
					inFieldString = false;
					fieldValueStart = it - resp.begin() + 1;
				} else if (inFieldValue)
					return disconnect("Got : in an unexpected place");
				break;
			case ',':
				if (stringStart != -1)
					return disconnect("Got , in a string (all strings should have been hex");
				if (inFieldValue) {
					inFieldValue = false;
					inFieldString = true;
					if (fieldString == "size") {
						try {
							tx_size = std::stol(std::string(resp.begin() + fieldValueStart, it));
						} catch (std::exception& e) {
							return disconnect("transaction size could not be parsed");
						}
					} else if (fieldString == "fee") {
						try {
							tx_fee = uint64_t(std::stod(std::string(resp.begin() + fieldValueStart, it)) * 100000000);
						} catch (std::exception& e) {
							return disconnect("transaction value could not be parsed");
						}
					} else if (fieldString == "currentpriority") {
						try {
							tx_prio = std::stod(std::string(resp.begin() + fieldValueStart, it));
						} catch (std::exception& e) {
							return disconnect("transaction prio could not be parsed");
						}
					}
				} else if (inTx)
					return disconnect("Got unexpected ,");
				break;
			case '[':
			{
				it++;
				int32_t depStringStart = -1;
				while (*it != ']' && it < resp.end() - 1) {
					if (*it == '"') {
						if (depStringStart != -1) {
							txDeps.insert(std::string(resp.begin() + depStringStart, it));
							depStringStart = -1;
						} else
							depStringStart = it - resp.begin() + 1;
					}
					it++;
				}
				if (*it != ']' || depStringStart != -1)
					return disconnect("Missing array end character (])");
				break;
			}
			case '{':
				if (stringStart != -1)
					return disconnect("Got { in a string (all strings should have been hex");
				else if (!inTx) {
					inTx = true;
					inFieldString = true;
				} else
					return disconnect("Got JSON object start when we weren't expecting one");
				break;
			case '}':
				if (inTx) {
					if (inFieldValue) {
						inFieldValue = false;
						if (fieldString == "size") {
							try {
								tx_size = std::stol(std::string(resp.begin() + fieldValueStart, it));
							} catch (std::exception& e) {
								return disconnect("transaction size could not be parsed");
							}
						} else if (fieldString == "fee") {
							try {
								tx_fee = uint64_t(std::stod(std::string(resp.begin() + fieldValueStart, it)) * 100000000);
							} catch (std::exception& e) {
								return disconnect("transaction value could not be parsed");
							}
						} else if (fieldString == "currentpriority") {
							try {
								tx_prio = std::stod(std::string(resp.begin() + fieldValueStart, it));
							} catch (std::exception& e) {
								return disconnect("transaction prio could not be parsed");
							}
						}
					} else
						return disconnect("Got unepxecpted }");

					if (tx_size < 0)
						return disconnect("Did not get transaction size");
					else if (tx_fee < 0)
						return disconnect("Did not get transaction fee");
					else if (tx_prio < 0)
						return disconnect("Did not get transaction prio");

					std::vector<unsigned char> hash;
					if (!hex_str_to_reverse_vector(txHash, hash) || hash.size() != 32)
						return disconnect("got bad hash");

					txn.emplace_back(tx_fee, tx_size, tx_prio, hash, txDeps.size());
					if (!hashToEntry.insert(std::make_pair(txHash, &txn.back())).second)
						return disconnect("Duplicate transaction");

					if (txDeps.empty())
						vectorToSort.push_back(&txn.back());
					else {
						for (const std::string& dep : txDeps) {
							auto depIt = hashToEntry.find(dep);
							if (depIt == hashToEntry.end())
								txnWaitingOnDeps.insert(std::make_pair(dep, &txn.back()));
							else
								depIt->second->setDeps.insert(&txn.back());
						}
					}

					auto waitingIts = txnWaitingOnDeps.equal_range(txHash);
					for (auto waitingIt = waitingIts.first; waitingIt != waitingIts.second; waitingIt++)
						txn.back().setDeps.insert(waitingIt->second);
					txnWaitingOnDeps.erase(txHash);

					inTx = false;
					tx_size = -1;
					tx_fee = -1;
					txDeps.clear();
				} else
					return disconnect("Global JSON object closed before the end");
				break;
			}
			it++;
		}
		if (it != resp.end() - expected_end.length() || memcmp(&(*it), &expected_end[0], expected_end.length()) != 0)
			return disconnect("JSON object was not closed at the end");

		if (!txnWaitingOnDeps.empty())
			return disconnect("Tx depended on another one which did not exist");

		std::vector<std::pair<std::vector<unsigned char>, size_t> > txn_selected;
		std::function<bool (const CTxMemPoolEntry* a, const CTxMemPoolEntry* b)> comp = [](const CTxMemPoolEntry* a, const CTxMemPoolEntry* b) {
			return a->feePerKb < b->feePerKb || (a->feePerKb == b->feePerKb && a->prio < b->prio);
		};
		std::make_heap(vectorToSort.begin(), vectorToSort.end(), comp);

		uint64_t minFeePerKbSelected = 4000000000;
		unsigned minFeePerKbTxnCount = 0;
		uint64_t totalSizeSelected = 0;
		while (totalSizeSelected < 9*MAX_FAS_TOTAL_SIZE/10 && vectorToSort.size()) {
			std::pop_heap(vectorToSort.begin(), vectorToSort.end(), comp);
			CTxMemPoolEntry* e = vectorToSort.back();
			vectorToSort.pop_back();
			if (e->size <= MAX_RELAY_TRANSACTION_BYTES) {
				for (CTxMemPoolEntry* dep : e->setDeps)
					if ((--dep->reqCount) == 0) {
						vectorToSort.push_back(dep);
						std::push_heap(vectorToSort.begin(), vectorToSort.end(), comp);
					}
				txn_selected.push_back(std::make_pair(e->hash, e->size));
				totalSizeSelected += e->size;
				if (e->feePerKb == minFeePerKbSelected)
					minFeePerKbTxnCount++;
				else if (e->feePerKb < minFeePerKbSelected) {
					minFeePerKbSelected = e->feePerKb;
					minFeePerKbTxnCount = 1;
				}
			}
		}

		unsigned minFeePerKbTxnSkipped = 0;
		while (vectorToSort.size()) {
			std::pop_heap(vectorToSort.begin(), vectorToSort.end(), comp);
			CTxMemPoolEntry* e = vectorToSort.back();
			vectorToSort.pop_back();
			if (e->feePerKb != minFeePerKbSelected)
				break;
			minFeePerKbTxnSkipped++;
		}

		if (++count == 0 && minFeePerKbTxnSkipped > 1 && minFeePerKbTxnCount > 1)
			printf("WARNING: Skipped %u txn while accepting %u identical-fee txn\n", minFeePerKbTxnSkipped, minFeePerKbTxnCount);

		txn_for_block_func(txn_selected, txn.size());
		awaiting_response = false;

		if (close_after_read)
			return disconnect("Got Connection: close");
	}
}

//Stolen from Bitcoin
static std::string EncodeBase64(const std::string& str)
{
	static const char *pbase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	std::string strRet="";
	strRet.reserve((str.length()+2)/3*4);

	int mode=0, left=0;
	const unsigned char *pch = (unsigned char*) &str[0];
	const unsigned char *pchEnd = (unsigned char*) &str[str.length()];

	while (pch<pchEnd)
	{
		int enc = *(pch++);
		switch (mode)
		{
			case 0: // we have no bits
				strRet += pbase64[enc >> 2];
				left = (enc & 3) << 4;
				mode = 1;
				break;

			case 1: // we have two bits
				strRet += pbase64[left | (enc >> 4)];
				left = (enc & 15) << 2;
				mode = 2;
				break;

			case 2: // we have four bits
				strRet += pbase64[left | (enc >> 6)];
				strRet += pbase64[enc & 63];
				mode = 0;
				break;
		}
	}

	if (mode)
	{
		strRet += pbase64[left];
		strRet += '=';
		if (mode == 1)
			strRet += '=';
	}

	return strRet;
}

void RPCClient::maybe_get_txn_for_block() {
	if (!connected || awaiting_response.exchange(true))
		return;

	std::ostringstream obj;
	obj << "{"
		<< "\"method\": \"getrawmempool\","
		<< "\"params\": [ true ],"
		<< "\"id\": 1"
		<< "}";

	std::ostringstream req;
	req << "POST / HTTP/1.1\r\n"
		<< "User-Agent: RelayNetworkServer/42\r\n"
		<< "Host: " << serverHost << "\r\n"
		<< "Content-Type: application/json\r\n"
		<< "Content-Length: " << obj.str().length() << "\r\n"
		<< "Connection: keep-alive\r\n"
		<< "Accept: application/json\r\n"
		<< "Authorization: Basic " << EncodeBase64(std::string(getenv("RPC_USER")) + ":" + getenv("RPC_PASS"))
		<< "\r\n\r\n"
		<< obj.str();
	std::string bytes(req.str());
	maybe_do_send_bytes(bytes.c_str(), bytes.length());
}
