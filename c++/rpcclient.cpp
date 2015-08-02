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
}

void RPCClient::net_process(const std::function<void(std::string)>& disconnect) {
	connected = true;

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
		static const std::string expected_start("{\"result\":{\"capabilities\":[\"proposal\"],\"version\":3,\"previousblockhash\":\"");
		static const std::string expected_second_start("\",\"transactions\":[");
		static const uint32_t total_expected_start = expected_start.length() + 64 + expected_second_start.length();
		{
			char resp[expected_start.length() + 1];
			if (read_all(resp, expected_start.length()) != (ssize_t)expected_start.length())
				return disconnect("Failed to read response");
			if (memcmp(resp, &expected_start[0], expected_start.length()) != 0)
				return disconnect("Got result which was not an object");

			if (read_all(resp, 64) != 64)
				return disconnect("Failed to read response");

			if (read_all(resp, expected_second_start.length()) != (ssize_t)expected_second_start.length())
				return disconnect("Failed to read response");
			if (memcmp(resp, &expected_second_start[0], expected_second_start.length()) != 0)
				return disconnect("Got result which was not an object");
		}

		std::vector<unsigned char> resp(content_length - total_expected_start);
		if (read_all((char*)&resp[0], content_length - total_expected_start) != content_length - total_expected_start)
			return disconnect("Failed to read response");
		auto it = resp.begin();

		std::vector<std::vector<unsigned char> > txn_hashes;

		bool inTx = false, done = false, inFieldString = false, inFieldValue = false;
		int32_t stringStart = -1;
		std::string fieldString;

		while (it < resp.end() && !done) {
			switch(*it) {
			case '{':
				if (stringStart != -1)
					return disconnect("Got { in a string (all strings should have been hex");
				if (!inTx) {
					inTx = true;
					inFieldString = true;
				} else
					return disconnect("Got unexpected { token");
				break;
			case '}':
				if (stringStart != -1)
					return disconnect("Got } in a string (all strings should have been hex");
				if (inTx)
					inTx = false;
				else
					return disconnect("Got unexpected } token");
				break;

			case '[':
				return disconnect("Got unexpected [ token");
			case ']':
				done = true;
				break;

			case '"':
				if (stringStart != -1) {
					if (!inTx)
						return disconnect("Got unexpected \" token");
					else if (inFieldString)
						fieldString = std::string(resp.begin() + stringStart, it);
					else if (inFieldValue && fieldString == "hash") {
						std::vector<unsigned char> hash;
						if (!hex_str_to_reverse_vector(std::string(resp.begin() + stringStart, it), hash) || hash.size() != 32)
							return disconnect("got bad hash");
						txn_hashes.push_back(hash);
					}
					stringStart = -1;
				} else
					stringStart = it - resp.begin() + 1;
				break;

			case ':':
				if (stringStart != -1)
					return disconnect("Got : in a string (all strings should have been hex");
				if (inFieldString) {
					inFieldString = false;
					inFieldValue = true;
					if (fieldString == "depends") {
						it++;
						if (*it != '[')
							return disconnect("Missing [ token");
						while (it < resp.end() && *it != ']')
							it++;
						if (*it != ']')
							return disconnect("Missing ] token");
					}
				} else if (inFieldValue)
					return disconnect("Got unexpected : token");
				break;

			case ',':
				if (stringStart != -1)
					return disconnect("Got , in a string (all strings should have been hex");
				if (inFieldValue) {
					inFieldValue = false;
					inFieldString = true;
				} else if (inTx)
					return disconnect("Got unexpected , token");
			}
			it++;
		}

		txn_for_block_func(txn_hashes);
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
		<< "\"method\": \"getblocktemplate\","
		<< "\"params\": [ ],"
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
