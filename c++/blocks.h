#ifndef _RELAY_BLOCKS_H
#define _RELAY_BLOCKS_H

#include <vector>

bool got_block_has_been_relayed(const std::vector<unsigned char>& hash);
const char* is_block_sane(const std::vector<unsigned char>& hash, std::vector<unsigned char>::const_iterator start, std::vector<unsigned char>::const_iterator end);
bool recv_headers_msg_from_trusted(const std::vector<unsigned char>);

#endif
