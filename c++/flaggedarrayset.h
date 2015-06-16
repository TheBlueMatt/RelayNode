#ifndef _RELAY_FLAGGEDARRAYSET_H
#define _RELAY_FLAGGEDARRAYSET_H

#include <vector>
#include <thread>
#include <map>
#include <unordered_map>

/******************************
 **** FlaggedArraySet util ****
 ******************************/
struct ElemAndFlag {
	bool flag;
	std::shared_ptr<std::vector<unsigned char> > elem;
	bool allowDups;
	ElemAndFlag(const std::shared_ptr<std::vector<unsigned char>>& elemIn, bool flagIn, bool allowDupsIn) : flag(flagIn), elem(elemIn), allowDups(allowDupsIn) {}
	ElemAndFlag(bool allowDupsIn) : allowDups(allowDupsIn) {}
	bool operator == (const ElemAndFlag& o) const { if (allowDups) return o.elem == elem; return *o.elem == *elem; }
};

namespace std {
	template <> struct hash<ElemAndFlag> {
		size_t operator()(const ElemAndFlag& e) const {
			std::vector<unsigned char>& v = *e.elem;
			if (v.size() < 5 + 32 + 4)
				return 42; // WAT?
			size_t res = 0;
			static_assert(sizeof(size_t) == 4 || sizeof(size_t) == 8, "Your size_t is neither 32-bit nor 64-bit?");
			for (unsigned int i = (5 + 32 + 4) - 8; i < 5 + 32 + 4; i += sizeof(size_t)) {
				for (unsigned int j = 0; j < sizeof(size_t); j++)
					res ^= v[i+j] << 8*j;
			}
			return res;
		}
	};
}


class FlaggedArraySet {
private:
	unsigned int maxSize, flag_count;
	uint64_t total, offset;
	std::unordered_map<ElemAndFlag, uint64_t> backingMap;
	std::map<uint64_t, std::unordered_map<ElemAndFlag, uint64_t>::iterator> backingReverseMap;
	bool allowDups;

public:
	void clear();
	FlaggedArraySet(unsigned int maxSizeIn, bool allowDupsIn) : maxSize(maxSizeIn), backingMap(maxSize), allowDups(allowDupsIn) { clear(); }

	size_t size() { return backingMap.size(); }
	size_t flagCount() { return flag_count; }
	bool contains(const std::shared_ptr<std::vector<unsigned char> >& e);

private:
	void remove(std::map<uint64_t, std::unordered_map<ElemAndFlag, uint64_t>::iterator>::iterator rm);

public:
	void add(const std::shared_ptr<std::vector<unsigned char> >& e, bool flag);
	int remove(const std::shared_ptr<std::vector<unsigned char> >& e);
	std::shared_ptr<std::vector<unsigned char> > remove(int index);

	void for_all_txn(const std::function<void (const std::shared_ptr<std::vector<unsigned char> >&)> callback);
};

#endif
