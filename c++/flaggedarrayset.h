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
	ElemAndFlag(const std::shared_ptr<std::vector<unsigned char>>& elemIn, bool flagIn) : flag(flagIn), elem(elemIn) {}
	ElemAndFlag() {}
	bool operator == (const ElemAndFlag& o) const { return o.elem == elem; }
};
namespace std {
	template <> struct hash<ElemAndFlag> {
		size_t operator()(const ElemAndFlag& e) const {
			//Stolen from boost::hash_range
			size_t res = 0;
			for (const auto& v : *e.elem)
				res ^= v + 0x9e3779b9 + (res << 6) + (res >> 2);
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

public:
	void clear();
	FlaggedArraySet(unsigned int maxSizeIn) : maxSize(maxSizeIn), backingMap(maxSize) { clear(); }

	size_t size() { return backingMap.size(); }
	size_t flagCount() { return flag_count; }
	bool contains(const std::shared_ptr<std::vector<unsigned char> >& e);

private:
	void remove(std::map<uint64_t, std::unordered_map<ElemAndFlag, uint64_t>::iterator>::iterator rm);

public:
	void add(const std::shared_ptr<std::vector<unsigned char> >& e, bool flag);
	int remove(const std::shared_ptr<std::vector<unsigned char> >& e);
	std::shared_ptr<std::vector<unsigned char> > remove(int index);

	void for_all_txn(const std::function<void (std::shared_ptr<std::vector<unsigned char> >)> callback);
};

#endif
