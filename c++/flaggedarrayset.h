#ifndef _RELAY_FLAGGEDARRAYSET_H
#define _RELAY_FLAGGEDARRAYSET_H

#include <vector>
#include <thread>
#include <map>

/******************************
 **** FlaggedArraySet util ****
 ******************************/
struct ElemAndFlag {
	bool flag;
	std::shared_ptr<std::vector<unsigned char> > elem;
	ElemAndFlag(const std::shared_ptr<std::vector<unsigned char>>& elemIn, bool flagIn) : flag(flagIn), elem(elemIn) {}
	ElemAndFlag() {}
	bool operator <(const ElemAndFlag& o) const { return *elem < *o.elem; }
};



class FlaggedArraySet {
private:
	unsigned int maxSize, flag_count;
	uint64_t total, offset;
	std::map<ElemAndFlag, uint64_t> backingMap;
	std::map<uint64_t, std::map<ElemAndFlag, uint64_t>::iterator> backingReverseMap;

public:
	void clear();
	FlaggedArraySet(unsigned int maxSizeIn) : maxSize(maxSizeIn) { clear(); }

	size_t size() { return backingMap.size(); }
	size_t flagCount() { return flag_count; }
	bool contains(const std::shared_ptr<std::vector<unsigned char> >& e);

private:
	void remove(std::map<uint64_t, std::map<ElemAndFlag, uint64_t>::iterator>::iterator rm);

public:
	void add(const std::shared_ptr<std::vector<unsigned char> >& e, bool flag);
	int remove(const std::shared_ptr<std::vector<unsigned char> >& e);
	std::shared_ptr<std::vector<unsigned char> > remove(int index);

	void for_all_txn(const std::function<void (std::shared_ptr<std::vector<unsigned char> >)> callback);
};

#endif
