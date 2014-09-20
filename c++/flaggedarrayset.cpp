#include "flaggedarrayset.h"

#include <map>
#include <vector>
#include <thread>
#include <assert.h>

/******************************
 **** FlaggedArraySet util ****
 ******************************/
bool FlaggedArraySet::contains(const std::shared_ptr<std::vector<unsigned char> >& e) { return backingMap.count(ElemAndFlag(e, false)); }

void FlaggedArraySet::remove(std::map<uint64_t, std::map<ElemAndFlag, uint64_t>::iterator>::iterator rm) {
	uint64_t index = rm->first;
	if (rm->second->first.flag)
		flag_count--;

	ElemAndFlag e;
	assert((e = rm->second->first).elem);
	assert(index == rm->second->second);
	assert(size() == total - offset);

	if (index != offset) {
		assert(offset < total && offset < index);
		#ifndef NDEBUG
			bool foundRmTarget = false;
		#endif
		for (uint64_t i = offset; i < total; i++) {
			std::map<uint64_t, std::map<ElemAndFlag, uint64_t>::iterator>::iterator it;
			assert((it = backingReverseMap.find(i)) != backingReverseMap.end());
			assert(it->second->second == i);
			assert(backingMap.find(it->second->first) == it->second);
			assert((it == rm && !foundRmTarget && (foundRmTarget = true)) || (it != rm));
			assert((it != rm && (it->second->first < e || e < it->second->first)) || (it == rm && !(it->second->first < e || e < it->second->first)));
		}
		assert(foundRmTarget);

		auto last = rm; last++;
		auto it = backingReverseMap.find(offset);
		auto elem = it->second;
		it = backingReverseMap.erase(it);
		backingMap.erase(rm->second);
		for (; it != last; it++) {
			auto new_elem = it->second;
			elem->second++;
			it->second = elem;
			elem = new_elem;
		}

		for (uint64_t i = offset + 1; i < total; i++) {
			std::map<uint64_t, std::map<ElemAndFlag, uint64_t>::iterator>::iterator it;
			assert((it = backingReverseMap.find(i)) != backingReverseMap.end());
			assert(it->second->second == i);
			assert(backingMap.find(it->second->first) == it->second);
			assert(it->second->first < e || e < it->second->first);
		}
	} else {
		backingMap.erase(rm->second);
		backingReverseMap.erase(rm);
	}
	offset++;
}

void FlaggedArraySet::add(const std::shared_ptr<std::vector<unsigned char> >& e, bool flag) {
	auto res = backingMap.insert(std::make_pair(ElemAndFlag(e, flag), total));
	if (!res.second)
		return;

	backingReverseMap[total++] = res.first;

	while (size() > maxSize)
		remove(backingReverseMap.begin());

	if (flag)
		flag_count++;
}

int FlaggedArraySet::remove(const std::shared_ptr<std::vector<unsigned char> >& e) {
	auto it = backingMap.find(ElemAndFlag(e, false));
	if (it == backingMap.end())
		return -1;

	int res = it->second - offset;
	remove(backingReverseMap.find(it->second));
	return res;
}

std::shared_ptr<std::vector<unsigned char> > FlaggedArraySet::remove(int index) {
	auto it = backingReverseMap.find(index + offset);
	if (it == backingReverseMap.end())
		return std::make_shared<std::vector<unsigned char> >();

	std::shared_ptr<std::vector<unsigned char> > e = it->second->first.elem;
	remove(it);
	return e;
}

void FlaggedArraySet::clear() {
	flag_count = 0; total = 0; offset = 0;
	backingMap.clear(); backingReverseMap.clear();
}

void FlaggedArraySet::for_all_txn(const std::function<void (std::shared_ptr<std::vector<unsigned char> >)> callback) {
	for (std::pair<const uint64_t, std::map<ElemAndFlag, uint64_t>::iterator>& e : backingReverseMap)
		callback(e.second->first.elem);
}
