#include "flaggedarrayset.h"

#include <map>
#include <set>
#include <vector>
#include <list>
#include <thread>
#include <mutex>
#include <assert.h>

#include <stdio.h>

/******************************
 **** FlaggedArraySet util ****
 ******************************/
struct PtrPair {
	std::shared_ptr<std::vector<unsigned char> > elem;
	std::shared_ptr<std::vector<unsigned char> > elemHash;
	PtrPair(const std::shared_ptr<std::vector<unsigned char> >& elemIn, const std::shared_ptr<std::vector<unsigned char> >& elemHashIn) :
		elem(elemIn), elemHash(elemHashIn) {}
};

struct SharedPtrElem {
	PtrPair e;
	bool operator==(const SharedPtrElem& o) const { return *e.elemHash == *o.e.elemHash; }
	bool operator!=(const SharedPtrElem& o) const { return *e.elemHash != *o.e.elemHash; }
	bool operator< (const SharedPtrElem& o) const { return *e.elemHash <  *o.e.elemHash; }
	bool operator<=(const SharedPtrElem& o) const { return *e.elemHash <= *o.e.elemHash; }
	bool operator> (const SharedPtrElem& o) const { return *e.elemHash >  *o.e.elemHash; }
	bool operator>=(const SharedPtrElem& o) const { return *e.elemHash >= *o.e.elemHash; }
	SharedPtrElem(const PtrPair& eIn) : e(eIn) {}
};

class Deduper {
private:
	std::mutex dedup_mutex;
	std::set<FlaggedArraySet*> allArraySets;
	std::thread dedup_thread;
public:
	Deduper()
		: dedup_thread([&]() {
			while (true) {
				if (allArraySets.size() > 1) {
					std::list<PtrPair> ptrlist;

					{
						std::lock_guard<std::mutex> lock(dedup_mutex);
						for (FlaggedArraySet* fas : allArraySets) {
							if (fas->allowDups)
								continue;
							if (!fas->mutex.try_lock())
								continue;
							std::lock_guard<WaitCountMutex> lock(fas->mutex, std::adopt_lock);
							for (const auto& e : fas->backingMap) {
								if (fas->mutex.wait_count())
									break;
								ptrlist.push_back(PtrPair(e.first.elem, e.first.elemHash));
							}
						}
					}

					std::set<SharedPtrElem> txset;
					std::map<std::vector<unsigned char>*, PtrPair> duplicateMap;
					std::list<PtrPair> deallocList;
					for (const auto& ptr : ptrlist) {
						assert(ptr.elemHash);
						auto res = txset.insert(SharedPtrElem(ptr));
						if (!res.second && res.first->e.elem != ptr.elem)
							duplicateMap.insert(std::make_pair(&(*ptr.elem), res.first->e));
					}

					int dedups = 0;
					{
						std::lock_guard<std::mutex> lock(dedup_mutex);
						for (FlaggedArraySet* fas : allArraySets) {
							if (fas->allowDups)
								continue;
							if (!fas->mutex.try_lock())
								continue;
							std::lock_guard<WaitCountMutex> lock(fas->mutex, std::adopt_lock);
							for (auto& e : fas->backingMap) {
								if (fas->mutex.wait_count())
									break;
								auto it = duplicateMap.find(&(*e.first.elem));
								if (it != duplicateMap.end()) {
									assert(*it->second.elem == *e.first.elem);
									assert(*it->second.elemHash == *e.first.elemHash);
									deallocList.emplace_back(it->second);
									const_cast<ElemAndFlag&>(e.first).elem.swap(deallocList.back().elem);
									const_cast<ElemAndFlag&>(e.first).elemHash.swap(deallocList.back().elemHash);
									dedups++;
								}
							}
						}
					}
#ifdef FOR_TEST
					if (dedups)
						printf("Deduped %d txn\n", dedups);
#endif
				}
#ifdef FOR_TEST
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
#else
				std::this_thread::sleep_for(std::chrono::milliseconds(5000));
#endif
			}
		})
	{}

	~Deduper() {
		//TODO: close thread
	}

	void addFAS(FlaggedArraySet* fas) {
		std::lock_guard<std::mutex> lock(dedup_mutex);
		allArraySets.insert(fas);
	}

	void removeFAS(FlaggedArraySet* fas) {
		std::lock_guard<std::mutex> lock(dedup_mutex);
		allArraySets.erase(fas);
	}
};

static Deduper* deduper;

FlaggedArraySet::FlaggedArraySet(unsigned int maxSizeIn, bool allowDupsIn) :
		maxSize(maxSizeIn), backingMap(maxSize), allowDups(allowDupsIn) {
	clear();
	if (!deduper)
		deduper = new Deduper();
	deduper->addFAS(this);
}

FlaggedArraySet::~FlaggedArraySet() {
	deduper->removeFAS(this);
}

bool FlaggedArraySet::contains(const std::shared_ptr<std::vector<unsigned char> >& e) const { return backingMap.count(ElemAndFlag(e, false, allowDups, false)); }

void FlaggedArraySet::remove_(size_t index) {
	auto& rm = indexMap[index];
	if (rm->first.flag)
		flag_count--;

#ifndef NDEBUG
	assert(indexMap.size() == size() && size() == backingMap.size());
	assert(index < indexMap.size());
	ElemAndFlag e(rm->first);
	assert((e = rm->first).elem);
	assert(index + offset == rm->second);
#endif

	size_t size = this->size();

#ifndef NDEBUG
	bool foundRmTarget = false;
	for (uint64_t i = 0; i < size; i++) {
		std::unordered_map<ElemAndFlag, uint64_t>::iterator it;
		assert((it = indexMap.at(i)) != backingMap.end());
		assert(it->second == i + offset);
		assert((i == index && !foundRmTarget && (foundRmTarget = true)) || (i != index));
		assert((i != index && !(it->first == e)) || (i == index && (it->first == e)));
	}
	assert(foundRmTarget);
#endif

	if (index < size/2) {
		for (uint64_t i = 0; i < index; i++)
			indexMap[i]->second++;
		offset++;
	} else
		for (uint64_t i = index + 1; i < size; i++)
			indexMap[i]->second--;
	backingMap.erase(rm);
	indexMap.erase(indexMap.begin() + index);
	size--;

#ifndef NDEBUG
	for (uint64_t i = 0; i < size; i++) {
		std::unordered_map<ElemAndFlag, uint64_t>::iterator it;
		assert((it = indexMap.at(i)) != backingMap.end());
		assert(it->second == i + offset);
		assert(!(it->first == e));
	}
#endif
}

void FlaggedArraySet::add(const std::shared_ptr<std::vector<unsigned char> >& e, bool flag) {
	ElemAndFlag elem(e, flag, allowDups, true);
	std::lock_guard<WaitCountMutex> lock(mutex);

	auto res = backingMap.insert(std::make_pair(elem, size() + offset));
	if (!res.second)
		return;

	indexMap.push_back(res.first);

	assert(size() <= maxSize + 1);
	while (size() > maxSize)
		remove_(0);

	if (flag)
		flag_count++;
}

int FlaggedArraySet::remove(const std::shared_ptr<std::vector<unsigned char> >& e) {
	auto it = backingMap.find(ElemAndFlag(e, false, allowDups, false));
	if (it == backingMap.end())
		return -1;

	int res = it->second - offset;
	std::lock_guard<WaitCountMutex> lock(mutex);
	remove_(res);
	return res;
}

bool FlaggedArraySet::remove(int index, std::shared_ptr<std::vector<unsigned char> >& elem, std::shared_ptr<std::vector<unsigned char> >& elemHash) {
	if ((unsigned int)index >= indexMap.size())
		return false;

	std::lock_guard<WaitCountMutex> lock(mutex);
	const ElemAndFlag& e = indexMap[index]->first;
	elem = e.elem;
	elemHash = e.elemHash;

	remove_(index);
	return true;
}

void FlaggedArraySet::clear() {
	std::lock_guard<WaitCountMutex> lock(mutex);
	flag_count = 0; offset = 0;
	backingMap.clear(); indexMap.clear();
}

void FlaggedArraySet::for_all_txn(const std::function<void (const std::shared_ptr<std::vector<unsigned char> >&)> callback) const {
	std::lock_guard<WaitCountMutex> lock(mutex);
	for (const auto& e : indexMap)
		callback(e->first.elem);
}
