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
template<class E> struct SharedPtrElem {
	std::shared_ptr<E> e;
	bool operator==(const SharedPtrElem<E>& o) const { return *e == *o.e; }
	bool operator!=(const SharedPtrElem<E>& o) const { return *e != *o.e; }
	bool operator< (const SharedPtrElem<E>& o) const { return *e <  *o.e; }
	bool operator<=(const SharedPtrElem<E>& o) const { return *e <= *o.e; }
	bool operator> (const SharedPtrElem<E>& o) const { return *e >  *o.e; }
	bool operator>=(const SharedPtrElem<E>& o) const { return *e >= *o.e; }
	SharedPtrElem(const std::shared_ptr<E>& eIn) : e(eIn) {}
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
					std::list<std::shared_ptr<std::vector<unsigned char> > > ptrlist;

					{
						std::lock_guard<std::mutex> lock(dedup_mutex);
						for (FlaggedArraySet* fas : allArraySets) {
							if (fas->allowDups)
								continue;
#ifdef FOR_TEST
							fas->mutex.lock();
#else
							if (!fas->mutex.try_lock())
								continue;
#endif
							std::lock_guard<WaitCountMutex> lock(fas->mutex, std::adopt_lock);
							for (const auto& e : fas->backingMap) {
								if (fas->mutex.wait_count())
									break;
								ptrlist.push_back(e.first.elem);
							}
						}
					}

					std::set<SharedPtrElem<std::vector<unsigned char> > > txset;
					std::map<std::vector<unsigned char>*, std::shared_ptr<std::vector<unsigned char> > > duplicateMap;
					std::list<std::shared_ptr<std::vector<unsigned char> > > deallocList;
					for (const auto& ptr : ptrlist) {
						auto res = txset.insert(SharedPtrElem<std::vector<unsigned char> >(ptr));
						if (!res.second && res.first->e != ptr)
							duplicateMap[&(*ptr)] = res.first->e;
					}

					int dedups = 0;
					{
						std::lock_guard<std::mutex> lock(dedup_mutex);
						for (FlaggedArraySet* fas : allArraySets) {
							if (fas->allowDups)
								continue;
#ifdef FOR_TEST
							fas->mutex.lock();
#else
							if (!fas->mutex.try_lock())
								continue;
#endif
							std::lock_guard<WaitCountMutex> lock(fas->mutex, std::adopt_lock);
							for (auto& e : fas->backingMap) {
								if (fas->mutex.wait_count())
									break;
								auto it = duplicateMap.find(&(*e.first.elem));
								if (it != duplicateMap.end()) {
									assert(*it->second == *e.first.elem);
									deallocList.emplace_back(it->second);
									const_cast<ElemAndFlag&>(e.first).elem.swap(deallocList.back());
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

bool FlaggedArraySet::contains(const std::shared_ptr<std::vector<unsigned char> >& e) { return backingMap.count(ElemAndFlag(e, false, allowDups)); }

void FlaggedArraySet::remove(std::map<uint64_t, std::unordered_map<ElemAndFlag, uint64_t>::iterator>::iterator rm) {
	uint64_t index = rm->first;
	if (rm->second->first.flag)
		flag_count--;

	ElemAndFlag e(rm->second->first);
	assert((e = rm->second->first).elem);
	assert(index == rm->second->second);
	assert(size() == total - offset);

	if (index != offset) {
		assert(offset < total && offset < index);
		#ifndef NDEBUG
			bool foundRmTarget = false;
		#endif
		for (uint64_t i = offset; i < total; i++) {
			std::map<uint64_t, std::unordered_map<ElemAndFlag, uint64_t>::iterator>::iterator it;
			assert((it = backingReverseMap.find(i)) != backingReverseMap.end());
			assert(it->second->second == i);
			assert(backingMap.find(it->second->first) == it->second);
			assert((it == rm && !foundRmTarget && (foundRmTarget = true)) || (it != rm));
			assert((it != rm && !(it->second->first == e)) || (it == rm && (it->second->first == e)));
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
			std::map<uint64_t, std::unordered_map<ElemAndFlag, uint64_t>::iterator>::iterator it;
			assert((it = backingReverseMap.find(i)) != backingReverseMap.end());
			assert(it->second->second == i);
			assert(backingMap.find(it->second->first) == it->second);
			assert(!(it->second->first == e));
		}
	} else {
		backingMap.erase(rm->second);
		backingReverseMap.erase(rm);
	}
	offset++;
}

void FlaggedArraySet::add(const std::shared_ptr<std::vector<unsigned char> >& e, bool flag) {
	std::lock_guard<WaitCountMutex> lock(mutex);

	auto res = backingMap.insert(std::make_pair(ElemAndFlag(e, flag, allowDups), total));
	if (!res.second)
		return;

	backingReverseMap[total++] = res.first;

	while (size() > maxSize)
		remove(backingReverseMap.begin());

	if (flag)
		flag_count++;
}

int FlaggedArraySet::remove(const std::shared_ptr<std::vector<unsigned char> >& e) {
	auto it = backingMap.find(ElemAndFlag(e, false, allowDups));
	if (it == backingMap.end())
		return -1;

	int res = it->second - offset;
	std::lock_guard<WaitCountMutex> lock(mutex);
	remove(backingReverseMap.find(it->second));
	return res;
}

std::shared_ptr<std::vector<unsigned char> > FlaggedArraySet::remove(int index) {
	auto it = backingReverseMap.find(index + offset);
	if (it == backingReverseMap.end())
		return std::make_shared<std::vector<unsigned char> >();

	std::lock_guard<WaitCountMutex> lock(mutex);
	std::shared_ptr<std::vector<unsigned char> > e = it->second->first.elem;
	remove(it);
	return e;
}

void FlaggedArraySet::clear() {
	std::lock_guard<WaitCountMutex> lock(mutex);
	flag_count = 0; total = 0; offset = 0;
	backingMap.clear(); backingReverseMap.clear();
}

void FlaggedArraySet::for_all_txn(const std::function<void (const std::shared_ptr<std::vector<unsigned char> >&)> callback) {
	std::lock_guard<WaitCountMutex> lock(mutex);
	for (const auto& e : backingReverseMap)
		callback(e.second->first.elem);
}
