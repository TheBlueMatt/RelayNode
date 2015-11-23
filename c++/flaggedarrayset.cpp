#include "preinclude.h"

#include "flaggedarrayset.h"

#include <map>
#include <set>
#include <vector>
#include <list>
#include <thread>
#include <mutex>
#include <string.h>
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
#ifdef PRECISE_BENCH
			return;
#endif
			while (true) {
				bool haveMultipleSets = false;
				{
					std::lock_guard<std::mutex> lock(dedup_mutex);
					haveMultipleSets = allArraySets.size() > 1;
				}

				if (haveMultipleSets) {
					std::list<PtrPair> ptrlist;

					{
						std::lock_guard<std::mutex> lock(dedup_mutex);
						for (FlaggedArraySet* fas : allArraySets) {
							if (!fas->mutex.try_lock())
								continue;
							std::lock_guard<WaitCountMutex> lock(fas->mutex, std::adopt_lock);
							for (const auto& e : fas->backingMap) {
								if (fas->mutex.wait_count())
									break;
								assert(e.first.elem);
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
							if (!fas->mutex.try_lock())
								continue;
							std::lock_guard<WaitCountMutex> lock(fas->mutex, std::adopt_lock);
							for (auto& e : fas->backingMap) {
								if (fas->mutex.wait_count())
									break;
								assert(e.first.elem);
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
				}
#ifdef FOR_TEST
				std::this_thread::sleep_for(std::chrono::milliseconds(5));
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

FlaggedArraySet::FlaggedArraySet(uint64_t maxSizeIn, uint64_t maxFlagCountIn) :
		maxSize(maxSizeIn), maxFlagCount(maxFlagCountIn), backingMap(maxSize) {
	clear();
	if (!deduper)
		deduper = new Deduper();
	deduper->addFAS(this);
}

FlaggedArraySet::~FlaggedArraySet() {
	deduper->removeFAS(this);
	assert(sanity_check());
}

FlaggedArraySet& FlaggedArraySet::operator=(const FlaggedArraySet& o) {
	std::unique_lock<WaitCountMutex> lock(mutex, std::defer_lock);
	std::unique_lock<WaitCountMutex> lock2(o.mutex, std::defer_lock);
	std::lock(lock, lock2);

	o.cleanup_late_remove();
	_clear(false);

	maxSize = o.maxSize;
	maxFlagCount = o.maxFlagCount;
	flag_count = o.flag_count;
	offset = o.offset;
	backingMap = o.backingMap;
	indexMap = o.indexMap;
	return *this;
}


ElemAndFlag::ElemAndFlag(const std::shared_ptr<std::vector<unsigned char> >& elemIn, uint32_t flagIn, bool setHash) :
	flag(flagIn), elem(elemIn)
{
	if (setHash) {
		elemHash = std::make_shared<std::vector<unsigned char> >(32);
		double_sha256(&(*elem)[0], &(*elemHash)[0], elem->size());
	}
}
ElemAndFlag::ElemAndFlag(const std::shared_ptr<std::vector<unsigned char> >& elemHashIn, std::nullptr_t) :
	elemHash(elemHashIn) {}
ElemAndFlag::ElemAndFlag(const unsigned char* elemBeginIn, const unsigned char* elemEndIn, uint32_t flagIn) :
	flag(flagIn), elemBegin(elemBeginIn), elemEnd(elemEndIn) {}

bool ElemAndFlag::operator == (const ElemAndFlag& o) const {
	if ((elem && o.elem) || (elemHash && o.elemHash)) {
		bool hashSet = o.elemHash && elemHash;
		return o.elem == elem ||
			(hashSet && *o.elemHash == *elemHash) ||
			(!hashSet && *o.elem == *elem);
	} else {
		const unsigned char *o_begin, *o_end, *e_begin, *e_end;
		if (elem) {
			e_begin = &(*elem)[0];
			e_end = &(*elem->end());
		} else {
			e_begin = elemBegin;
			e_end = elemEnd;
		}
		if (o.elem) {
			o_begin = &(*o.elem)[0];
			o_end = &(*o.elem->end());
		} else {
			o_begin = o.elemBegin;
			o_end = o.elemEnd;
		}
		return o_end - o_begin == e_end - e_begin && !memcmp(&(*o_begin), &(*e_begin), o_end - o_begin);
	}
}

size_t std::hash<ElemAndFlag>::operator()(const ElemAndFlag& e) const {
	const unsigned char *it, *end;
	if (e.elem) {
		it = &(*e.elem)[0];
		end = &(*e.elem->end());
	} else {
		it = e.elemBegin;
		end = e.elemEnd;
	}

	if (end - it < 5 + 32 + 4) {
		assert(0);
		return 42; // WAT?
	}
	it += 5 + 32 + 4 - 8;
	size_t res = 0;
	static_assert(sizeof(size_t) == 4 || sizeof(size_t) == 8, "Your size_t is neither 32-bit nor 64-bit?");
	for (unsigned int i = 0; i < 8; i += sizeof(size_t)) {
		for (unsigned int j = 0; j < sizeof(size_t); j++)
			res ^= *(it + i + j) << 8*j;
	}
	return res;
}


bool FlaggedArraySet::sanity_check() const {
	size_t size = indexMap.size();
	assert(backingMap.size() == size);
	assert(this->size() == size - to_be_removed.size());

	uint64_t expected_flag_count = 0;
	for (uint64_t i = 0; i < size; i++) {
		std::unordered_map<ElemAndFlag, uint64_t>::iterator it = indexMap.at(i);
		assert(it != backingMap.end());
		assert(it->second == i + offset);
		assert(backingMap.find(it->first) == it);
		assert(&backingMap.find(it->first)->first == &it->first);
		expected_flag_count += it->first.flag;
	}
	assert(expected_flag_count == flag_count);

	uint64_t expected_flags_removed = 0;
	for (size_t i = 0; i < to_be_removed.size(); i++) {
		std::unordered_map<ElemAndFlag, uint64_t>::iterator it = indexMap.at(to_be_removed[i] + i);
		expected_flags_removed += it->first.flag;
	}
	assert(expected_flags_removed == flags_to_remove);

	assert(this->size() <= maxSize);
	assert(flagCount() <= maxFlagCount);

	return expected_flags_removed == flags_to_remove && expected_flag_count == flag_count;
}

void FlaggedArraySet::remove_(size_t index) {
	auto& rm = indexMap[index];
	assert(index < indexMap.size());
	flag_count -= rm->first.flag;

	size_t size = backingMap.size();

	if (index < size/2) {
		for (uint64_t i = 0; i < index; i++)
			indexMap[i]->second++;
		offset++;
	} else
		for (uint64_t i = index + 1; i < size; i++)
			indexMap[i]->second--;
	backingMap.erase(rm);
	indexMap.erase(indexMap.begin() + index);
}

void FlaggedArraySet::cleanup_late_remove() const {
	assert(sanity_check());
	if (to_be_removed.size()) {
		for (unsigned int i = 0; i < to_be_removed.size(); i++) {
			assert((unsigned int)to_be_removed[i] < indexMap.size());
			const_cast<FlaggedArraySet*>(this)->remove_(to_be_removed[i]);
		}
		to_be_removed.clear();
		flags_to_remove = 0;
		max_remove = 0;
	}
	assert(sanity_check());
}

bool FlaggedArraySet::contains(const std::shared_ptr<std::vector<unsigned char> >& e) const {
	std::lock_guard<WaitCountMutex> lock(mutex);
	cleanup_late_remove();
	return backingMap.count(ElemAndFlag(e, 0, false));
}

bool FlaggedArraySet::contains(const unsigned char* elemHash) const {
	//TODO: Come up with a cheap way to optimize this?
	std::lock_guard<WaitCountMutex> lock(mutex);
	cleanup_late_remove();
	ElemAndFlag e(std::make_shared<std::vector<unsigned char> >(elemHash, elemHash + 32), NULL);
	for (const std::unordered_map<ElemAndFlag, uint64_t>::iterator& it : indexMap) {
		assert(it->first.elemHash && e.elemHash);
		if (it->first == e)
			return true;
	}
	return false;
}

void FlaggedArraySet::add(const std::shared_ptr<std::vector<unsigned char> >& e, uint32_t flag) {
	ElemAndFlag elem(e, flag, true);

	std::lock_guard<WaitCountMutex> lock(mutex);
	cleanup_late_remove();

	auto res = backingMap.insert(std::make_pair(elem, size() + offset));
	if (!res.second)
		return;

	indexMap.push_back(res.first);
	flag_count += flag;

	assert(size() <= maxSize + 1);
	assert(flagCount() <= maxFlagCount + flag);
	while (size() > maxSize || flagCount() > maxFlagCount)
		remove_(0);

	assert(sanity_check());
}

int FlaggedArraySet::remove(const unsigned char* start, const unsigned char* end) {
	std::lock_guard<WaitCountMutex> lock(mutex);
	cleanup_late_remove();

	auto it = backingMap.find(ElemAndFlag(start, end, 0));
	if (it == backingMap.end())
		return -1;

	int res = it->second - offset;
	remove_(res);

	assert(sanity_check());
	return res;
}

std::shared_ptr<std::vector<unsigned char> > FlaggedArraySet::remove(unsigned int index, unsigned char* elemHashRes) {
	std::lock_guard<WaitCountMutex> lock(mutex);

	if (index < max_remove)
		cleanup_late_remove();
	unsigned int lookup_index = index + to_be_removed.size();

	if (lookup_index >= indexMap.size())
		return std::shared_ptr<std::vector<unsigned char> >();

	const ElemAndFlag& e = indexMap[lookup_index]->first;
	assert(e.elem && e.elemHash);
	memcpy(elemHashRes, &(*e.elemHash)[0], 32);
	std::shared_ptr<std::vector<unsigned char> > res = e.elem;

	if (index >= max_remove) {
		to_be_removed.push_back(index);
		max_remove = index;
		flags_to_remove += e.flag;
	} else {
		cleanup_late_remove();
		remove_(index);
	}

	assert(sanity_check());
	return res;
}

void FlaggedArraySet::_clear(bool takeLock) {
	std::unique_lock<WaitCountMutex> lock(mutex, std::defer_lock);
	if (takeLock)
		lock.lock();

	if (!indexMap.empty() && !backingMap.empty())
		assert(sanity_check());

	flag_count = 0; offset = 0;
	flags_to_remove = 0; max_remove = 0;
	backingMap.clear(); indexMap.clear(); to_be_removed.clear();
}

void FlaggedArraySet::for_all_txn(const std::function<void (const std::shared_ptr<std::vector<unsigned char> >&)> callback) const {
	std::lock_guard<WaitCountMutex> lock(mutex);
	cleanup_late_remove();
	for (const auto& e : indexMap) {
		assert(e->first.elem);
		callback(e->first.elem);
	}
}
