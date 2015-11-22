#ifndef _RELAY_FLAGGEDARRAYSET_H
#define _RELAY_FLAGGEDARRAYSET_H

#include <vector>
#include <thread>
#include <map>
#include <unordered_map>
#include <cstddef>

#include "utils.h"

/******************************
 **** FlaggedArraySet util ****
 ******************************/
struct ElemAndFlag {
	uint32_t flag;
	std::shared_ptr<std::vector<unsigned char> > elem, elemHash;
	std::vector<unsigned char>::const_iterator elemBegin, elemEnd;
	ElemAndFlag(const std::shared_ptr<std::vector<unsigned char> >& elemIn, uint32_t flagIn, bool setHash);
	ElemAndFlag(const std::shared_ptr<std::vector<unsigned char> >& elemHashIn, std::nullptr_t);
	ElemAndFlag(const std::vector<unsigned char>::const_iterator& elemBegin, const std::vector<unsigned char>::const_iterator& elemEnd, uint32_t flagIn);
	bool operator == (const ElemAndFlag& o) const;
};
namespace std {
	template <> struct hash<ElemAndFlag> {
		size_t operator()(const ElemAndFlag& e) const;
	};
}



class FlaggedArraySet {
private:
	uint64_t maxSize, maxFlagCount, flag_count;
	size_t offset;
	std::unordered_map<ElemAndFlag, uint64_t> backingMap;
	std::vector<std::unordered_map<ElemAndFlag, uint64_t>::iterator> indexMap;

	// The mutex is only used by memory deduper, FlaggedArraySet is not thread-safe
	// It is taken by changes to backingMap, any touches to backingMap in the deduper thread, or any touches to elem
	friend class Deduper;
	friend class FASLockHint;
	mutable WaitCountMutex mutex;

	mutable std::vector<int> to_be_removed;
	mutable uint32_t max_remove;
	mutable uint64_t flags_to_remove;

	void _clear(bool takeLock);

public:
	void clear() { _clear(true); }
	FlaggedArraySet(uint64_t maxSizeIn, uint64_t maxFlagCountIn);
	~FlaggedArraySet();

	size_t size() const { return backingMap.size() - to_be_removed.size(); }
	uint64_t flagCount() const { return flag_count - flags_to_remove; }
	bool contains(const std::shared_ptr<std::vector<unsigned char> >& e) const;
	bool contains(const unsigned char* elemHash) const;

	FlaggedArraySet& operator=(const FlaggedArraySet& o);

private:
	bool sanity_check() const;
	void remove_(size_t index);
	void cleanup_late_remove() const;

public:
	void add(const std::shared_ptr<std::vector<unsigned char> >& e, uint32_t flag);
	int remove(const std::vector<unsigned char>::const_iterator& start, const std::vector<unsigned char>::const_iterator& end);
	std::shared_ptr<std::vector<unsigned char> > remove(unsigned int index, unsigned char* elemHashRes);

	void for_all_txn(const std::function<void (const std::shared_ptr<std::vector<unsigned char> >&)> callback) const;
};

class FASLockHint {
private:
	WaitCountHint* hint;
public:
	FASLockHint(FlaggedArraySet& fas) : hint(new WaitCountHint(fas.mutex)) {}
	~FASLockHint() { delete hint; }
};

#endif
