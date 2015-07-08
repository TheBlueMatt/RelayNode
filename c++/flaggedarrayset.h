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
	bool flag;
	bool allowDups;
	std::shared_ptr<std::vector<unsigned char> > elem, elemHash;
	std::vector<unsigned char>::const_iterator elemBegin, elemEnd;
	ElemAndFlag(const std::shared_ptr<std::vector<unsigned char> >& elemIn, bool flagIn, bool allowDupsIn, bool setHash);
	ElemAndFlag(const std::shared_ptr<std::vector<unsigned char> >& elemHashIn, std::nullptr_t);
	ElemAndFlag(const std::vector<unsigned char>::const_iterator& elemBegin, const std::vector<unsigned char>::const_iterator& elemEnd, bool flagIn, bool allowDupsIn);
	bool operator == (const ElemAndFlag& o) const;
};
namespace std {
	template <> struct hash<ElemAndFlag> {
		size_t operator()(const ElemAndFlag& e) const;
	};
}



class FlaggedArraySet {
private:
	unsigned int maxSize, flag_count;
	uint64_t offset;
	std::unordered_map<ElemAndFlag, uint64_t> backingMap;
	std::vector<std::unordered_map<ElemAndFlag, uint64_t>::iterator> indexMap;
	bool allowDups;

	// The mutex is only used by memory deduper, FlaggedArraySet is not thread-safe
	// It is taken by changes to backingMap, any touches to backingMap in the deduper thread, or any touches to elem
	friend class Deduper;
	friend class FASLockHint;
	mutable WaitCountMutex mutex;

	mutable std::vector<int> to_be_removed;
	mutable int max_remove, flags_to_remove;

public:
	void clear();
	FlaggedArraySet(unsigned int maxSizeIn, bool allowDupsIn);
	~FlaggedArraySet();

	size_t size() const { return backingMap.size() - to_be_removed.size(); }
	size_t flagCount() const { return flag_count - flags_to_remove; }
	bool contains(const std::shared_ptr<std::vector<unsigned char> >& e) const;
	bool contains(const unsigned char* elemHash) const;

	FlaggedArraySet& operator=(const FlaggedArraySet& o) {
		maxSize = o.maxSize;
		flag_count = o.flag_count;
		offset = o.offset;
		backingMap = o.backingMap;
		indexMap = o.indexMap;
		allowDups = o.allowDups;
		return *this;
	}

private:
	bool sanity_check() const;
	void remove_(size_t index);
	void cleanup_late_remove() const;

public:
	void add(const std::shared_ptr<std::vector<unsigned char> >& e, bool flag);
	int remove(const std::vector<unsigned char>::const_iterator& start, const std::vector<unsigned char>::const_iterator& end);
	bool remove(int index, std::vector<unsigned char>& elemRes, unsigned char* elemHashRes);

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
