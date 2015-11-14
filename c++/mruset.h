// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MRUSET_H
#define BITCOIN_MRUSET_H

#include <deque>
#include <set>
#include <utility>

/** STL-like set container that only keeps the most recent N elements. */
template <typename T> class mruset
{
public:
    typedef T key_type;
    typedef T value_type;
    typedef typename std::set<T>::iterator iterator;
    typedef typename std::set<T>::const_iterator const_iterator;
    typedef typename std::set<T>::size_type size_type;

protected:
    std::set<T> set;
    std::deque<T> queue;
    size_type nMaxSize;

public:
    mruset(size_type nMaxSizeIn) { nMaxSize = nMaxSizeIn; }
    iterator begin() const { return set.begin(); }
    iterator end() const { return set.end(); }
    size_type size() const { return set.size(); }
    bool empty() const { return set.empty(); }
    iterator find(const key_type& k) const { return set.find(k); }
    size_type count(const key_type& k) const { return set.count(k); }
    void clear() { set.clear(); queue.clear(); }
    bool inline friend operator==(const mruset<T>& a, const mruset<T>& b) { return a.set == b.set; }
    bool inline friend operator==(const mruset<T>& a, const std::set<T>& b) { return a.set == b; }
    bool inline friend operator<(const mruset<T>& a, const mruset<T>& b) { return a.set < b.set; }
    size_type erase(const value_type& val) { return set.erase(val); }
protected:
    void inline limit_size() {
        if (nMaxSize)
            while (set.size() > nMaxSize)
            {
                set.erase(queue.front());
                queue.pop_front();
            }
    }
public:
    std::pair<iterator, bool> insert(const key_type& x)
    {
        std::pair<iterator, bool> ret = set.insert(x);
        if (ret.second)
        {
            limit_size();
            queue.push_back(x);
        }
        return ret;
    }
    size_type max_size() const { return nMaxSize; }
    size_type max_size(size_type s)
    {
        nMaxSize = s;
        limit_size();
        return nMaxSize;
    }
};

class vectormruset : public mruset<std::vector<unsigned char> >
{
private:
    uint64_t element_size;
public:
    vectormruset(size_type nMaxSizeIn) : mruset(nMaxSizeIn), element_size(0) {}
private:
    void inline limit_size() {
        if (nMaxSize)
            while (element_size > nMaxSize)
            {
                erase(queue.front());
                queue.pop_front();
            }
    }
public:
    size_type erase(const value_type& val) {
        size_type ret = set.erase(val);
        if (ret)
            element_size -= val.size();
        return ret;
    }
    std::pair<iterator, bool> insert(const key_type& x)
    {
        std::pair<iterator, bool> ret = set.insert(x);
        if (ret.second)
        {
            element_size += x.size();
            queue.push_back(x);
            limit_size();
        }
        return ret;
    }
    size_type max_size(size_type s)
    {
        nMaxSize = s;
        limit_size();
        return nMaxSize;
    }
};

#endif // BITCOIN_MRUSET_H
