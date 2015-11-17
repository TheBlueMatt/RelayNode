#ifndef _RELAY_PREINCLUDE_H
#define _RELAY_PREINCLUDE_H

#ifdef FOR_VALGRIND
#include "valgrind/drd.h"
#define _GLIBCXX_SYNCHRONIZATION_HAPPENS_BEFORE(A) ANNOTATE_HAPPENS_BEFORE(A)
#define _GLIBCXX_SYNCHRONIZATION_HAPPENS_AFTER(A) ANNOTATE_HAPPENS_AFTER(A)

#include <mutex>
#include <atomic>
#include <string.h>

template <typename T>
class locked_atomic {
public:
	T obj;
	mutable std::mutex mutex;
public:
	locked_atomic() {}
	constexpr locked_atomic(T desired) : obj(desired) {}
	locked_atomic(const locked_atomic&) =delete;

	T operator=(T desired) { store(desired); return desired; }
	T operator=(T desired) volatile { store(desired); return desired; }
	locked_atomic& operator=(const locked_atomic&) =delete;
	locked_atomic& operator=(const locked_atomic&) volatile =delete;

	bool is_lock_free() const { return false; }
	bool is_lock_free() const volatile { return false; }

	void store(T desired, std::memory_order order = std::memory_order_seq_cst) { std::lock_guard<std::mutex> lock(mutex); obj = desired; }
	void store(T desired, std::memory_order order = std::memory_order_seq_cst) volatile { std::lock_guard<std::mutex> lock(mutex); obj = desired; }

	T load(std::memory_order order = std::memory_order_seq_cst) const { std::lock_guard<std::mutex> lock(mutex); return obj; }
	T load(std::memory_order order = std::memory_order_seq_cst) const volatile { std::lock_guard<std::mutex> lock(mutex); return obj; }

	operator T() const { return load(); }
	operator T() const volatile { return load(); }

	T exchange(T desired, std::memory_order order = std::memory_order_seq_cst)
		{ std::lock_guard<std::mutex> lock(mutex); T res = obj; obj = desired; return res;}
	T exchange(T desired, std::memory_order order = std::memory_order_seq_cst) volatile
		{ std::lock_guard<std::mutex> lock(mutex); T res = obj; obj = desired; return res;}

	bool compare_exchange_strong(T& expected, T desired, std::memory_order order = std::memory_order_seq_cst) {
		std::lock_guard<std::mutex> lock(mutex);
		if (memcmp(&obj, &expected, sizeof(T))) {
			memcpy(&expected, &obj, sizeof(T));
			return false;
		} else {
			memcpy(&obj, &expected, sizeof(T));
			return true;
		}
	}
};

template<typename T>
class locked_atomic_int : public locked_atomic<T> {
public:
	locked_atomic_int() {}
	constexpr locked_atomic_int(T desired) : locked_atomic<T>(desired) {}
	locked_atomic_int(const locked_atomic_int&) =delete;

	T operator=(T desired) { locked_atomic<T>::store(desired); return desired; }
	T operator=(T desired) volatile { store(desired); return desired; }
	locked_atomic_int& operator=(const locked_atomic_int&) =delete;
	locked_atomic_int& operator=(const locked_atomic_int&) volatile =delete;

	T fetch_add(T arg, std::memory_order = std::memory_order_seq_cst)
		{ std::lock_guard<std::mutex> lock(locked_atomic<T>::mutex); T ret = locked_atomic<T>::obj; locked_atomic<T>::obj += arg; return ret; }
	T fetch_add(T arg, std::memory_order = std::memory_order_seq_cst) volatile
		{ std::lock_guard<std::mutex> lock(locked_atomic<T>::mutex); T ret = locked_atomic<T>::obj; locked_atomic<T>::obj += arg; return ret; }

	T fetch_sub(T arg, std::memory_order = std::memory_order_seq_cst)
		{ std::lock_guard<std::mutex> lock(locked_atomic<T>::mutex); T ret = locked_atomic<T>::obj; locked_atomic<T>::obj -= arg; return ret; }
	T fetch_sub(T arg, std::memory_order = std::memory_order_seq_cst) volatile
		{ std::lock_guard<std::mutex> lock(locked_atomic<T>::mutex); T ret = locked_atomic<T>::obj; locked_atomic<T>::obj -= arg; return ret; }

	T fetch_and(T arg, std::memory_order = std::memory_order_seq_cst)
		{ std::lock_guard<std::mutex> lock(locked_atomic<T>::mutex); T ret = locked_atomic<T>::obj; locked_atomic<T>::obj &= arg; return ret; }
	T fetch_and(T arg, std::memory_order = std::memory_order_seq_cst) volatile
		{ std::lock_guard<std::mutex> lock(locked_atomic<T>::mutex); T ret = locked_atomic<T>::obj; locked_atomic<T>::obj &= arg; return ret; }

	T fetch_or(T arg, std::memory_order = std::memory_order_seq_cst)
		{ std::lock_guard<std::mutex> lock(locked_atomic<T>::mutex); T ret = locked_atomic<T>::obj; locked_atomic<T>::obj |= arg; return ret; }
	T fetch_or(T arg, std::memory_order = std::memory_order_seq_cst) volatile
		{ std::lock_guard<std::mutex> lock(locked_atomic<T>::mutex); T ret = locked_atomic<T>::obj; locked_atomic<T>::obj |= arg; return ret; }

	T fetch_xor(T arg, std::memory_order = std::memory_order_seq_cst)
		{ std::lock_guard<std::mutex> lock(locked_atomic<T>::mutex); T ret = locked_atomic<T>::obj; locked_atomic<T>::obj ^= arg; return ret; }
	T fetch_xor(T arg, std::memory_order = std::memory_order_seq_cst) volatile
		{ std::lock_guard<std::mutex> lock(locked_atomic<T>::mutex); T ret = locked_atomic<T>::obj; locked_atomic<T>::obj ^= arg; return ret; }

	T operator+=(T arg) { return fetch_add(arg) + arg; }
	T operator+=(T arg) volatile { return fetch_add(arg) + arg; }

	T operator-=(T arg) { return fetch_sub(arg) - arg; }
	T operator-=(T arg) volatile { return fetch_sub(arg) - arg; }

	T operator&=(T arg) { return fetch_and(arg) & arg; }
	T operator&=(T arg) volatile { return fetch_and(arg) & arg; }

	T operator|=(T arg) { return fetch_or(arg) | arg; }
	T operator|=(T arg) volatile { return fetch_or(arg) | arg; }

	T operator^=(T arg) { return fetch_xor(arg) ^ arg; }
	T operator^=(T arg) volatile { return fetch_xor(arg) ^ arg; }
};

#define DECLARE_ATOMIC(TYPE, NAME) locked_atomic<TYPE> NAME
#define DECLARE_ATOMIC_INT(TYPE, NAME) locked_atomic_int<TYPE> NAME
#define DECLARE_ATOMIC_PTR(TYPE, NAME) locked_atomic_int<TYPE*> NAME
#define DECLARE_NON_ATOMIC_PTR(TYPE, NAME) locked_atomic_int<TYPE*> NAME

#else

#define ANNOTATE_HAPPENS_BEFORE(A)
#define ANNOTATE_HAPPENS_AFTER(A)

#define DECLARE_ATOMIC(TYPE, NAME) std::atomic<TYPE> NAME
#define DECLARE_ATOMIC_INT(TYPE, NAME) std::atomic<TYPE> NAME
#define DECLARE_ATOMIC_PTR(TYPE, NAME) std::atomic<TYPE*> NAME
#define DECLARE_NON_ATOMIC_PTR(TYPE, NAME) TYPE* NAME

#endif

#endif
