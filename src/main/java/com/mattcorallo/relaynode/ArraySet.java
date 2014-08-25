package com.mattcorallo.relaynode;

import org.jetbrains.annotations.NotNull;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.util.*;

/**
 * Keeps a set with indexes of elements
 */
public class ArraySet<K> implements Set<K> {
	final int maxSize;
	final Map<K, Long> backingMap;
	final Map<Long, K> backingReverseMap;

	long offset = 0;
	long total = 0;

	public ArraySet(int maxSize) {
		this.maxSize = maxSize;
		backingMap = LimitedSynchronizedObjects.createMap(maxSize);
		backingReverseMap = LimitedSynchronizedObjects.createMap(maxSize);
	}

	@Override
	public int size() {
		return backingMap.size();
	}

	@Override
	public boolean isEmpty() {
		return backingMap.isEmpty();
	}

	@Override
	public boolean contains(Object o) {
		return backingMap.containsKey(o);
	}

	@NotNull
	@Override
	public Iterator<K> iterator() {
		return backingMap.keySet().iterator();
	}

	@NotNull
	@Override
	public Object[] toArray() {
		return backingMap.keySet().toArray();
	}

	@NotNull
	@Override
	public <T> T[] toArray(T[] a) {
		return backingMap.keySet().toArray(a);
	}

	@Override
	public boolean add(K k) {
		synchronized (backingMap) {
			if (backingMap.containsKey(k))
				return false;

			boolean wasFull = backingMap.size() == maxSize;
			backingMap.put(k, total);
			backingReverseMap.put(total++, k);
			if (wasFull)
				offset++;
			return true;
		}
	}

	@Override
	public boolean remove(Object o) {
		synchronized (backingMap) {
			Long index = backingMap.remove(o);
			if (index == null)
				return false;
			backingReverseMap.remove(index);
			return true;
		}
	}

	@Override
	public boolean containsAll(Collection<?> c) {
		return backingMap.keySet().containsAll(c);
	}

	@Override
	public boolean addAll(Collection<? extends K> c) {
		throw new NotImplementedException();
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		throw new NotImplementedException();
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		throw new NotImplementedException();
	}

	@Override
	public void clear() {
		synchronized (backingMap) {
			backingMap.clear();
			backingReverseMap.clear();
			offset = 0;
			total = 0;
		}
	}

	public Integer getIndex(Object key) {
		synchronized (backingMap) {
			Long res = backingMap.get(key);
			if (res == null)
				return null;
			return (int) (res - offset);
		}
	}

	public K getByIndex(int index) {
		synchronized (backingMap) {
			return backingReverseMap.get(index + offset);
		}
	}
}
