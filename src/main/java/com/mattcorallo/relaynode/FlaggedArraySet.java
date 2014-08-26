package com.mattcorallo.relaynode;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.*;

/**
 * Keeps a set with indexes of elements
 */
public class FlaggedArraySet<K> {
	private static class ElementAndFlag<T> {
		boolean flag;
		T element;
		public ElementAndFlag(@NotNull T element, boolean flag) { this.element = element; this.flag = flag; }
		public ElementAndFlag(@NotNull T element) { this(element, false); }

		@Override
		public boolean equals(Object o) {
			return o instanceof ElementAndFlag &&
					(((ElementAndFlag) o).element == element ||
							(element != null && element.equals(((ElementAndFlag) o).element)));
		}

		@Override
		public int hashCode() {
			return element.hashCode();
		}
	}

	private final int maxSize;
	private final Map<ElementAndFlag<K>, Long> backingMap;
	private final Map<Long, ElementAndFlag<K>> backingReverseMap;
	private final Set<Long> indexesRemoved;

	private long offset = 0;
	private long total = 0;
	private int flagCount = 0;

	public FlaggedArraySet(int maxSize) {
		this.maxSize = maxSize;
		backingMap = new LinkedHashMap<>(maxSize);
		backingReverseMap = new LinkedHashMap<>(maxSize);
		indexesRemoved = new HashSet<>(maxSize);
	}

	public synchronized int size() {
		return backingMap.size();
	}

	public synchronized int flagCount() {
		return flagCount;
	}

	public synchronized boolean contains(@NotNull K o) {
		return backingMap.containsKey(new ElementAndFlag<>(o));
	}

	public synchronized boolean add(@NotNull K k, boolean flag) {
		if (contains(k))
			return false;

		while (size() >= maxSize)
			remove(backingMap.keySet().iterator().next());

		ElementAndFlag<K> newElement = new ElementAndFlag<>(k, flag);
		backingMap.put(newElement, total);
		backingReverseMap.put(total++, newElement);

		if (flag)
			flagCount++;

		return true;
	}

	private synchronized boolean remove(ElementAndFlag<K> o) {
		Long index = backingMap.remove(o);
		if (index == null)
			return false;
		o = backingReverseMap.remove(index);

		if (o.flag)
			flagCount--;

		if (offset == index)
			offset++;
		else {
			for (long i = index-1; i >= offset; i--) {
				ElementAndFlag<K> t = backingReverseMap.remove(i);
				backingMap.put(t, i+1);
				backingReverseMap.put(i+1, t);
			}
			offset++;
		}

		return true;
	}

	public boolean remove(@NotNull K o) {
		return remove(new ElementAndFlag<>(o));
	}

	@Nullable
	public synchronized Integer getIndex(@NotNull K key) {
		Long res = backingMap.get(new ElementAndFlag<>(key));
		if (res == null)
			return null;
		return (int) (res - offset);
	}

	@Nullable
	public synchronized K getByIndex(int index) {
		ElementAndFlag<K> res = backingReverseMap.get(index + offset);
		if (res == null)
			return null;
		return res.element;
	}
}
