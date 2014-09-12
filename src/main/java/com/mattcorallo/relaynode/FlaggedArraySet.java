package com.mattcorallo.relaynode;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.*;

/**
 * Keeps a set with indexes of elements
 */
public class FlaggedArraySet<K> {
	private static class Index {
		long index;
		public Index(long index) { this.index = index; }
		@Override public boolean equals(Object o) { return o instanceof  Index && ((Index) o).index == index; }
		@Override public int hashCode() { return (int) (index ^ (index >> 32)); }
	}

	private static class ElementAndFlag<T> {
		boolean flag;
		T element;
		Index index;
		public ElementAndFlag(@Nonnull T element, boolean flag, Index index) { this.element = element; this.flag = flag; this.index = index; }
		public ElementAndFlag(@Nonnull T element) { this(element, false, null); }

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
	private final Map<ElementAndFlag<K>, Index> backingMap;
	private final Map<Long, ElementAndFlag<K>> backingReverseMap;

	private long offset = 0;
	private long total = 0;
	private int flagCount = 0;

	public FlaggedArraySet(int maxSize) {
		this.maxSize = maxSize;
		backingMap = new LinkedHashMap<>(maxSize);
		backingReverseMap = new HashMap<>(maxSize);
	}

	public synchronized int size() {
		return backingMap.size();
	}

	public synchronized int flagCount() {
		return flagCount;
	}

	public synchronized boolean contains(@Nonnull K o) {
		return backingMap.containsKey(new ElementAndFlag<>(o));
	}

	public synchronized boolean add(@Nonnull K k, boolean flag) {
		if (contains(k))
			return false;

		while (size() >= maxSize)
			remove(backingMap.keySet().iterator().next(), true);

		ElementAndFlag<K> newElement = new ElementAndFlag<>(k, flag, new Index(total));
		backingMap.put(newElement, newElement.index);
		backingReverseMap.put(total++, newElement);

		if (flag)
			flagCount++;

		return true;
	}

	private synchronized Integer remove(ElementAndFlag<K> o, boolean stillInReverseMap) {
		Index index = backingMap.remove(o);
		if (index == null)
			return null;
		if (stillInReverseMap)
			o = backingReverseMap.remove(index.index);

		if (o.flag)
			flagCount--;

		if (offset != index.index) {
			ElementAndFlag<K> nextElem = backingReverseMap.remove(offset);
			for (long i = offset; i < index.index; i++) {
				ElementAndFlag<K> thisElem = backingReverseMap.put(i+1, nextElem);
				nextElem.index.index = i + 1;
				nextElem = thisElem;
			}
		}
		offset++;

		return (int)(index.index - (offset - 1));
	}

	public Integer remove(@Nonnull K o) {
		return remove(new ElementAndFlag<>(o), true);
	}

	@Nullable
	public synchronized K remove(int index) {
		ElementAndFlag<K> res = backingReverseMap.remove(index + offset);
		if (res == null)
			return null;
		remove(res, false);
		return res.element;
	}
}
