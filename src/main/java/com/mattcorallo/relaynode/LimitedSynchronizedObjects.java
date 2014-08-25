package com.mattcorallo.relaynode;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.util.*;

public class LimitedSynchronizedObjects {
	public static <K,V> Map<K,V> createMap(final int maxSize) {
		return Collections.synchronizedMap(new LinkedHashMap<K,V>(maxSize) {
			@Override
			public V put(K k, V v) {
				V res = super.put(k, v);
				if (size() > maxSize)
					remove(keySet().iterator().next());
				return res;
			}

			@Override
			public void putAll(Map<? extends K, ? extends V> m) {
				throw new NotImplementedException();
			}
		});
	}

	public static <K> Set<K> createSet(final int maxSize) {
		return Collections.synchronizedSet(new LinkedHashSet<K>(maxSize) {
			@Override
			public boolean add(K k) {
				boolean res = super.add(k);
				if (size() > maxSize)
					remove(iterator().next());
				return res;
			}
		});
	}

	public static <K> List<K> createList(final int maxSize) {
		return Collections.synchronizedList(new ArrayList<K>(maxSize + 1) {
			@Override
			public boolean add(K e) {
				boolean res = super.add(e);
				if (size() > maxSize)
					remove(0);
				return res;
			}
		});
	}
}
