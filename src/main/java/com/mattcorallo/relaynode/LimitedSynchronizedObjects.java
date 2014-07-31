package com.mattcorallo.relaynode;

import java.util.*;

public class LimitedSynchronizedObjects {
	public static <K,V> Map<K,V> createMap(final int maxSize) {
		return Collections.synchronizedMap(new LinkedHashMap<K,V>(maxSize) {
			@Override
			public synchronized V put(K k, V v) {
				V res = super.put(k, v);
				if (size() > maxSize)
					remove(keySet().iterator().next());
				return res;
			}
		});
	}

	public static <K> Set<K> createSet(final int maxSize) {
		return Collections.synchronizedSet(new LinkedHashSet<K>(maxSize) {
			@Override
			public synchronized boolean add(K k) {
				boolean res = super.add(k);
				if (size() > maxSize)
					remove(iterator().next());
				return res;
			}
		});
	}
}
