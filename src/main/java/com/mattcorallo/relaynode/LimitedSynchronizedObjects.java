package com.mattcorallo.relaynode;

import java.util.*;

public class LimitedSynchronizedObjects {
	public static <K,V> Map<K,V> createMap(int maxSize) {
		return Collections.synchronizedMap(new LinkedHashMap<K,V>(maxSize) {
			@Override
			public synchronized V put(K k, V v) {
				V res = super.put(k, v);
				if (size() > 1000)
					super.remove(super.keySet().iterator().next());
				return res;
			}
		});
	}

	public static <K> Set<K> createSet(int maxSize) {
		return Collections.synchronizedSet(new LinkedHashSet<K>(maxSize) {
			@Override
			public synchronized boolean add(K k) {
				boolean res = super.add(k);
				if (size() > 1000)
					super.remove(super.iterator().next());
				return res;
			}
		});
	}
}
