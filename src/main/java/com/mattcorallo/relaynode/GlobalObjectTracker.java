package com.mattcorallo.relaynode;

import com.google.bitcoin.core.Transaction;
import com.google.common.util.concurrent.Uninterruptibles;

import javax.annotation.Nonnull;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Ensures we don't get duplicate objects eating heap by deduplicating
 */
public class GlobalObjectTracker {
	private static final Map<QuarterHash, WeakReference<Transaction>> transactionCache = new HashMap<>();
	@Nonnull
	static Lock transactionLock = new ReentrantLock();

	@Nonnull
	public static Transaction putTransaction(QuarterHash hash, @Nonnull Transaction transaction) {
		transactionLock.lock();
		try {
			WeakReference<Transaction> reference = transactionCache.get(hash);
			if (reference != null) {
				Transaction existing = reference.get();
				if (existing != null)
					return existing;
			}

			transactionCache.put(hash, new WeakReference<>(transaction));
			return transaction;
		} finally {
			transactionLock.unlock();
		}
	}

	@Nonnull
	public static Transaction putTransaction(@Nonnull Transaction transaction) {
		return putTransaction(new QuarterHash(transaction.getHash()), transaction);
	}

	static {
		new Thread(new Runnable() {
			@Override
			public void run() {
				while (true) {
					boolean deleted = false;
					if (transactionLock.tryLock()) {
						try {
							for (Map.Entry<QuarterHash, WeakReference<Transaction>> entry : transactionCache.entrySet()) {
								if (entry.getValue().get() == null) {
									transactionCache.remove(entry.getKey());
									deleted = true;
									break;
								}
							}
						} finally {
							transactionLock.unlock();
						}
					}
					if (!deleted)
						Uninterruptibles.sleepUninterruptibly(1, TimeUnit.SECONDS);
					else
						Uninterruptibles.sleepUninterruptibly(1, TimeUnit.MILLISECONDS);
				}
			}
		}).start();
	}
}
