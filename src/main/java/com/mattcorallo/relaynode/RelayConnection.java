package com.mattcorallo.relaynode;

import com.google.bitcoin.core.*;
import com.google.bitcoin.net.MessageWriteTarget;
import com.google.bitcoin.net.StreamParser;
import com.google.bitcoin.params.MainNetParams;

import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.*;

public abstract class RelayConnection implements StreamParser {
	private static final NetworkParameters params = MainNetParams.get();
	private static final int MAGIC_BYTES = 0x42BEEF42;

	private enum MessageTypes {
		VERSION,
		BLOCK, TRANSACTION, END_BLOCK,
	}

	private class PendingBlock {
		Block header;
		Map<QuarterHash, Transaction> transactions = new LinkedHashMap<>();
		int pendingTransactionCount = 0;

		PendingBlock(Block header) {
			this.header = header;
		}

		synchronized void addTransaction(QuarterHash hash) {
			Transaction t = relayTransactionCache.get(hash);
			transactions.put(hash, t);
			if (t == null)
				pendingTransactionCount++;
		}

		synchronized void foundTransaction(Transaction t) throws VerificationException {
			if (transactions.containsKey(new QuarterHash(t.getHash()))) {
				if (transactions.put(new QuarterHash(t.getHash()), t) != null)
					throw new ProtocolException("");

				pendingTransactionCount--;

				if (pendingTransactionCount <= 0)
					buildBlock();
			} else
				throw new ProtocolException("");
		}

		private void buildBlock() throws VerificationException {
			List<Transaction> txn = new LinkedList<>();
			for (Map.Entry<QuarterHash, Transaction> e : transactions.entrySet())
				txn.add(e.getValue());

			Block block = new Block(params, header.getVersion(), header.getPrevBlockHash(), header.getMerkleRoot(),
					header.getTimeSeconds(), header.getDifficultyTarget(), header.getNonce(),
					txn);

			block.verify();

			receiveBlock(block);
		}
	}

	private Set<Sha256Hash> relayedTransactionCache = LimitedSynchronizedObjects.createSet(1000);
	private Set<Sha256Hash> relayedBlockCache = LimitedSynchronizedObjects.createSet(100);

	private Map<QuarterHash, Transaction> relayTransactionCache = LimitedSynchronizedObjects.createMap(1000);

	private MessageWriteTarget relayPeer;

	public long txnInBlock = 0, txnRelayedInBlock = 0;
	public long txnInBlockTotal = 0, txnSkippedTotal = 0;
	public long txnRelayedOutOfBlockTotal = 0;

	abstract void LogLine(String line);
	abstract void LogStatsRecv(String lines);
	abstract void LogConnected(String line);

	abstract void receiveBlock(Block b);
	abstract void receiveTransaction(Transaction t);

	static final Executor sendBlockExecutor = new ThreadPoolExecutor(4, 50, 2, TimeUnit.HOURS, new LinkedBlockingQueue<Runnable>());

	public void sendBlock(final Block b) {
		sendBlockExecutor.execute(new Runnable() {
			@Override
			public void run() {
				synchronized (RelayConnection.this) {
					try {
						if (relayedBlockCache.contains(b.getHash()))
							return;

						byte[] blockHeader = b.cloneAsHeader().bitcoinSerialize();
						int transactionCount = b.getTransactions().size();
						relayPeer.writeBytes(ByteBuffer.allocate(4 * 4 + blockHeader.length)
								.putInt(MAGIC_BYTES).putInt(MessageTypes.BLOCK.ordinal()).putInt(blockHeader.length + 4 + transactionCount * QuarterHash.BYTE_LENGTH)
								.put(blockHeader).putInt(transactionCount)
								.array());

						for (Transaction t : b.getTransactions())
							relayPeer.writeBytes(new QuarterHash(t.getHash()).bytes);

						for (Transaction t : b.getTransactions()) {
							if (!relayedTransactionCache.contains(t.getHash()))
								sendTransaction(t, false);
							else
								relayedTransactionCache.remove(t.getHash());
						}

						relayPeer.writeBytes(ByteBuffer.allocate(4 * 3)
								.putInt(MAGIC_BYTES).putInt(MessageTypes.END_BLOCK.ordinal()).putInt(0)
								.array());

						relayedBlockCache.add(b.getHash());
					} catch (IOException e) {
						/* Should get a disconnect automatically */
						LogLine("Failed to write bytes");
					}
				}
			}
		});
	}

	private synchronized void sendTransaction(Transaction t, boolean cacheSend) {
		try {
			if (cacheSend && relayedTransactionCache.contains(t.getHash()))
				return;
			byte[] transactionBytes = t.bitcoinSerialize();
			relayPeer.writeBytes(ByteBuffer.allocate(4*3 + transactionBytes.length)
					.putInt(MAGIC_BYTES).putInt(MessageTypes.TRANSACTION.ordinal()).putInt(transactionBytes.length)
					.put(transactionBytes)
					.array());
			if (cacheSend)
				relayedTransactionCache.add(t.getHash());
		} catch (IOException e) {
			/* Should get a disconnect automatically */
			LogLine("Failed to write bytes");
		}
	}

	public void sendTransaction(Transaction t) {
		sendTransaction(t, true);
	}

	private PendingBlock readingBlock; private int transactionsLeft;
	private byte[] readingTransaction; private int readingTransactionPos;

	private int readBlockTransactions(ByteBuffer buff) {
		int i = 0;
		try {
			for (; i < transactionsLeft; i++) {
				readingBlock.addTransaction(new QuarterHash(buff));
				txnInBlock++; txnInBlockTotal++;
			}
		} catch (BufferUnderflowException e) {}
		transactionsLeft = transactionsLeft - i;
		return QuarterHash.BYTE_LENGTH * i;
	}

	@Override
	public int receiveBytes(ByteBuffer buff) {
		int startPos = buff.position();
		try {
			if (readingTransaction != null) {
				int read = Math.min(readingTransaction.length - readingTransactionPos, buff.remaining());
				buff.get(readingTransaction, readingTransactionPos, read);
				readingTransactionPos += read;
				if (readingTransactionPos == readingTransaction.length) {
					Transaction t = new Transaction(params, readingTransaction);
					t = GlobalObjectTracker.putTransaction(t);
					t.verify();

					if (readingBlock != null) {
						readingBlock.foundTransaction(t);
						txnRelayedInBlock++;
					} else {
						relayTransactionCache.put(new QuarterHash(t.getHash()), t);
						receiveTransaction(t);
						txnRelayedOutOfBlockTotal++;
					}

					readingTransaction = null;
					return read + receiveBytes(buff);
				} else
					return read;
			} else if (transactionsLeft > 0) {
				int res = readBlockTransactions(buff);
				if (transactionsLeft <= 0)
					return res + receiveBytes(buff);
				else
					return res;
			}

			int magic = buff.getInt();
			MessageTypes msgType = MessageTypes.values()[buff.getInt()];
			int msgLength = buff.getInt();
			if (magic != MAGIC_BYTES || msgLength > Block.MAX_SIZE)
				throw new ProtocolException("");

			switch(msgType) {
				case VERSION:
					byte[] versionString = new byte[msgLength];
					buff.get(versionString);
					LogConnected("Connected to node with version: " + new String(versionString).replaceAll("[^ -~]", ""));
					return 3*4 + msgLength;

				case BLOCK:
					if (readingBlock != null)
						throw new ProtocolException("readingBlock already present");

					byte[] headerBytes = new byte[Block.HEADER_SIZE];
					buff.get(headerBytes);
					PendingBlock block = new PendingBlock(new Block(params, headerBytes));

					int transactionCount = buff.getInt();
					if (QuarterHash.BYTE_LENGTH * transactionCount + Block.HEADER_SIZE + 4 != msgLength)
						throw new ProtocolException("transactionCount: " + transactionCount + ", msgLength: " + msgLength);

					transactionsLeft = transactionCount;
					readingBlock = block;
					return 4*4 + Block.HEADER_SIZE + receiveBytes(buff);

				case TRANSACTION:
					readingTransaction = new byte[msgLength];
					readingTransactionPos = 0;
					return 3*4 + receiveBytes(buff);

				case END_BLOCK:
					if (readingBlock.pendingTransactionCount > 0)
						throw new ProtocolException("pendingTransactionCount " + readingBlock.pendingTransactionCount);

					txnSkippedTotal += (txnInBlock - txnRelayedInBlock);

					LogStatsRecv("Skipped: " + (txnInBlock - txnRelayedInBlock) + "/" + txnInBlock +
							" (" + ((txnInBlock - txnRelayedInBlock + 0.0) / txnInBlock) + "%)\n" +
							"In total, skipped " + txnSkippedTotal + " of " + txnInBlockTotal +
							" (" + ((txnSkippedTotal + 0.0) / txnInBlockTotal) + "%)\n" +
							"Relayed " + txnRelayedOutOfBlockTotal + " txn out of blocks");

					txnInBlock = 0; txnRelayedInBlock = 0;

					readingBlock = null;
					return 3*4;
			}
		} catch (BufferUnderflowException e) {
			buff.position(startPos);
			return 0;
		} catch (NullPointerException | VerificationException | ArrayIndexOutOfBoundsException e) {
			LogLine("Corrupted data read from relay peer " + e.getMessage());
			relayPeer.closeConnection();
			return 0;
		}
		throw new RuntimeException();
	}

	@Override
	public void setWriteTarget(MessageWriteTarget writeTarget) {
		try {
			writeTarget.writeBytes(ByteBuffer.allocate(4 * 3 + RelayNode.VERSION.length())
					.putInt(MAGIC_BYTES).putInt(MessageTypes.VERSION.ordinal()).putInt(RelayNode.VERSION.length())
					.put(RelayNode.VERSION.getBytes())
					.array());
		} catch (IOException e) {
			/* Should get a disconnect automatically */
			LogLine("Failed to write VERSION_INIT");
		}
		relayPeer = writeTarget;
	}

	@Override
	public int getMaxMessageSize() {
		return Block.MAX_SIZE; // Its bigger than 64k, so buffers will just be 64k in size
	}
}
