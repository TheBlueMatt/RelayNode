package com.mattcorallo.relaynode;

import com.google.bitcoin.core.*;
import com.google.bitcoin.net.MessageWriteTarget;
import com.google.bitcoin.net.StreamParser;
import com.google.bitcoin.params.MainNetParams;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.concurrent.*;

public abstract class RelayConnection implements StreamParser {
	private static final NetworkParameters params = MainNetParams.get();
	private static final int MAGIC_BYTES = 0xF2BEEF42;

	static enum RelayMode {
		ABBREV_HASH,
		CACHE_ID,
	}

	private static final Map<String, Integer> MAX_RELAY_TRANSACTION_BYTES = new HashMap<>();
	private static final Map<String, Integer> MAX_EXTRA_OVERSIZE_TXN = new HashMap<>();
	private static final Map<String, Integer> MAX_RELAY_OVERSIZE_TXN_BYTES = new HashMap<>();
	private static final Map<String, Integer> TRANSACTIONS_CACHED = new HashMap<>();
	private static final Map<String, RelayMode> RELAY_MODE = new HashMap<>();
	static {
		MAX_RELAY_TRANSACTION_BYTES.put("efficient eagle", Block.MAX_BLOCK_SIZE);
		TRANSACTIONS_CACHED.put("efficient eagle", 2000);
		RELAY_MODE.put("efficient eagle", RelayMode.ABBREV_HASH);
		MAX_EXTRA_OVERSIZE_TXN.put("efficient eagle", 0);
		MAX_RELAY_OVERSIZE_TXN_BYTES.put("efficient eagle", 0);

		MAX_RELAY_TRANSACTION_BYTES.put("charming chameleon", 10000);
		TRANSACTIONS_CACHED.put("charming chameleon", 1000);
		RELAY_MODE.put("charming chameleon", RelayMode.ABBREV_HASH);
		MAX_EXTRA_OVERSIZE_TXN.put("charming chameleon", 0);
		MAX_RELAY_OVERSIZE_TXN_BYTES.put("charming chameleon", 0);

		MAX_RELAY_TRANSACTION_BYTES.put("fuck it, ship it!", 10000);
		TRANSACTIONS_CACHED.put("fuck it, ship it!", 1000);
		RELAY_MODE.put("fuck it, ship it!", RelayMode.CACHE_ID);
		MAX_EXTRA_OVERSIZE_TXN.put("fuck it, ship it!", 250000);
		MAX_RELAY_OVERSIZE_TXN_BYTES.put("fuck it, ship it!", 20);

		MAX_RELAY_TRANSACTION_BYTES.put("prioritized panther", 10000);
		TRANSACTIONS_CACHED.put("prioritized panther", 1000);
		RELAY_MODE.put("prioritized panther", RelayMode.CACHE_ID);
		MAX_EXTRA_OVERSIZE_TXN.put("prioritized panther", 250000);
		MAX_RELAY_OVERSIZE_TXN_BYTES.put("prioritized panther", 20);

		// 20MB + overhead
		MAX_RELAY_TRANSACTION_BYTES.put(RelayNode.VERSION, 10000);
		TRANSACTIONS_CACHED.put(RelayNode.VERSION, 1525);
		RELAY_MODE.put(RelayNode.VERSION, RelayMode.CACHE_ID);
		MAX_EXTRA_OVERSIZE_TXN.put(RelayNode.VERSION, 25);
		MAX_RELAY_OVERSIZE_TXN_BYTES.put(RelayNode.VERSION, 200000);
	}

	private enum MessageTypes {
		VERSION,
		BLOCK, TRANSACTION, END_BLOCK,
		MAX_VERSION,
	}

	private class PendingBlock {
		Block header;
		@Nonnull
		Map<QuarterHash, Transaction> transactions = new LinkedHashMap<>();
		int pendingTransactionCount = 0;
		boolean alreadyBuilt = false;

		PendingBlock(Block header) {
			this.header = header;
		}

		synchronized void addTransaction(QuarterHash hash) {
			Transaction t = relayTransactionCache.get(hash);
			transactions.put(hash, t);
			if (t == null)
				pendingTransactionCount++;
		}

		synchronized void addTransaction(Integer index) {
			Transaction t = newRelayTransactionCache.getByIndex(index);
			newRelayTransactionCache.remove(t);
			transactions.put(new QuarterHash(t.getHash()), t);
		}

		synchronized void foundTransaction(@Nonnull Transaction t) throws VerificationException {
			if (transactions.containsKey(new QuarterHash(t.getHash()))) {
				if (transactions.put(new QuarterHash(t.getHash()), t) != null)
					throw new ProtocolException("Duplicate transaction in a single block");

				pendingTransactionCount--;

				if (pendingTransactionCount == 0)
					buildBlock();
				else if (pendingTransactionCount < 0)
					throw new ProtocolException("pendingTransactionCount " + pendingTransactionCount);
			} else if (RELAY_MODE.get(protocolVersion) == RelayMode.CACHE_ID)
				transactions.put(new QuarterHash(t.getHash()), t);
			else
				throw new ProtocolException("foundTransaction we didn't need");
		}

		public void buildBlock() throws VerificationException {
			if (alreadyBuilt)
				return;
			alreadyBuilt = true;

			List<Transaction> txn = new LinkedList<>();
			for (Map.Entry<QuarterHash, Transaction> e : transactions.entrySet())
				txn.add(e.getValue());

			Block block = new Block(params, header.getVersion(), header.getPrevBlockHash(), header.getMerkleRoot(),
					header.getTimeSeconds(), header.getDifficultyTarget(), header.getNonce(),
					txn);

			block.verify();

			receiveBlock(block);

			LogStatsRecv("Block built with " + bytesInBlock + " bytes on the wire");
		}
	}

	private boolean sendVersionOnConnect;
	private String protocolVersion = null;

	private final Set<Sha256Hash> relayedBlockCache = LimitedSynchronizedObjects.createSet(10);

	private volatile FlaggedArraySet<Sha256Hash> relayedTransactionCache = null;
	private volatile Map<QuarterHash, Transaction> relayTransactionCache = null;
	private volatile FlaggedArraySet<Transaction> newRelayTransactionCache = null;

	private MessageWriteTarget relayPeer;

	public long txnInBlock = 0, txnRelayedInBlock = 0;
	public long bytesInBlock = 0;
	public long txnInBlockTotal = 0, txnSkippedTotal = 0;
	public long txnRelayedOutOfBlockTotal = 0;

	abstract void LogLine(String line);
	abstract void LogStatsRecv(String lines);
	abstract void LogConnected(String line);

	abstract void receiveBlockHeader(Block b);
	abstract void receiveBlock(Block b);
	abstract void receiveTransaction(Transaction t);

	public RelayConnection(boolean sendVersionOnConnect) {
		this.sendVersionOnConnect = sendVersionOnConnect;
	}

	public synchronized void sendBlock(@Nonnull final Block b) {
		if (protocolVersion == null)
			return;
		try {
			if (relayedBlockCache.contains(b.getHash()))
				return;

			byte[] blockHeader = b.cloneAsHeader().bitcoinSerialize();
			int transactionCount = b.getTransactions().size();
			RelayMode mode = RELAY_MODE.get(protocolVersion);

			// Guess that we're only gonna relay the coinbase txn
			ByteArrayOutputStream out = new ByteArrayOutputStream(4 * 4 + blockHeader.length + transactionCount * 2 + 3 + b.getTransactions().get(0).getMessageSize());
			out.write(ByteBuffer.allocate(4 * 3 + blockHeader.length).order(ByteOrder.BIG_ENDIAN)
					.putInt(MAGIC_BYTES).putInt(MessageTypes.BLOCK.ordinal())
					.putInt(mode == RelayMode.ABBREV_HASH ? (blockHeader.length + 4 + transactionCount * QuarterHash.BYTE_LENGTH) : transactionCount)
					.put(blockHeader).array());

			if (mode == RelayMode.ABBREV_HASH)
				out.write(ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(transactionCount).array());

			for (Transaction t : b.getTransactions()) {
				if (mode == RelayMode.ABBREV_HASH) {
					QuarterHash.writeBytes(t.getHash(), out);
				} else {
					Integer index = relayedTransactionCache.getIndex(t.getHash());
					if (index == null) {
						byte[] transactionBytes = t.bitcoinSerialize();
						if (transactionBytes.length > 16777215) {
							LogLine("Tried to relay block with invalid transaction in it!");
							throw new RuntimeException();
						}
						out.write((byte) 0xff);
						out.write((byte) 0xff);
						out.write(transactionBytes.length >> 16);
						out.write(transactionBytes.length >> 8);
						out.write(transactionBytes.length);
						out.write(transactionBytes);
					} else {
						if (index >= Short.MAX_VALUE * 2) {
							LogLine("INTERNAL ERROR: FlaggedArraySet is inconsistent");
							relayPeer.closeConnection();
							return;
						}
						out.write(index >> 8);
						out.write(index);
						relayedTransactionCache.remove(t.getHash());
					}
				}
			}

			relayPeer.writeBytes(out.toByteArray());

			if (mode == RelayMode.ABBREV_HASH) {
				for (Transaction t : b.getTransactions()) {
					if (!relayedTransactionCache.contains(t.getHash())) {
						byte[] transactionBytes = t.bitcoinSerialize();
						relayPeer.writeBytes(ByteBuffer.allocate(4 + transactionBytes.length).order(ByteOrder.BIG_ENDIAN)
								.putInt(transactionBytes.length).put(transactionBytes)
								.array());
					}
				}
			}

			boolean latestVersion = RelayNode.VERSION.equals(protocolVersion);
			ByteBuffer lastPacket = ByteBuffer.allocate(4 * 3 + (latestVersion ? 0 : (4 * 3 + RelayNode.VERSION.length())))
					.order(ByteOrder.BIG_ENDIAN);
			lastPacket.putInt(MAGIC_BYTES).putInt(MessageTypes.END_BLOCK.ordinal()).putInt(0);
			if (!latestVersion)
				lastPacket.putInt(MAGIC_BYTES).putInt(MessageTypes.MAX_VERSION.ordinal()).putInt(RelayNode.VERSION.length())
						.put(RelayNode.VERSION.getBytes());
			relayPeer.writeBytes(lastPacket.array());

			relayedBlockCache.add(b.getHash());
		} catch (IOException e) {
						/* Should get a disconnect automatically */
			LogLine("Failed to write bytes");
		}
	}

	public synchronized void sendTransaction(@Nonnull final Transaction t) {
		final byte[] transactionBytes = t.bitcoinSerialize();
		if (protocolVersion == null ||
				(transactionBytes.length > MAX_RELAY_TRANSACTION_BYTES.get(protocolVersion) &&
						(transactionBytes.length > MAX_RELAY_OVERSIZE_TXN_BYTES.get(protocolVersion) || relayedTransactionCache.flagCount() >= MAX_EXTRA_OVERSIZE_TXN.get(protocolVersion))))
			return;
		if (relayedTransactionCache.contains(t.getHash()))
			return;
		try {
			relayPeer.writeBytes(ByteBuffer.allocate(4 * 3 + transactionBytes.length)
					.putInt(MAGIC_BYTES).putInt(MessageTypes.TRANSACTION.ordinal())
					.putInt(transactionBytes.length).put(transactionBytes)
					.array());
		} catch (IOException e) {
			LogLine("Failed to write bytes");
		}
		relayedTransactionCache.add(t.getHash(), transactionBytes.length > MAX_RELAY_TRANSACTION_BYTES.get(protocolVersion));
	}

	@Nullable
	private PendingBlock readingBlock; private int transactionsLeft;
	@Nullable
	private byte[] readingTransaction; private int readingTransactionPos;

	private int readBlockTransactions(@Nonnull ByteBuffer buff) {
		if (readingBlock == null)
			throw new RuntimeException();
		int bytesRead = 0;
		int pos = buff.position();
		RelayMode mode = RELAY_MODE.get(protocolVersion);
		try {
			for (; transactionsLeft > 0; transactionsLeft--) {
				pos = buff.position();
				if (mode == RelayMode.ABBREV_HASH) {
					readingBlock.addTransaction(new QuarterHash(buff));
					bytesRead += QuarterHash.BYTE_LENGTH;
				} else {
					int txIndex = buff.getShort() & 0xffff;
					if (txIndex != 0xffff) {
						readingBlock.addTransaction(txIndex);
						bytesRead += 2;
						bytesInBlock += 2;

						if (transactionsLeft == 1)
							readingBlock.buildBlock();
					} else {
						int txLength = (buff.getShort() & 0xffff) << 8;
						txLength |= buff.get() & 0xff;
						if (txLength > Block.MAX_BLOCK_SIZE)
							throw new ProtocolException("Got txLength of " + txLength);

						readingTransaction = new byte[txLength];
						readingTransactionPos = 0;
						bytesRead += 5;

						txnInBlock++; txnInBlockTotal++;
						bytesInBlock += 2 + 3 + txLength;
						transactionsLeft--;
						break;
					}
				}
				txnInBlock++; txnInBlockTotal++;
			}
		} catch (BufferUnderflowException e) {
			buff.position(pos);
		}
		return bytesRead;
	}

	boolean killConnection = false;
	@Override
	public int receiveBytes(@Nonnull ByteBuffer buff) {
		if (killConnection)
			return -1;

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
						if (transactionsLeft == 0)
							readingBlock.buildBlock();
						LogStatsRecv("Received in-block " + t.getHashAsString() + " size:" + t.getMessageSize());
						txnRelayedInBlock++;
					} else {
						if (RELAY_MODE.get(protocolVersion) == RelayMode.ABBREV_HASH)
							relayTransactionCache.put(new QuarterHash(t.getHash()), t);
						else
							newRelayTransactionCache.add(t, readingTransaction.length > MAX_RELAY_OVERSIZE_TXN_BYTES.get(protocolVersion));
						receiveTransaction(t);
						txnRelayedOutOfBlockTotal++;
					}

					readingTransaction = null;
					return read + receiveBytes(buff);
				} else
					return read;
			} else if (transactionsLeft > 0) {
				int res = readBlockTransactions(buff);
				if (transactionsLeft <= 0 || readingTransaction != null)
					return res + receiveBytes(buff);
				else
					return res;
			}

			int magic = buff.getInt();
			MessageTypes msgType = MessageTypes.TRANSACTION;
			int msgLength;

			if (readingBlock == null || magic == MAGIC_BYTES) {
				msgType = MessageTypes.values()[buff.getInt()];
				if (readingBlock != null && msgType != MessageTypes.END_BLOCK)
					throw new ProtocolException("Got full message of type " + msgType.name() + " while reading a block");

				msgLength = buff.getInt();
				if (magic != MAGIC_BYTES)
					throw new ProtocolException("Magic bytes incorrect");
			} else
				msgLength = magic;

			if (msgLength > Block.MAX_BLOCK_SIZE)
				throw new ProtocolException("Remote provided message of length " + msgLength);

			switch(msgType) {
				case VERSION:
					byte[] versionBytes = new byte[msgLength];
					buff.get(versionBytes);
					String versionString = new String(versionBytes);

					if (TRANSACTIONS_CACHED.get(versionString) == null) {
						LogLine("Connected to node with bad version: " + versionString.replaceAll("[^ -~]", ""));
						relayPeer.writeBytes(ByteBuffer.allocate(4 * 3 + RelayNode.VERSION.length()).order(ByteOrder.BIG_ENDIAN)
								.putInt(MAGIC_BYTES).putInt(MessageTypes.MAX_VERSION.ordinal()).putInt(RelayNode.VERSION.length())
								.put(RelayNode.VERSION.getBytes())
								.array()); // Wont get written to OS buffers until after we return :(
						killConnection = true;
						buff.position(0);
						return 0;
					} else {
						if (RelayNode.VERSION.equals(versionString))
							LogConnected("Connected to node with version: " + versionString.replaceAll("[^ -~]", ""));
						else
							LogLine("Connected to node with old version: " + versionString.replaceAll("[^ -~]", ""));

						relayedTransactionCache = new FlaggedArraySet<>(TRANSACTIONS_CACHED.get(versionString));
						relayTransactionCache = LimitedSynchronizedObjects.createMap(TRANSACTIONS_CACHED.get(versionString));
						newRelayTransactionCache = new FlaggedArraySet<>(TRANSACTIONS_CACHED.get(versionString));

						protocolVersion = versionString;

						if (!sendVersionOnConnect) {
							sendVersionMessage(relayPeer, versionString);
							if (!RelayNode.VERSION.equals(versionString))
								relayPeer.writeBytes(ByteBuffer.allocate(4 * 3 + RelayNode.VERSION.length()).order(ByteOrder.BIG_ENDIAN)
										.putInt(MAGIC_BYTES).putInt(MessageTypes.MAX_VERSION.ordinal()).putInt(RelayNode.VERSION.length())
										.put(RelayNode.VERSION.getBytes())
										.array());
						}
					}
					return 3*4 + msgLength;

				case MAX_VERSION:
					versionBytes = new byte[msgLength];
					buff.get(versionBytes);
					versionString = new String(versionBytes);

					LogLine("WARNING: Connected to node with a higher max version (PLEASE UPGRADE): " + versionString.replaceAll("[^ -~]", ""));
					return 3*4 + msgLength;

				case BLOCK:
					if (protocolVersion == null)
						throw new ProtocolException("Got BLOCK before VERSION");
					if (readingBlock != null)
						throw new ProtocolException("readingBlock already present");

					byte[] headerBytes = new byte[Block.HEADER_SIZE];
					buff.get(headerBytes);
					PendingBlock block = new PendingBlock(new Block(params, headerBytes));

					RelayMode mode = RELAY_MODE.get(protocolVersion);

					int transactionCount = mode == RelayMode.ABBREV_HASH ? buff.getInt(): msgLength;
					if (mode == RelayMode.ABBREV_HASH && QuarterHash.BYTE_LENGTH * transactionCount + Block.HEADER_SIZE + 4 != msgLength)
						throw new ProtocolException("transactionCount: " + transactionCount + ", msgLength: " + msgLength);

					receiveBlockHeader(block.header);
					relayedBlockCache.add(block.header.getHash());

					transactionsLeft = transactionCount;
					readingBlock = block;
					bytesInBlock = 4 * 3 + Block.HEADER_SIZE;
					return 4 * (mode == RelayMode.ABBREV_HASH ? 4 : 3) + Block.HEADER_SIZE + receiveBytes(buff);

				case TRANSACTION:
					if (protocolVersion == null)
						throw new ProtocolException("Got TRANSACTION before VERSION");
					if (readingBlock == null && (msgLength > MAX_RELAY_TRANSACTION_BYTES.get(protocolVersion) &&
							(msgLength > MAX_RELAY_OVERSIZE_TXN_BYTES.get(protocolVersion) || newRelayTransactionCache.flagCount() >= MAX_EXTRA_OVERSIZE_TXN.get(protocolVersion))))
						throw new ProtocolException("Too large free transaction relayed");

					readingTransaction = new byte[msgLength];
					readingTransactionPos = 0;
					if (readingBlock == null)
						return 3*4 + receiveBytes(buff);
					else
						return 4 + receiveBytes(buff);

				case END_BLOCK:
					if (protocolVersion == null)
						throw new ProtocolException("Got END_BLOCK before VERSION");
					if (readingBlock == null)
						throw new ProtocolException("END_BLOCK without BLOCK");
					if (readingBlock.pendingTransactionCount > 0)
						throw new ProtocolException("pendingTransactionCount " + readingBlock.pendingTransactionCount);

					bytesInBlock += 4*3;

					readingBlock.buildBlock();

					txnSkippedTotal += (txnInBlock - txnRelayedInBlock);

					LogStatsRecv("Skipped: " + (txnInBlock - txnRelayedInBlock) + "/" + txnInBlock +
							" (" + ((txnInBlock - txnRelayedInBlock + 0.0) / txnInBlock) + "%)\n" +
							"in block " + readingBlock.header.getHashAsString() + "\n" +
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
			LogLine("Corrupted data read from relay peer " + e.getClass().toString() + ": " + e.getMessage());
			LogLine(" at " + e.getStackTrace()[0].getFileName() + ":" + e.getStackTrace()[0].getLineNumber());
			relayPeer.closeConnection();
			return 0;
		} catch (IOException e) {
			LogLine("Failed to write bytes");
			return -1;
		}
		throw new RuntimeException();
	}

	private void sendVersionMessage(@Nonnull MessageWriteTarget writeTarget, @Nonnull String version) {
		try {
			writeTarget.writeBytes(ByteBuffer.allocate(4 * 3 + version.length())
					.putInt(MAGIC_BYTES).putInt(MessageTypes.VERSION.ordinal()).putInt(version.length())
					.put(version.getBytes())
					.array());
		} catch (IOException e) {
			/* Should get a disconnect automatically */
			LogLine("Failed to write VERSION_INIT");
		}
	}

	@Override
	public void setWriteTarget(@Nonnull MessageWriteTarget writeTarget) {
		if (sendVersionOnConnect)
			sendVersionMessage(writeTarget, RelayNode.VERSION);
		relayPeer = writeTarget;
	}

	@Override
	public int getMaxMessageSize() {
		return Block.MAX_BLOCK_SIZE; // Its bigger than 64k, so buffers will just be 64k in size
	}
}
