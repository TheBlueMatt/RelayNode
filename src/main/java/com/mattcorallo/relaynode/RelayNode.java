/*
 * Relay Node Server
 *
 * Copyright (C) 2013 Matt Corallo <git@bluematt.me>
 *
 * This is free software: you can redistribute it under the
 * terms in the LICENSE file.
 */

package com.mattcorallo.relaynode;

import com.google.bitcoin.core.*;
import com.google.bitcoin.net.NioClientManager;
import com.google.bitcoin.net.NioServer;
import com.google.bitcoin.net.StreamParser;
import com.google.bitcoin.net.StreamParserFactory;
import com.google.bitcoin.params.MainNetParams;
import com.google.bitcoin.store.BlockStore;
import com.google.bitcoin.store.BlockStoreException;
import com.google.bitcoin.store.MemoryBlockStore;
import com.google.bitcoin.utils.Threading;
import com.google.common.base.Preconditions;
import com.google.common.util.concurrent.Uninterruptibles;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.NotYetConnectedException;
import java.util.*;
import java.util.concurrent.*;

/**
 * Keeps a peer and a set of invs which it has told us about (ie that it has data for)
 */
class PeerAndInvs {
	Peer p;
	Set<InventoryItem> invs = LimitedSynchronizedObjects.createSet(500);

	public PeerAndInvs(@NotNull Peer p) {
		this.p = p;
		p.addEventListener(new AbstractPeerEventListener() {
			@Override
			public Message onPreMessageReceived(Peer p, Message m) {
				if (m instanceof InventoryMessage) {
					for (InventoryItem item : ((InventoryMessage) m).getItems())
						invs.add(item);
				} else if (m instanceof Transaction)
					invs.add(new InventoryItem(InventoryItem.Type.Transaction, m.getHash()));
				else if (m instanceof Block)
					invs.add(new InventoryItem(InventoryItem.Type.Block, m.getHash()));
				return m;
			}
		}, Threading.SAME_THREAD);
	}

	public void maybeRelay(Message m) {
		Preconditions.checkArgument(m instanceof Block || m instanceof Transaction);

		InventoryItem item;
		if (m instanceof Block)
			item = new InventoryItem(InventoryItem.Type.Block, m.getHash());
		else
			item = new InventoryItem(InventoryItem.Type.Transaction, m.getHash());

		if (invs.add(item)) {
			try {
				p.sendMessage(m);
			} catch (NotYetConnectedException e) { /* We'll get them next time */ }
		}
	}

	@Override public boolean equals(Object o) { return o instanceof PeerAndInvs && ((PeerAndInvs)o).p == this.p; }
	@Override public int hashCode() { return p.hashCode(); }
}

/**
 * Keeps track of a set of PeerAndInvs
 */
class Peers {
	private final Set<PeerAndInvs> peers = Collections.synchronizedSet(new HashSet<PeerAndInvs>());

	@NotNull
	public PeerAndInvs add(@NotNull Peer p) {
		PeerAndInvs peerAndInvs = new PeerAndInvs(p);
		add(peerAndInvs);
		return peerAndInvs;
	}

	public boolean add(@NotNull final PeerAndInvs peerAndInvs) {
		if (peers.add(peerAndInvs)) {
			peerAndInvs.p.addEventListener(new AbstractPeerEventListener() {
				@Override
				public void onPeerDisconnected(Peer peer, int peerCount) {
					peers.remove(peerAndInvs);
				}
			}, Threading.SAME_THREAD);
			return true;
		}
		return false;
	}

	public int size() { return peers.size(); }

	public void relayObject(Message m) {
		PeerAndInvs[] peersArr;
		synchronized (peers) {
			peersArr = peers.toArray(new PeerAndInvs[peers.size()]);
		}
		for (PeerAndInvs p : peersArr)
			p.maybeRelay(m);
	}
}

/**
 * Keeps track of the set of known blocks and transactions for relay
 */
abstract class Pool<Type extends Message> {
	abstract int relayedCacheSize();

	class AddedObject {
		Sha256Hash hash;
		long removeTime = System.currentTimeMillis() + 60*1000;
		AddedObject(Sha256Hash hash) { this.hash = hash; }
	}
	final List<AddedObject> removeObjectList = Collections.synchronizedList(new LinkedList<AddedObject>());

	@NotNull
	Map<Sha256Hash, Type> objects = new HashMap<Sha256Hash, Type>() {
		@Override
		public Type put(Sha256Hash key, Type value) {
			removeObjectList.add(new AddedObject(key));
			return super.put(key, value);
		}
	};
	Set<Sha256Hash> objectsRelayed = LimitedSynchronizedObjects.createSet(relayedCacheSize());

	Peers trustedOutboundPeers;
	public Pool(Peers trustedOutboundPeers) {
		this.trustedOutboundPeers = trustedOutboundPeers;
		Thread t = new Thread(new Runnable() {
			@Override
			public void run() {
				while (true) {
					synchronized (removeObjectList) {
						long targetTime = System.currentTimeMillis();
						try {
							for (AddedObject o = removeObjectList.get(0); o.removeTime < targetTime; o = removeObjectList.get(0)) {
								objects.remove(o.hash);
								removeObjectList.remove(0);
							}
						} catch (IndexOutOfBoundsException e) { /* Already removed? */}
					}
					Uninterruptibles.sleepUninterruptibly(1, TimeUnit.SECONDS);
				}
			}
		});
		t.setName("Pool Invalid Object Remover");
		t.start();
	}

	public synchronized boolean shouldRequestInv(Sha256Hash hash) {
		return !objectsRelayed.contains(hash) && !objects.containsKey(hash);
	}

	public @Nullable Type getObject(Sha256Hash hash) {
		return objects.get(hash);
	}

	public void provideObject(@NotNull final Type m) {
		synchronized (this) {
			if (!objectsRelayed.contains(m.getHash()))
				objects.put(m.getHash(), m);
		}
		trustedOutboundPeers.relayObject(m);
	}

	public void invGood(@NotNull final Peers clients, final Sha256Hash hash) {
		boolean relay = false;
		Type o;
		synchronized (Pool.this) {
			o = objects.remove(hash);
			if (!objectsRelayed.contains(hash)) {
				objectsRelayed.add(hash);
				if (o != null)
					relay = true;
			}
		}
		if (relay)
			clients.relayObject(o);
	}
}

class BlockPool extends Pool<Block> {
	public BlockPool(Peers trustedOutboundPeers) {
		super(trustedOutboundPeers);
	}

	@Override
	int relayedCacheSize() {
		return 100;
	}
}

class TransactionPool extends Pool<Transaction> {
	public TransactionPool(Peers trustedOutboundPeers) {
		super(trustedOutboundPeers);
	}

	@Override
	int relayedCacheSize() {
		return 10000;
	}
}

/**
 * A RelayNode which is designed to relay blocks/txn from a set of untrusted peers, through a trusted bitcoind, to the
 * rest of the untrusted peers. It does no verification and trusts everything that comes from the trusted bitcoind is
 * good to relay.
 */
public class RelayNode {
	public static final String VERSION = "prioritized panther";

	public static void main(String[] args) throws Exception {
		new RelayNode().run(8334, 8335, 8336);
	}

	// We do various things async to avoid blocking network threads on expensive processing
	@NotNull
	public static Executor asyncExecutor = Executors.newCachedThreadPool();

	NetworkParameters params = MainNetParams.get();
	@NotNull
	VersionMessage versionMessage = new VersionMessage(params, 0);

	@NotNull
	Peers trustedOutboundPeers = new Peers();

	@NotNull
	TransactionPool txPool = new TransactionPool(trustedOutboundPeers);
	@NotNull
	BlockPool blockPool = new BlockPool(trustedOutboundPeers);

	@NotNull
	BlockStore blockStore = new MemoryBlockStore(params);
	BlockChain blockChain;


	/******************************************
	 ***** Stuff to keep track of clients *****
	 ******************************************/
	final Peers txnClients = new Peers();
	final Peers blocksClients = new Peers();
	@NotNull
	RelayConnectionListener relayClients;
	@NotNull
	PeerEventListener clientPeerListener = new AbstractPeerEventListener() {
		@Nullable
		@Override
		public Message onPreMessageReceived(@NotNull final Peer p, final Message m) {
			if (m instanceof InventoryMessage) {
				GetDataMessage getDataMessage = new GetDataMessage(params);
				for (InventoryItem item : ((InventoryMessage)m).getItems()) {
					if (item.type == InventoryItem.Type.Block) {
						if (blockPool.shouldRequestInv(item.hash))
							getDataMessage.addBlock(item.hash);
					} else if (item.type == InventoryItem.Type.Transaction) {
						if (txPool.shouldRequestInv(item.hash))
							getDataMessage.addTransaction(item.hash);
					}
				}
				if (!getDataMessage.getItems().isEmpty())
					p.sendMessage(getDataMessage);
			} else if (m instanceof Block) {
				asyncExecutor.execute(new Runnable() {
					@Override
					public void run() {
						blockPool.provideObject((Block) m); // This will relay to trusted peers, just in case we reject something we shouldn't
						try {
							if (blockStore.get(m.getHash()) == null && blockChain.add(((Block) m).cloneAsHeader())) {
								relayClients.sendBlock((Block) m);
								blockPool.invGood(blocksClients, m.getHash());
								LogBlockRelay(m.getHash(), "SPV check", p.getAddress().getAddr(), null);
							}
						} catch (Exception e) { /* Invalid block, don't relay it */ }
					}
				});
			} else if (m instanceof Transaction) {
				txPool.provideObject((Transaction) m);
				try {
					((Transaction) m).verify();
				} catch (VerificationException e) {
					return null; // Swallow "Transaction had no inputs or no outputs" without disconnecting client
				}
			}
			return m;
		}
	};


	/************************************************
	 ***** Stuff to keep track of trusted peers *****
	 ************************************************/

	/** Manages reconnecting to trusted peers and relay nodes, often sleeps */
	@NotNull
	private static ScheduledExecutorService reconnectExecutor = Executors.newScheduledThreadPool(1);

	/** Keeps track of a trusted peer connection (two connections per peer) */
	class TrustedPeerConnections {
		/** We only receive messages here (listen for invs of validated data) */
		@Nullable
		public Peer inbound;
		/** We only send messages here (send unvalidated data) */
		@Nullable
		public Peer outbound;
		/** The address to (re)connect to */
		public InetSocketAddress addr;

		public volatile boolean inboundConnected = false; // Flag for UI only, very racy, often wrong
		public volatile boolean outboundConnected = false; // Flag for UI only, very racy, often wrong

		private synchronized void disconnect() {
			if (inbound != null)
				inbound.close(); // Double-check closed
			inbound = null;
			inboundConnected = false;

			if (outbound != null)
				outbound.close(); // Double-check closed
			outbound = null;
			outboundConnected = false;
		}

		private synchronized void connect() {
			disconnect();

			versionMessage.time = System.currentTimeMillis()/1000;
			inbound = new Peer(params, versionMessage, null, new PeerAddress(addr));
			inbound.addEventListener(trustedPeerInboundListener, Threading.SAME_THREAD);
			inbound.addEventListener(trustedPeerDisconnectListener);
			inbound.addEventListener(new AbstractPeerEventListener() {
				@Override
				public void onPeerConnected(Peer p, int peerCount) {
					inboundConnected = true;
				}
			});
			trustedPeerManager.openConnection(addr, inbound);

			outbound = new Peer(params, versionMessage, blockChain, new PeerAddress(addr));
			trustedOutboundPeers.add(outbound);
			outbound.addEventListener(trustedPeerDisconnectListener);
			outbound.addEventListener(new AbstractPeerEventListener() {
				@Override
				public void onPeerConnected(Peer p, int peerCount) {
					outbound.setDownloadParameters(Long.MAX_VALUE, false);
					outbound.startBlockChainDownload();
					outboundConnected = true;
				}
			});
			trustedPeerManager.openConnection(addr, outbound);
		}

		public synchronized void onDisconnect() {
			disconnect();

			reconnectExecutor.schedule(new Runnable() {
				@Override
				public void run() {
					synchronized (TrustedPeerConnections.this) {
						if (inbound == null || outbound == null) {
							disconnect();
							connect();
						}
					}
				}
			}, 1, TimeUnit.SECONDS);
		}

		public TrustedPeerConnections(@NotNull InetSocketAddress addr) {
			this.addr = addr;
			connect();
			trustedPeerConnectionsMap.put(addr.getAddress(), this);
		}
	}

	final Map<InetAddress, TrustedPeerConnections> trustedPeerConnectionsMap = Collections.synchronizedMap(new HashMap<InetAddress, TrustedPeerConnections>());
	@NotNull
	NioClientManager trustedPeerManager = new NioClientManager();
	@NotNull
	PeerEventListener trustedPeerInboundListener = new AbstractPeerEventListener() {
		@Override
		public Message onPreMessageReceived(@NotNull final Peer p, final Message m) {
			if (m instanceof InventoryMessage) {
				GetDataMessage getDataMessage = new GetDataMessage(params);
				final List<Sha256Hash> blocksGood = new LinkedList<>();
				final List<Sha256Hash> txGood = new LinkedList<>();
				for (InventoryItem item : ((InventoryMessage)m).getItems()) {
					if (item.type == InventoryItem.Type.Block) {
						if (blockPool.shouldRequestInv(item.hash))
							getDataMessage.addBlock(item.hash);
						else
							blocksGood.add(item.hash);
					} else if (item.type == InventoryItem.Type.Transaction) {
						if (txPool.shouldRequestInv(item.hash))
							getDataMessage.addTransaction(item.hash);
						else
							txGood.add(item.hash);
					}
				}
				if (!getDataMessage.getItems().isEmpty())
					p.sendMessage(getDataMessage);
				if (!blocksGood.isEmpty())
					asyncExecutor.execute(new Runnable() {
						@Override
						public void run() {
							for (Sha256Hash hash : blocksGood) {
								Block b = blockPool.getObject(hash);
								if (b != null)
									relayClients.sendBlock(b);
								blockPool.invGood(blocksClients, hash);
								LogBlockRelay(hash, "trusted inv", p.getAddress().getAddr(), null);
							}
						}
					});
				if (!txGood.isEmpty())
					asyncExecutor.execute(new Runnable() {
						@Override
						public void run() {
							for (Sha256Hash hash : txGood) {
								Transaction t = txPool.getObject(hash);
								if (t != null)
									relayClients.sendTransaction(t);
								txPool.invGood(txnClients, hash);
							}
						}
					});
			} else if (m instanceof Transaction) {
				asyncExecutor.execute(new Runnable() {
					@Override
					public void run() {
						relayClients.sendTransaction((Transaction) m);
						txPool.provideObject((Transaction) m);
						txPool.invGood(txnClients, m.getHash());
					}
				});
			} else if (m instanceof Block) {
				asyncExecutor.execute(new Runnable() {
					@Override
					public void run() {
						relayClients.sendBlock((Block) m);
						blockPool.provideObject((Block) m);
						blockPool.invGood(blocksClients, m.getHash());
						LogBlockRelay(m.getHash(), "trusted block", p.getAddress().getAddr(), null);
						try {
							blockChain.add(((Block) m).cloneAsHeader());
						} catch (Exception e) {
							LogLine("WARNING: Exception adding block from trusted peer " + p.getAddress());
						}
					}
				});
			}
			return m;
		}
	};

	@NotNull
	PeerEventListener trustedPeerDisconnectListener = new AbstractPeerEventListener() {
		@Override
		public void onPeerDisconnected(@NotNull Peer peer, int peerCount) {
			TrustedPeerConnections connections = trustedPeerConnectionsMap.get(peer.getAddress().getAddr());
			if (connections == null)
				return;
			connections.onDisconnect();
		}
	};


	/*******************************************************************
	 ***** Stuff to keep track of other relay nodes which we trust *****
	 *******************************************************************/
	final Set<InetSocketAddress> relayPeersWaitingOnReconnection = Collections.synchronizedSet(new HashSet<InetSocketAddress>());
	final Set<InetSocketAddress> relayPeersConnected = Collections.synchronizedSet(new HashSet<InetSocketAddress>());

	/***************************
	 ***** Stuff that runs *****
	 ***************************/
	FileWriter relayLog;
	public RelayNode() throws BlockStoreException, IOException {
		versionMessage.appendToSubVer("RelayNode", VERSION, null);
		// Fudge a few flags so that we can connect to other relay nodes
		versionMessage.localServices = VersionMessage.NODE_NETWORK;
		versionMessage.bestHeight = 1;

		relayLog = new FileWriter("blockrelay.log", true);

		trustedPeerManager.startAsync().awaitRunning();

		blockChain = new BlockChain(params, blockStore);
	}

	public void run(int onlyBlocksListenPort, int bothListenPort, int relayListenPort) {
		Threading.uncaughtExceptionHandler = new Thread.UncaughtExceptionHandler() {
			@Override
			public void uncaughtException(@NotNull Thread t, @NotNull Throwable e) {
				LogLine("Uncaught exception in thread " + t.getName());
				UnsafeByteArrayOutputStream o = new UnsafeByteArrayOutputStream();
				PrintStream b = new PrintStream(o);
				e.printStackTrace(b);
				b.close();
				for (String s : new String(o.toByteArray()).split("\n"))
					LogLine(s);
				LogLine(e.toString());
			}
		};
		// Listen for incoming client connections
		try {
			NioServer onlyBlocksServer = new NioServer(new StreamParserFactory() {
				@Nullable
				@Override
				public StreamParser getNewParser(InetAddress inetAddress, int port) {
					versionMessage.time = System.currentTimeMillis()/1000;
					Peer p = new Peer(params, versionMessage, null, new PeerAddress(inetAddress, port));
					blocksClients.add(p); // Should come first to avoid relaying back to the sender
					p.addEventListener(clientPeerListener, Threading.SAME_THREAD);
					return p;
				}
			}, new InetSocketAddress(onlyBlocksListenPort));

			NioServer bothServer = new NioServer(new StreamParserFactory() {
				@Nullable
				@Override
				public StreamParser getNewParser(InetAddress inetAddress, int port) {
					versionMessage.time = System.currentTimeMillis()/1000;
					Peer p = new Peer(params, versionMessage, null, new PeerAddress(inetAddress, port));
					txnClients.add(blocksClients.add(p)); // Should come first to avoid relaying back to the sender
					p.addEventListener(clientPeerListener, Threading.SAME_THREAD);
					return p;
				}
			}, new InetSocketAddress(bothListenPort));

			relayClients = new RelayConnectionListener(relayListenPort, clientPeerListener, this);

			onlyBlocksServer.startAsync().awaitRunning();
			bothServer.startAsync().awaitRunning();
		} catch (IOException e) {
			System.err.println("Failed to bind to port");
			System.exit(1);
		}

		// Print stats
		new Thread(new Runnable() {
			@Override
			public void run() {
				printStats();
			}
		}).start();

		WatchForUserInput();
	}

	public void WatchForUserInput() {
		// Get user input
		Scanner scanner = new Scanner(System.in);
		String line;
		while (true) {
			line = scanner.nextLine();
			if (line.equals("q")) {
				System.out.println("Quitting...");
				// Wait...cleanup? naaaaa
				System.exit(0);
			} else if (line.startsWith("t ")) {
				String[] hostPort = line.substring(2).split(":");
				if (hostPort.length != 2) {
					LogLineEnter("Invalid argument");
					continue;
				}
				try {
					int port = Integer.parseInt(hostPort[1]);
					InetSocketAddress addr = new InetSocketAddress(hostPort[0], port);
					if (addr.isUnresolved())
						LogLineEnter("Unable to resolve host");
					else {
						if (trustedPeerConnectionsMap.containsKey(addr.getAddress())) {
							LogLineEnter("Already had trusted peer " + addr);
						} else {
							new TrustedPeerConnections(addr);
							LogLineEnter("Added trusted peer " + addr);
						}
					}
				} catch (NumberFormatException e) {
					LogLineEnter("Invalid argument");
				}
			} else if (line.startsWith("r ")) {
				try {
					InetSocketAddress addr = new InetSocketAddress(line.substring(2), 8336);
					if (addr.isUnresolved())
						LogLineEnter("Unable to resolve host");
					else {
						ConnectToTrustedRelayPeer(addr);
						LogLineEnter("Added trusted relay peer " + addr);
					}
				} catch (NumberFormatException e) {
					LogLineEnter("Invalid argument");
				}
			} else {
				LogLineEnter("Invalid command");
			}
		}
	}

	public void ConnectToTrustedRelayPeer(@NotNull final InetSocketAddress address) {
		RelayConnection connection = new RelayConnection(true) {
			String recvStats = "";
			@Override
			void LogLine(String line) {
				RelayNode.this.LogLine(line);
			}

			@Override void LogStatsRecv(String lines) {
				for (String line : lines.split("\n"))
					recvStats += "STATS: " + line + "\n";
			}

			@Override
			void LogConnected(String line) {
				RelayNode.this.LogLine(line);
			}

			@Override
			void receiveBlockHeader(Block b) { }

			@Override
			void receiveBlock(@NotNull final Block b) {
				asyncExecutor.execute(new Runnable() {
					@Override
					public void run() {
						relayClients.sendBlock(b);
						blockPool.provideObject(b);
						blockPool.invGood(blocksClients, b.getHash());
						LogBlockRelay(b.getHash(), "relay peer", address.getAddress(), recvStats);
						recvStats = "";
						try {
							blockChain.add(b.cloneAsHeader());
						} catch (Exception e) {
							LogLine("WARNING: Exception adding block from relay peer " + address);
							// Force reconnect of trusted peer(s)
							synchronized (trustedPeerConnectionsMap) {
								for (TrustedPeerConnections peer : trustedPeerConnectionsMap.values())
									peer.onDisconnect();
							}
						}
					}
				});
			}

			@Override void receiveTransaction(Transaction t) { }

			@Override
			public void connectionClosed() {
				relayPeersConnected.remove(address);
				relayPeersWaitingOnReconnection.add(address);
				reconnectExecutor.schedule(new Runnable() {
					@Override
					public void run() {
						ConnectToTrustedRelayPeer(address);
					}
				}, 1, TimeUnit.SECONDS);
			}

			@Override
			public void connectionOpened() {
				relayPeersConnected.add(address);
				relayPeersWaitingOnReconnection.remove(address);
			}
		};
		trustedPeerManager.openConnection(address, connection);
		relayPeersWaitingOnReconnection.add(address);
	}

	final Queue<String> logLines = new LinkedList<>();
	int enterPressed = 0;
	public void LogLine(String line) {
		synchronized (logLines) {
			logLines.add(line);
		}
	}
	public void LogLineEnter(String line) {
		synchronized (logLines) {
			logLines.add(line);
			enterPressed++;
		}
	}

	Set<Sha256Hash> blockRelayedSet = Collections.synchronizedSet(new HashSet<Sha256Hash>());
	public void LogBlockRelay(@NotNull Sha256Hash blockHash, String source, @NotNull InetAddress remote, String statsLines) {
		if (blockRelayedSet.contains(blockHash))
			return;
		blockRelayedSet.add(blockHash);
		source = source + " from " + remote.getHostAddress() + "/" + RDNS.getRDNS(remote);
		LogLine(blockHash.toString().substring(4, 32) + " relayed (" + source + ") " + System.currentTimeMillis());
		try {
			relayLog.write(blockHash + " " + System.currentTimeMillis() + " " + source + "\n");
			if (statsLines != null)
				relayLog.write(statsLines);
			relayLog.flush();
		} catch (IOException e) {
			System.err.println("Failed to write to relay log");
			System.exit(1);
		}
	}

	public void printStats() {
		// Things may break if your column count is too small
		boolean firstIteration = true;
		int linesPrinted = 0;
		while (true) {
			int prevLinesPrinted = linesPrinted;
			linesPrinted = 0;
			int linesLogged = 0;

			StringBuilder output = new StringBuilder();

			if (!firstIteration) {
				synchronized (logLines) {
					output.append("\033[s\033[1000D"); // Save cursor position + move to first char

					for (int i = 0; i < logLines.size() - enterPressed; i++)
						output.append("\n"); // Move existing log lines up

					for (int i = 0; i < prevLinesPrinted; i++)
						output.append("\033[1A\033[K"); // Up+clear linesPrinted lines

					for (int i = 0; i < logLines.size(); i++)
						output.append("\033[1A\033[K"); // Up and make sure we're at the beginning, clear line
					for (String line : logLines)
						output.append(line).append("\n");

					linesLogged = logLines.size() - enterPressed;
					logLines.clear(); enterPressed = 0;
				}
			}

			if (trustedPeerConnectionsMap.isEmpty()) {
				output.append("\nNo trusted nodes (no transaction relay)").append("\n"); linesPrinted += 2;
			} else {
				output.append("\nTrusted nodes: ").append("\n"); linesPrinted += 2;
				synchronized (trustedPeerConnectionsMap) {
					for (Map.Entry<InetAddress, TrustedPeerConnections> entry : trustedPeerConnectionsMap.entrySet()) {
						String status;
						if (entry.getValue().inboundConnected && entry.getValue().outboundConnected)
							status = " fully connected";
						else if (entry.getValue().inboundConnected)
							status = " inbound connection only";
						else if (entry.getValue().outboundConnected)
							status = " outbound connection only";
						else
							status = " not connected";
						output.append("  ").append(entry.getValue().addr).append(status).append("\n");
						linesPrinted++;
					}
				}
			}

			Set<InetAddress> relayPeers = relayClients.getClientSet();
			int relayClientCount = 0;
			if (relayPeersWaitingOnReconnection.isEmpty() && relayPeersConnected.isEmpty()) {
				output.append("\nNo relay peers").append("\n"); linesPrinted += 2;
			} else {
				output.append("\nRelay peers:").append("\n"); linesPrinted += 2;

				synchronized (relayPeersConnected) {
					for (InetSocketAddress peer : relayPeersConnected) { // If its not connected, its not in the set
						if (relayPeers.contains(peer.getAddress())) {
							output.append("  ").append(peer.getAddress()).append(" fully connected").append("\n"); linesPrinted++;
							relayClientCount++;
						} else {
							output.append("  ").append(peer.getAddress()).append(" connected outbound only").append("\n"); linesPrinted++;
						}
					}
				}
				synchronized (relayPeersWaitingOnReconnection) {
					for (InetSocketAddress a : relayPeersWaitingOnReconnection) {
						if (relayPeers.contains(a.getAddress())) {
							output.append("  ").append(a.getAddress()).append(" connected inbound only").append("\n"); linesPrinted++;
							relayClientCount++;
						} else {
							output.append("  ").append(a.getAddress()).append(" not connected").append("\n"); linesPrinted++;
						}
					}
				}
			}

			output.append("\n"); linesPrinted++;
			output.append("Connected block+transaction clients: ").append(txnClients.size()).append("\n"); linesPrinted++;
			output.append("Connected block-only clients: ").append(blocksClients.size() - txnClients.size()).append("\n"); linesPrinted++;
			output.append("Connected relay clients: ").append(relayPeers.size() - relayClientCount).append("\n"); linesPrinted++;
			output.append("Connected relay node peers: ").append(relayClientCount).append("\n"); linesPrinted++;
			output.append("Chain download at ").append(blockChain.getBestChainHeight()).append("\n"); linesPrinted++;

			output.append("\n"); linesPrinted++;
			output.append("Commands:").append("\n"); linesPrinted++;
			output.append("q        \t\tquit").append("\n"); linesPrinted++;
			output.append("t IP:port\t\tadd node IP:port as a trusted peer").append("\n"); linesPrinted++;
			output.append("r IP\t\t\tadd trusted relay node to relay from").append("\n"); linesPrinted++;

			if (firstIteration)
				output.append("\n");
			else
				output.append("\033[u");
			firstIteration = false;

			if (linesLogged > 0)
				output.append("\033[").append(linesLogged).append("B");

			System.out.print(output.toString());
			System.out.flush();

			Uninterruptibles.sleepUninterruptibly(500, TimeUnit.MILLISECONDS);
		}
	}
}
