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
import com.google.bitcoin.params.MainNetParams;
import com.google.bitcoin.store.BlockStoreException;
import com.google.bitcoin.utils.Threading;
import com.google.common.util.concurrent.Uninterruptibles;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.NotYetConnectedException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.Lock;

/**
 * Keeps track of a set of PeerAndInvs
 */
class Peers {
	Semaphore lock = new Semaphore(1);
	private final Set<Peer> peers = Collections.synchronizedSet(new HashSet<Peer>());

	public boolean add(@Nonnull final Peer p) {
		if (peers.add(p)) {
			p.addEventListener(new AbstractPeerEventListener() {
				@Override
				public void onPeerDisconnected(Peer peer, int peerCount) {
					try { lock.acquire(); } catch (InterruptedException e) { throw new RuntimeException(e); }
					peers.remove(p);
					lock.release();
				}
			});
			return true;
		}
		return false;
	}

	public int size() { return peers.size(); }

	public void relayObject(Message m) {
		try { lock.acquire(); } catch (InterruptedException e) { throw new RuntimeException(e); }
		for (Peer p : peers) {
			try {
				p.sendMessage(m);
			} catch (NotYetConnectedException e) { /* We'll catch them next time */ }
		}
		lock.release();
	}
}

/**
 * A RelayNode which is designed to relay blocks/txn from a set of untrusted peers, through a trusted bitcoind, to the
 * rest of the untrusted peers. It does no verification and trusts everything that comes from the trusted bitcoind is
 * good to relay.
 */
public class RelayNode {
	public static final String VERSION = "toucan twink";

	public static void main(String[] args) throws Exception {
		new RelayNode().run(8336);
	}

	NetworkParameters params = MainNetParams.get();
	@Nonnull
	VersionMessage versionMessage = new VersionMessage(params, 0);

	@Nonnull
	Peers trustedOutboundPeers = new Peers();

	@Nonnull
	UnlimitedMemoryBlockStore blockStore = new UnlimitedMemoryBlockStore(params);
	BlockChain blockChain;

	Set<Sha256Hash> txnRelayed = LimitedSynchronizedObjects.createSet(2500);


	/******************************************
	 ***** Stuff to keep track of clients *****
	 ******************************************/
	@Nonnull
	RelayConnectionListener relayClients;
	@Nonnull
	Peers untrustedPeers = new Peers();

	@Nonnull
	PeerEventListener untrustedPeerListener = new AbstractPeerEventListener() {
		@Nullable
		@Override
		public Message onPreMessageReceived(@Nonnull final Peer p, final Message m) {
			if (m instanceof InventoryMessage) {
				GetDataMessage getDataMessage = new GetDataMessage(params);
				for (InventoryItem item : ((InventoryMessage)m).getItems()) {
					if (item.type == InventoryItem.Type.Block) {
						if (blockStore.get(item.hash) != null)
							getDataMessage.addBlock(item.hash);
					} else if (item.type == InventoryItem.Type.Transaction) {
						if (!txnRelayed.contains(item.hash))
							getDataMessage.addTransaction(item.hash);
					}
				}
				if (!getDataMessage.getItems().isEmpty())
					p.sendMessage(getDataMessage);
				return null;
			} else if (m instanceof Block) {
				try {
					long timeRecv = System.currentTimeMillis();
					if (blockStore.get(m.getHash()) == null && blockChain.add(((Block) m).cloneAsHeader())) {
						long timeRelayStart = System.currentTimeMillis();
						relayClients.sendBlock((Block) m);
						long timeRelayDone = System.currentTimeMillis();
						untrustedPeers.relayObject(m);
						trustedOutboundPeers.relayObject(m);
						if (p.getVersionMessage().subVer.contains("RelayNodeProtocol"))
							LogBlockRelay(m.getHash(), "relay SPV", p.getAddress().getAddr(), null, timeRecv, timeRelayStart, timeRelayDone);
						else
							LogBlockRelay(m.getHash(), "p2p SPV", p.getAddress().getAddr(), null, timeRecv, timeRelayStart, timeRelayDone);
					}
				} catch (Exception e) { /* Invalid block, don't relay it */ }
				return null;
			} else if (m instanceof Transaction) {
				trustedOutboundPeers.relayObject(m);
				return null; // Swallow "Transaction had no inputs or no outputs" without disconnecting client
			}
			return m;
		}
	};


	/************************************************
	 ***** Stuff to keep track of trusted peers *****
	 ************************************************/

	/** Manages reconnecting to trusted peers and relay nodes, often sleeps */
	@Nonnull
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

		boolean closedPermanently = false;

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
			connectionManager.openConnection(addr, inbound);

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
			connectionManager.openConnection(addr, outbound);
		}

		public synchronized void onDisconnect() {
			disconnect();

			if (!closedPermanently)
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

		public void disconnectPermanently() {
			closedPermanently = true;
			disconnect();
			trustedPeerConnectionsMap.remove(addr.getAddress());
		}

		public TrustedPeerConnections(@Nonnull InetSocketAddress addr) {
			this.addr = addr;
			connect();
			trustedPeerConnectionsMap.put(addr.getAddress(), this);
		}
	}

	final Map<InetAddress, TrustedPeerConnections> trustedPeerConnectionsMap = Collections.synchronizedMap(new HashMap<InetAddress, TrustedPeerConnections>());
	@Nonnull
	NioClientManager connectionManager = new NioClientManager();
	@Nonnull
	PeerEventListener trustedPeerInboundListener = new AbstractPeerEventListener() {
		@Override
		public Message onPreMessageReceived(@Nonnull final Peer p, final Message m) {
			if (m instanceof InventoryMessage) {
				GetDataMessage getDataMessage = new GetDataMessage(params);
				for (InventoryItem item : ((InventoryMessage)m).getItems()) {
					if (item.type == InventoryItem.Type.Block)
						getDataMessage.addBlock(item.hash);
					else if (item.type == InventoryItem.Type.Transaction)
						getDataMessage.addTransaction(item.hash);
				}
				if (!getDataMessage.getItems().isEmpty())
					p.sendMessage(getDataMessage);
			} else if (m instanceof Transaction) {
				if (txnRelayed.contains(m.getHash()))
					return null;
				relayClients.sendTransaction((Transaction) m);
				untrustedPeers.relayObject(m);
				txnRelayed.add(m.getHash());
			} else if (m instanceof Block) {
				long timeRecv = System.currentTimeMillis();
				if (blockStore.get(m.getHash()) != null)
					return null;
				long timeRelayStart = System.currentTimeMillis();
				relayClients.sendBlock((Block) m);
				long timeRelayDone = System.currentTimeMillis();
				untrustedPeers.relayObject(m);
				LogBlockRelay(m.getHash(), "trusted block", p.getAddress().getAddr(), null, timeRecv, timeRelayStart, timeRelayDone);
				try {
					blockChain.add(((Block) m).cloneAsHeader());
				} catch (Exception e) {
					LogLine("WARNING: Exception adding block from trusted peer " + p.getAddress());
				}
			}
			return m;
		}
	};

	@Nonnull
	PeerEventListener trustedPeerDisconnectListener = new AbstractPeerEventListener() {
		@Override
		public void onPeerDisconnected(@Nonnull Peer peer, int peerCount) {
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
	final Set<InetSocketAddress> relayPeersDisconnect = Collections.synchronizedSet(new HashSet<InetSocketAddress>());

	/*******************************************************************************************
	 ***** I keep a few outbound peers with nodes that reliably transport blocks regularly *****
	 *******************************************************************************************/
	final Set<InetSocketAddress> outboundP2PWaitingOnReconnection = Collections.synchronizedSet(new HashSet<InetSocketAddress>());
	final Set<InetSocketAddress> outboundP2PConnected = Collections.synchronizedSet(new HashSet<InetSocketAddress>());
	final Set<InetSocketAddress> outboundP2PDisconnect = Collections.synchronizedSet(new HashSet<InetSocketAddress>());

	/***************************
	 ***** Stuff that runs *****
	 ***************************/
	public RelayNode() throws BlockStoreException, IOException {
		versionMessage.appendToSubVer("RelayNode", VERSION, null);
		// Fudge a few flags so that we can connect to other relay nodes
		versionMessage.localServices = VersionMessage.NODE_NETWORK;
		versionMessage.bestHeight = 1;

		connectionManager.startAsync().awaitRunning();

		blockChain = new BlockChain(params, blockStore);
	}

	public void run(int relayListenPort) {
		Threading.uncaughtExceptionHandler = new Thread.UncaughtExceptionHandler() {
			@Override
			public void uncaughtException(@Nonnull Thread t, @Nonnull Throwable e) {
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
			relayClients = new RelayConnectionListener(relayListenPort, untrustedPeerListener, this);
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
			} else if (line.startsWith("t") || line.startsWith("o")) {
				String[] hostPort = line.substring(2).split(":");
				if (hostPort.length != 2) {
					LogLineEnter("Invalid argument");
					continue;
				}
				InetSocketAddress addr;
				try {
					int port = Integer.parseInt(hostPort[1]);
					addr = new InetSocketAddress(hostPort[0], port);
					if (addr.isUnresolved()) {
						LogLineEnter("Unable to resolve host");
						continue;
					}
				} catch (NumberFormatException e) {
					LogLineEnter("Invalid argument");
					continue;
				}
				if (line.startsWith("t ")) {
					if (trustedPeerConnectionsMap.containsKey(addr.getAddress()))
						LogLineEnter("Already had trusted peer " + addr);
					else {
						new TrustedPeerConnections(addr);
						LogLineEnter("Added trusted peer " + addr);
					}
				} else if (line.startsWith("t-")) {
					TrustedPeerConnections conn = trustedPeerConnectionsMap.get(addr.getAddress());
					if (conn == null)
						LogLineEnter("Had no trusted connection to " + addr);
					else {
						conn.disconnectPermanently();
						LogLineEnter("Removed trusted connection to " + addr);
					}
				} else if (line.startsWith("o ")) {
					if (outboundP2PConnected.contains(addr) || outboundP2PWaitingOnReconnection.contains(addr)) {
						LogLineEnter("Already had outbound connection to " + addr);
					} else {
						ConnectToUntrustedBitcoinP2P(addr);
						LogLineEnter("Added outbound connection to " + addr);
					}
				} else if (line.startsWith("o-")) {
					if (!outboundP2PConnected.contains(addr) && !outboundP2PWaitingOnReconnection.contains(addr)) {
						LogLineEnter("Had no outbound connection to " + addr);
					} else {
						outboundP2PDisconnect.add(addr);
						LogLineEnter("Will remove outbound connection to " + addr + " after next disconnect");
					}
				} else
					LogLine("Invalid command");
			} else if (line.startsWith("r")) {
				try {
					InetSocketAddress addr = new InetSocketAddress(line.substring(2), 8336);
					if (addr.isUnresolved())
						LogLineEnter("Unable to resolve host");
					else if (line.startsWith("r ")) {
						if (relayPeersConnected.contains(addr) || relayPeersWaitingOnReconnection.contains(addr))
							LogLineEnter("Already had relay peer " + addr);
						else {
							ConnectToTrustedRelayPeer(addr);
							LogLineEnter("Added trusted relay peer " + addr);
						}
					} else if (line.startsWith("r-")) {
						if (!relayPeersConnected.contains(addr) && !relayPeersWaitingOnReconnection.contains(addr))
							LogLineEnter("Had no relay peer " + addr);
						else {
							relayPeersDisconnect.add(addr);
							LogLineEnter("Will remove relay peer connection to " + addr + " after next disconnect");
						}
					} else
						LogLine("Invalid command");
				} catch (NumberFormatException e) {
					LogLineEnter("Invalid argument");
				}
			} else {
				LogLineEnter("Invalid command");
			}
		}
	}

	public void ConnectToTrustedRelayPeer(@Nonnull final InetSocketAddress address) {
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
			void receiveBlock(@Nonnull final Block b) {
				long timeStart = System.currentTimeMillis();
				if (blockStore.get(b.getHash()) != null)
					return;
				long timeRelayStart = System.currentTimeMillis();
				relayClients.sendBlock(b);
				long timeRelayDone = System.currentTimeMillis();
				untrustedPeers.relayObject(b);
				LogBlockRelay(b.getHash(), "relay peer", address.getAddress(), recvStats, timeStart, timeRelayStart, timeRelayDone);
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

			@Override void receiveTransaction(Transaction t) { }

			@Override
			public void connectionClosed() {
				relayPeersConnected.remove(address);
				if (relayPeersDisconnect.remove(address))
					return;
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
		connectionManager.openConnection(address, connection);
		relayPeersWaitingOnReconnection.add(address);
	}

	public void ConnectToUntrustedBitcoinP2P(@Nonnull final InetSocketAddress address) {
		VersionMessage version = new VersionMessage(params, 42);
		version.appendToSubVer("RelayNode", RelayNode.VERSION, "Outbound - bitcoin-peering@mattcorallo.com");
		Peer peer = new Peer(params, version, null, new PeerAddress(address));
		peer.addEventListener(untrustedPeerListener, Threading.SAME_THREAD);
		peer.addEventListener(new AbstractPeerEventListener() {
			@Override
			public void onPeerDisconnected(Peer peer, int peerCount) {
				outboundP2PConnected.remove(address);
				if (outboundP2PDisconnect.remove(address))
					return;
				outboundP2PWaitingOnReconnection.add(address);
				reconnectExecutor.schedule(new Runnable() {
					@Override
					public void run() {
						ConnectToUntrustedBitcoinP2P(address);
					}
				}, 1, TimeUnit.SECONDS);
			}

			@Override
			public void onPeerConnected(Peer peer, int peerCount) {
				outboundP2PConnected.add(address);
				outboundP2PWaitingOnReconnection.remove(address);
			}
		});
		untrustedPeers.add(peer);
		connectionManager.openConnection(address, peer);
		outboundP2PWaitingOnReconnection.add(address);
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
	@Nonnull
	public static Executor logExecutor = Executors.newFixedThreadPool(1);
	public void LogBlockRelay(@Nonnull final Sha256Hash blockHash, final String source, @Nonnull final InetAddress remote,
							  final String statsLines, final long timeRecv, final long timeRelayStart, final long timeRelayDone) {
		final long timeDone = System.currentTimeMillis();
		logExecutor.execute(new Runnable() {
			@Override
			public void run() {
				if (blockRelayedSet.contains(blockHash))
					return;
				blockRelayedSet.add(blockHash);
				String psource = source + " from " + remote.getHostAddress() + "/" + RDNS.getRDNS(remote);
				LogLine(blockHash.toString().substring(4, 32) + " relayed (" + psource + ") " + timeDone +
						" (" + (timeRelayStart - timeRecv) + ", " + (timeRelayDone - timeRelayStart) + ", " + (timeDone - timeRelayDone) + ")");
				try {
					FileWriter relayLog = new FileWriter("blockrelay.log", true);
					relayLog.write(blockHash + " " + timeDone + " " + psource + " " + (timeRelayStart - timeRecv) + (timeRelayDone - timeRelayStart) + " " + (timeDone - timeRelayDone) + "\n");
					if (statsLines != null)
						relayLog.write(statsLines);
					relayLog.close();
				} catch (IOException e) {
					LogLine("Failed to write relay log");
					System.exit(1);
				}
				System.gc();
			}
		});
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
				output.append("\nNo Trusted Nodes (no transaction relay)").append("\n"); linesPrinted += 2;
			} else {
				output.append("\nTrusted Nodes: ").append("\n"); linesPrinted += 2;
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
				output.append("\nNo Relay Peers").append("\n"); linesPrinted += 2;
			} else {
				output.append("\nRelay Peers:").append("\n"); linesPrinted += 2;

				synchronized (relayPeersConnected) {
					for (InetSocketAddress peer : relayPeersConnected) { // If its not connected, its not in the set
						if (relayPeers.contains(peer.getAddress())) {
							output.append("  ").append(peer.getAddress())
									.append(relayPeersDisconnect.contains(peer) ? " waiting on disconnect" : " fully connected")
									.append("\n"); linesPrinted++;
							relayClientCount++;
						} else {
							output.append("  ").append(peer.getAddress())
									.append(relayPeersDisconnect.contains(peer) ? "waiting on disconnect" : " connected outbound only")
									.append("\n"); linesPrinted++;
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

			if (outboundP2PWaitingOnReconnection.isEmpty() && outboundP2PConnected.isEmpty()) {
				output.append("\nNo Outbound Listeners").append("\n"); linesPrinted += 2;
			} else {
				output.append("\nOutbound Listeners:").append("\n"); linesPrinted += 2;
				synchronized (outboundP2PConnected) {
					for (InetSocketAddress peer : outboundP2PConnected) {
						output.append("  ").append(peer)
								.append(outboundP2PDisconnect.contains(peer) ? " waiting on disconnect" : " connected")
								.append("\n"); linesPrinted++;
					}
				}
				synchronized (outboundP2PWaitingOnReconnection) {
					for (InetSocketAddress peer : outboundP2PWaitingOnReconnection) {
						output.append("  ").append(peer).append(" not connected").append("\n"); linesPrinted++;
					}
				}
			}

			output.append("\n"); linesPrinted++;
			output.append("Connected relay clients: ").append(relayPeers.size() - relayClientCount).append("\n"); linesPrinted++;
			output.append("Connected relay node peers: ").append(relayClientCount).append("\n"); linesPrinted++;
			output.append("Chain download at ").append(blockChain.getBestChainHeight()).append("\n"); linesPrinted++;

			output.append("\n"); linesPrinted++;
			output.append("Commands:").append("\n"); linesPrinted++;
			output.append("q        \t\tquit").append("\n"); linesPrinted++;
			output.append("t IP:port\t\tadd node IP:port as a trusted peer").append("\n"); linesPrinted++;
			output.append("t-IP:port\t\tremove node IP:port as a trusted peer").append("\n"); linesPrinted++;
			output.append("o IP:port\t\tadd node IP:port as an untrusted peer").append("\n"); linesPrinted++;
			output.append("o-IP:port\t\tremove node IP:port as an untrusted peer").append("\n"); linesPrinted++;
			output.append("r IP\t\t\tadd trusted relay node to relay from").append("\n"); linesPrinted++;
			output.append("r-IP\t\t\tremove trusted relay node to relay from").append("\n"); linesPrinted++;

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
