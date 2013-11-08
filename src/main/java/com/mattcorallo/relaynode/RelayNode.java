package com.mattcorallo.relaynode;

import com.google.bitcoin.core.*;
import com.google.bitcoin.networkabstraction.NioClientManager;
import com.google.bitcoin.networkabstraction.NioServer;
import com.google.bitcoin.networkabstraction.StreamParser;
import com.google.bitcoin.networkabstraction.StreamParserFactory;
import com.google.bitcoin.params.MainNetParams;
import com.google.bitcoin.store.BlockStore;
import com.google.bitcoin.store.BlockStoreException;
import com.google.bitcoin.store.MemoryBlockStore;
import com.google.bitcoin.utils.Threading;
import com.google.common.base.Preconditions;

import javax.annotation.Nullable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.*;

/**
 * Keeps a peer and a set of invs which it has told us about (ie that it has data for)
 */
class PeerAndInvs {
    Peer p;
    Set<InventoryItem> invs = new LinkedHashSet<InventoryItem>() {
        @Override
        public boolean add(InventoryItem e) {
            boolean res = super.add(e);
            if (size() > 5000)
                super.remove(super.iterator().next());
            return res;
        }
    };

    public PeerAndInvs(Peer p) {
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

        if (!invs.contains(item)) {
            try {
                p.sendMessage(m);
                invs.add(item);
            } catch (IOException e) { /* Oops, lost them */ }
        }
    }
}

/**
 * Keeps track of a set of PeerAndInvs
 */
class Peers {
    public final Set<PeerAndInvs> peers = Collections.synchronizedSet(new HashSet<PeerAndInvs>());

    public PeerAndInvs add(Peer p) {
        PeerAndInvs peerAndInvs = new PeerAndInvs(p);
        add(peerAndInvs);
        return peerAndInvs;
    }

    public boolean add(final PeerAndInvs peerAndInvs) {
        peerAndInvs.p.addEventListener(new AbstractPeerEventListener() {
            @Override
            public void onPeerDisconnected(Peer peer, int peerCount) {
                peers.remove(peerAndInvs);
            }
        }, Threading.SAME_THREAD);
        return peers.add(peerAndInvs);
    }

    public int size() { return peers.size(); }

    public void relayObject(Message m) {
        synchronized (peers) {
            for (PeerAndInvs p : peers)
                p.maybeRelay(m);
        }
    }
}

/**
 * Keeps track of the set of known blocks and transactions for relay
 */
abstract class Pool<Type extends Message> {
    abstract int relayedCacheSize();

    Map<Sha256Hash, Type> objects = new HashMap<Sha256Hash, Type>();
    Set<Sha256Hash> objectsRelayed = new LinkedHashSet<Sha256Hash>() {
        @Override
        public boolean add(Sha256Hash e) {
            boolean res = super.add(e);
            if (size() > relayedCacheSize())
                super.remove(super.iterator().next()); //TODO: right order, or inverse?
            return res;
        }
    };

    Peers trustedOutboundPeers;
    public Pool(Peers trustedOutboundPeers) { this.trustedOutboundPeers = trustedOutboundPeers; }

    public synchronized boolean shouldRequestInv(Sha256Hash hash) {
        return !objectsRelayed.contains(hash) && !objects.containsKey(hash);
    }

    public synchronized void provideObject(Type m) {
        if (!objectsRelayed.contains(m.getHash()))
            objects.put(m.getHash(), m);
        trustedOutboundPeers.relayObject(m);
    }

    public synchronized void invGood(Peers clients, Sha256Hash hash) {
        if (!objectsRelayed.contains(hash)) {
            Type o = objects.get(hash);
            Preconditions.checkState(o != null);
            clients.relayObject(o);
            objectsRelayed.add(hash);
        }
        objects.remove(hash);
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

/** Keeps track of trusted peer connections (two for each trusted peer) */
class TrustedPeerConnections {
    /** We only receive messages here (listen for invs of validated data) */
    public Peer inbound;
    /** We only send messages here (send unvalidated data) */
    public Peer outbound;
}

/**
 * A RelayNode which is designed to relay blocks/txn from a set of untrusted peers, through a trusted bitcoind, to the
 * rest of the untrusted peers. It does no verification and trusts everything that comes from the trusted bitcoind is
 * good to relay.
 */
public class RelayNode {
    public static void main(String[] args) throws BlockStoreException {
        new RelayNode().run(8334, 8335);
    }

    NetworkParameters params = MainNetParams.get();
    VersionMessage versionMessage = new VersionMessage(params, 0);

    Peers trustedOutboundPeers = new Peers();

    TransactionPool txPool = new TransactionPool(trustedOutboundPeers);
    BlockPool blockPool = new BlockPool(trustedOutboundPeers);

    BlockStore blockStore = new MemoryBlockStore(params);
    BlockChain blockChain;
    PeerGroup trustedOutboundPeerGroup;
    volatile boolean chainDownloadDone = false;


    /******************************************
     ***** Stuff to keep track of clients *****
     ******************************************/
    final Peers txnClients = new Peers();
    final Peers blocksClients = new Peers();
    PeerEventListener clientPeerListener = new AbstractPeerEventListener() {
        @Override
        public Message onPreMessageReceived(Peer p, Message m) {
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
                    try {
                        p.sendMessage(getDataMessage);
                    } catch (IOException e) { /* Oops, lost them */ }
            } else if (m instanceof Block) {
                blockPool.provideObject((Block) m); // This will relay to trusted peers, just in case we reject something we shouldn't
                try {
                    if (blockChain.add((Block) m)) {
                        LogBlockRelay(m.getHash(), "SPV check, from " + p.getAddress());
                        blockPool.invGood(blocksClients, m.getHash());
                    }
                } catch (Exception e) { /* Invalid block, don't relay it */ }
            } else if (m instanceof Transaction)
                txPool.provideObject((Transaction) m);
            return m;
        }
    };


    /************************************************
     ***** Stuff to keep track of trusted peers *****
     ************************************************/
    final Map<InetSocketAddress, TrustedPeerConnections> trustedPeerConnectionsMap = Collections.synchronizedMap(new HashMap<InetSocketAddress, TrustedPeerConnections>());
    NioClientManager trustedPeerManager = new NioClientManager();
    PeerEventListener trustedPeerInboundListener = new AbstractPeerEventListener() {
        @Override
        public Message onPreMessageReceived(Peer p, Message m) {
            if (m instanceof InventoryMessage) {
                GetDataMessage getDataMessage = new GetDataMessage(params);
                for (InventoryItem item : ((InventoryMessage)m).getItems()) {
                    if (item.type == InventoryItem.Type.Block) {
                        if (blockPool.shouldRequestInv(item.hash))
                            getDataMessage.addBlock(item.hash);
                        else {
                            LogBlockRelay(item.hash, "inv from node " + p.getAddress());
                            blockPool.invGood(blocksClients, item.hash);
                        }
                    } else if (item.type == InventoryItem.Type.Transaction) {
                        if (txPool.shouldRequestInv(item.hash))
                            getDataMessage.addTransaction(item.hash);
                        else
                            txPool.invGood(txnClients, item.hash);
                    }
                }
                if (!getDataMessage.getItems().isEmpty())
                    try {
                        p.sendMessage(getDataMessage);
                    } catch (IOException e) { /* Oops, lost them, we'll pick them back up in onPeerDisconnected */ }
            } else if (m instanceof Transaction) {
                txPool.provideObject((Transaction) m);
                txPool.invGood(txnClients, m.getHash());
            } else if (m instanceof Block) {
                blockPool.provideObject((Block) m);
                LogBlockRelay(m.getHash(), "block from node " + p.getAddress());
                blockPool.invGood(blocksClients, m.getHash());
            }
            return m;
        }
    };

    // Runs on USER_THREAD (which is used exclusively for reconnection attempts)
    PeerEventListener trustedPeerDisconnectListener = new AbstractPeerEventListener() {
        @Override
        public void onPeerDisconnected(Peer peer, int peerCount) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
            ConnectToTrustedPeer(peer.getAddress().toSocketAddress());
        }
    };


    /*******************************************************************
     ***** Stuff to keep track of other relay nodes which we trust *****
     *******************************************************************/
    Peers trustedRelayPeers = new Peers(); // Just used to keep a list of relay peers
    Set<InetSocketAddress> relayPeersWaitingOnReconnection = Collections.synchronizedSet(new HashSet<InetSocketAddress>());
    PeerEventListener trustedRelayPeerListener = new AbstractPeerEventListener() {
        @Override
        public Message onPreMessageReceived(Peer p, Message m) {
            if (m instanceof Block) {
                blockPool.provideObject((Block) m);
                LogBlockRelay(m.getHash(), "block from relay peer " + p.getAddress());
                blockPool.invGood(blocksClients, m.getHash());
            }
            return m;
        }
    };


    /***************************
     ***** Stuff that runs *****
     ***************************/
    public RelayNode() throws BlockStoreException {
        String version = "queer quail";
        versionMessage.appendToSubVer("RelayNode", version, null);
        // Fudge a few flags so that we can connect to other relay nodes
        versionMessage.localServices = VersionMessage.NODE_NETWORK;
        versionMessage.bestHeight = 1;

        trustedPeerManager.startAndWait();

        blockChain = new BlockChain(params, blockStore);

        trustedOutboundPeerGroup = new PeerGroup(params, blockChain);
        trustedOutboundPeerGroup.setUserAgent("RelayNode", version);
        trustedOutboundPeerGroup.addEventListener(trustedPeerDisconnectListener, Threading.USER_THREAD);
        trustedOutboundPeerGroup.setFastCatchupTimeSecs(Long.MAX_VALUE); // We'll revert to full blocks after catchup, but oh well
        trustedOutboundPeerGroup.startAndWait();
    }

    public void run(int onlyBlocksListenPort, int bothListenPort) {
        // Listen for incoming client connections
        try {
            NioServer onlyBlocksServer = new NioServer(new StreamParserFactory() {
                @Nullable
                @Override
                public StreamParser getNewParser(InetAddress inetAddress, int port) {
                    Peer p = new Peer(params, versionMessage, null, new InetSocketAddress(inetAddress, port));
                    blocksClients.add(p); // Should come first to avoid relaying back to the sender
                    p.addEventListener(clientPeerListener, Threading.SAME_THREAD);
                    return p;
                }
            }, new InetSocketAddress(onlyBlocksListenPort));

            NioServer bothServer = new NioServer(new StreamParserFactory() {
                @Nullable
                @Override
                public StreamParser getNewParser(InetAddress inetAddress, int port) {
                    Peer p = new Peer(params, versionMessage, null, new InetSocketAddress(inetAddress, port));
                    txnClients.add(blocksClients.add(p)); // Should come first to avoid relaying back to the sender
                    p.addEventListener(clientPeerListener, Threading.SAME_THREAD);
                    return p;
                }
            }, new InetSocketAddress(bothListenPort));

            onlyBlocksServer.startAndWait();
            bothServer.startAndWait();
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
                synchronized (printLock) {
                    System.out.println("Quitting...");
                    // Wait...cleanup? naaaaa
                    System.exit(0);
                }
            } else if (line.startsWith("t ")) {
                String[] hostPort = line.substring(2).split(":");
                if (hostPort.length != 2) {
                    LogLine("Invalid argument");
                    continue;
                }
                try {
                    int port = Integer.parseInt(hostPort[1]);
                    InetSocketAddress addr = new InetSocketAddress(hostPort[0], port);
                    if (addr.isUnresolved())
                        LogLine("Unable to resolve host");
                    else {
                        ConnectToTrustedPeer(addr);
                        LogLine("Added trusted peer " + addr);
                    }
                } catch (NumberFormatException e) {
                    LogLine("Invalid argument");
                }
            } else if (line.startsWith("r ")) {
                String[] hostPort = line.substring(2).split(":");
                if (hostPort.length != 2) {
                    LogLine("Invalid argument");
                    continue;
                }
                try {
                    int port = Integer.parseInt(hostPort[1]);
                    InetSocketAddress addr = new InetSocketAddress(hostPort[0], port);
                    if (addr.isUnresolved())
                        LogLine("Unable to resolve host");
                    else {
                        ConnectToTrustedRelayPeer(addr);
                        LogLine("Added trusted relay peer " + addr);
                    }
                } catch (NumberFormatException e) {
                    LogLine("Invalid argument");
                }
            } else {
                LogLine("Invalid command");
            }
        }
    }

    public void ConnectToTrustedRelayPeer(final InetSocketAddress address) {
        final Peer p = new Peer(params, versionMessage, null, address);
        p.addEventListener(trustedRelayPeerListener, Threading.SAME_THREAD);
        p.addEventListener(new AbstractPeerEventListener() {
            @Override
            public void onPeerDisconnected(Peer peer, int peerCount) {
                Preconditions.checkState(peer == p);
                relayPeersWaitingOnReconnection.add(address);
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                relayPeersWaitingOnReconnection.remove(address);
                ConnectToTrustedRelayPeer(address);
            }
        }, Threading.USER_THREAD);
        trustedRelayPeers.add(p);
        trustedPeerManager.openConnection(address, p);
    }

    public void ConnectToTrustedPeer(InetSocketAddress address) {
        TrustedPeerConnections connections = trustedPeerConnectionsMap.get(address);
        if (connections != null) {
            connections.inbound.close();
            connections.outbound.close();
        }
        connections = new TrustedPeerConnections();

        connections.inbound = new Peer(params, versionMessage, null, address);
        connections.inbound.addEventListener(trustedPeerInboundListener, Threading.SAME_THREAD);
        connections.inbound.addEventListener(trustedPeerDisconnectListener, Threading.USER_THREAD);
        trustedPeerManager.openConnection(address, connections.inbound);

        connections.outbound = trustedOutboundPeerGroup.connectTo(address);
        trustedOutboundPeers.add(connections.outbound);
        trustedOutboundPeerGroup.startBlockChainDownload(new DownloadListener() {
            @Override
            protected void doneDownload() {
                chainDownloadDone = true;
            }
        });

        trustedPeerConnectionsMap.put(address, connections);
    }

    final Queue<String> logLines = new LinkedList<String>();
    public void LogLine(String line) {
        synchronized (logLines) {
            logLines.add(line);
        }
    }

    Set<Sha256Hash> blockRelayedSet = Collections.synchronizedSet(new HashSet<Sha256Hash>());
    public void LogBlockRelay(Sha256Hash blockHash, String reason) {
        if (blockRelayedSet.contains(blockHash))
            return;
        blockRelayedSet.add(blockHash);
        LogLine(blockHash.toString().substring(4, 32) + " relayed (" + reason + ")");
    }

    // Wouldn't want to print from multiple threads, would we?
    final Object printLock = new Object();
    public void printStats() {
        // Things may break if your column count is too small
        boolean firstIteration = true;
        int linesPrinted = 1;
        for (int iter = 0; true; iter++) {
            int prevLinesPrinted = linesPrinted;
            linesPrinted = 1;

            synchronized (printLock) {
                if (!firstIteration) {
                    synchronized (logLines) {
                        System.out.print("\033[s\033[1000D"); // Save cursor position + move to first char

                        for (String ignored : logLines)
                            System.out.println(); // Move existing log lines up

                        for (int i = 0; i < prevLinesPrinted; i++)
                            System.out.print("\033[1A\033[K"); // Up+clear linesPrinted lines

                        for (String ignored : logLines)
                            System.out.print("\033[1A\033[K"); // Up and make sure we're at the beginning, clear line
                        for (String line : logLines)
                            System.out.println(line);
                        logLines.clear();
                    }
                }

                if (trustedPeerConnectionsMap.isEmpty()) {
                    System.out.println("\nNo trusted nodes (no transaction relay)"); linesPrinted += 2;
                } else {
                    System.out.println("\nTrusted nodes: "); linesPrinted += 2;
                    synchronized (trustedPeerConnectionsMap) {
                        for (Map.Entry<InetSocketAddress, TrustedPeerConnections> entry : trustedPeerConnectionsMap.entrySet()) {
                            // TODO: There are better ways to check connection...
                            boolean connected = true;
                            try {
                                entry.getValue().inbound.sendMessage(new Ping(0xDEADBEEF));
                            } catch (Exception e) {
                                connected = false;
                            }
                            System.out.println("  " + entry.getKey() + (connected ? " connected" : " not connected")); linesPrinted++;
                        }
                    }
                }

                Set<InetAddress> relayPeers = new HashSet<InetAddress>();
                if (trustedRelayPeers.peers.isEmpty()) {
                    System.out.println("\nNo relay peers"); linesPrinted += 2;
                } else {
                    System.out.println("\nRelay peers:"); linesPrinted += 2;
                    synchronized (trustedRelayPeers.peers) {
                        for (PeerAndInvs peer : trustedRelayPeers.peers) { // If its not connected, its not in the set
                            System.out.println("  " + peer.p.getAddress() + " connected"); linesPrinted++;
                            relayPeers.add(peer.p.getAddress().getAddr());
                        }
                    }
                    synchronized (relayPeersWaitingOnReconnection) {
                        for (InetSocketAddress a : relayPeersWaitingOnReconnection) {
                            System.out.println("  " + a + " not connected"); linesPrinted++;
                            relayPeers.add(a.getAddress());
                        }
                    }
                }

                int relayClients = 0;
                synchronized (blocksClients.peers) {
                    for (PeerAndInvs p : blocksClients.peers)
                        if (relayPeers.contains(p.p.getAddress().getAddr()))
                            relayClients++;
                }

                System.out.println(); linesPrinted++;
                System.out.println("Connected block+transaction clients: " + txnClients.size()); linesPrinted++;
                System.out.println("Connected block-only clients: " +
                        (blocksClients.size() - txnClients.size() - relayClients)); linesPrinted++;
                System.out.println("Connected relay node clients: " + relayClients); linesPrinted++;
                System.out.println(chainDownloadDone ? "Chain download done (relaying SPV-checked blocks)" :
                        ("Chain download at " + blockChain.getBestChainHeight())); linesPrinted++;

                System.out.println(); linesPrinted++;
                System.out.println("Commands:"); linesPrinted++;
                System.out.println("q        \t\tquit"); linesPrinted++;
                System.out.println("t IP:port\t\tadd node IP:port as a trusted peer"); linesPrinted++;
                System.out.println("r IP:port\t\tadd trusted relay node (via its block-only port) to relay from"); linesPrinted++;
                if (firstIteration)
                    System.out.println();
                else
                    System.out.print("\033[u");
                firstIteration = false;
            }

            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                System.err.println("Stats printing thread interrupted");
                System.exit(1);
            }
        }
    }
}
