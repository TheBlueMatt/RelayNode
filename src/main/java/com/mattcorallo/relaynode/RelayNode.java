package com.mattcorallo.relaynode;

import com.google.bitcoin.core.*;
import com.google.bitcoin.networkabstraction.NioClientManager;
import com.google.bitcoin.networkabstraction.NioServer;
import com.google.bitcoin.networkabstraction.StreamParser;
import com.google.bitcoin.networkabstraction.StreamParserFactory;
import com.google.bitcoin.params.MainNetParams;
import com.google.bitcoin.utils.Threading;
import com.google.common.base.Preconditions;
import com.google.common.collect.EvictingQueue;

import javax.annotation.Nullable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.*;

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

    public synchronized boolean shouldRequestInv(Sha256Hash hash) {
        return !objectsRelayed.contains(hash) && !objects.containsKey(hash);
    }

    public synchronized void provideObject(Type m) {
        if (!objectsRelayed.contains(m.getHash()))
            objects.put(m.getHash(), m);
    }

    public synchronized void invGood(Set<Peer> clients, Sha256Hash hash) {
        Type o = objects.get(hash);
        Preconditions.checkState(o != null);
        if (!objectsRelayed.contains(hash)) {
            for (Peer p : clients) {
                try {
                    p.sendMessage(o);
                } catch (IOException e) { } // Oops, lost them
            }
            objectsRelayed.add(hash);
        }
        objects.remove(hash);
    }
}

class BlockPool extends Pool<Block> {
    @Override
    int relayedCacheSize() {
        return 100;
    }
}

class TransactionPool extends Pool<Transaction> {
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
}/**


 * A RelayNode which is designed to relay blocks/txn from a set of untrusted peers, through a trusted bitcoind, to the
 * rest of the untrusted peers. It does no verification and trusts everything that comes from the trusted bitcoind is
 * good to relay.
 */
public class RelayNode {
    public static void main(String[] args) {
        new RelayNode().run(8444);
    }

    final NetworkParameters params = MainNetParams.get();
    final VersionMessage versionMessage = new VersionMessage(params, 0);

    final TransactionPool txPool = new TransactionPool();
    final BlockPool blockPool = new BlockPool();


    /******************************************
     ***** Stuff to keep track of clients *****
     ******************************************/
    final Set<Peer> clients = Collections.synchronizedSet(new HashSet<Peer>());
    PeerEventListener clientPeerListener = new AbstractPeerEventListener() {
        @Override
        public Message onPreMessageReceived(Peer p, Message m) {
            if (m instanceof InventoryMessage) {
                GetDataMessage getDataMessage = new GetDataMessage(params);
                for (InventoryItem item : ((InventoryMessage)m).getItems()) {
                    if (item.type == InventoryItem.Type.Block)
                        if (blockPool.shouldRequestInv(item.hash))
                            getDataMessage.addBlock(item.hash);
                        else if (item.type == InventoryItem.Type.Transaction)
                            if (txPool.shouldRequestInv(item.hash))
                                getDataMessage.addTransaction(item.hash);
                }
                if (!getDataMessage.getItems().isEmpty())
                    try {
                        p.sendMessage(getDataMessage);
                    } catch (IOException e) { } // Oops, lost them
                return null;
            } else if (m instanceof Transaction) {
                txPool.provideObject((Transaction) m);
                return null;
            } else if (m instanceof Block) {
                blockPool.provideObject((Block) m);
                return null;
            }
            return m;
        }
    };


    /************************************************
     ***** Stuff to keep track of trusted peers *****
     ************************************************/
    Map<InetSocketAddress, TrustedPeerConnections> trustedPeerConnectionsMap = Collections.synchronizedMap(new HashMap<InetSocketAddress, TrustedPeerConnections>());
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
                        else
                            blockPool.invGood(clients, item.hash);
                    } else if (item.type == InventoryItem.Type.Transaction) {
                        if (txPool.shouldRequestInv(item.hash))
                            getDataMessage.addTransaction(item.hash);
                        else
                            txPool.invGood(clients, item.hash);
                    }
                }
                if (!getDataMessage.getItems().isEmpty())
                    try {
                        p.sendMessage(getDataMessage);
                    } catch (IOException e) { } // Oops, lost them, we'll pick them back up in onPeerDisconnected
                return null;
            } else if (m instanceof Transaction) {
                txPool.provideObject((Transaction) m);
                txPool.invGood(clients, m.getHash());
                return null;
            } else if (m instanceof Block) {
                blockPool.provideObject((Block) m);
                blockPool.invGood(clients, m.getHash());
                return null;
            }
            return m;
        }

        @Override
        public void onPeerDisconnected(Peer peer, int peerCount) {
            //TODO
        }
    };


    /***************************
     ***** Stuff that runs *****
     ***************************/
    public RelayNode() {
        versionMessage.appendToSubVer("RelayNode", "adventurous aardvark", null);
        trustedPeerManager.startAndWait();
    }

    public void run(int listenPort) {
        // Listen for incoming client connections
        try {
            NioServer server = new NioServer(new StreamParserFactory() {
                @Nullable
                @Override
                public StreamParser getNewParser(InetAddress inetAddress, int port) {
                    Peer p = new Peer(params, versionMessage, null, new InetSocketAddress(inetAddress, port));
                    p.addEventListener(clientPeerListener, Threading.SAME_THREAD);
                    clients.add(p);
                    return p;
                }
            }, new InetSocketAddress(listenPort));
            server.startAndWait();
        } catch (IOException e) {
            System.err.println("Failed to bind to port " + listenPort);
            System.exit(1);
        }

        // Print stats
        new Thread(new Runnable() {
            @Override
            public void run() {
                printStats();
            }
        }).start();

        // Get user input
        Scanner scanner = new Scanner(System.in);
        String line;
        while ((line = scanner.nextLine()) != null) {
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
                    else
                        AddTrustedPeer(addr);
                } catch (NumberFormatException e) {
                    LogLine("Invalid argument");
                }
            }
        }
    }

    public void AddTrustedPeer(InetSocketAddress address) {
        TrustedPeerConnections connections = new TrustedPeerConnections();
        connections.inbound = new Peer(params, versionMessage, null, address);
        connections.inbound.addEventListener(trustedPeerInboundListener, Threading.SAME_THREAD);
        trustedPeerManager.openConnection(address, connections.inbound);

        connections.outbound = new Peer(params, versionMessage, null, address);
        trustedPeerManager.openConnection(address, connections.outbound);

        trustedPeerConnectionsMap.put(address, connections);
    }

    public static final int LOG_LINES = 10;
    Queue<String> logLines = EvictingQueue.create(LOG_LINES);
    public void LogLine(String line) {
        synchronized (logLines) {
            logLines.add(line);
        }
    }

    // Wouldn't want to print from multiple threads, would we?
    Object printLock = new Object();
    public void printStats() {
        while (true) {
            synchronized (printLock) {
                System.out.print("\0332J"); // Clear screen, move to top-left

                if (trustedPeerConnectionsMap.isEmpty()) {
                    System.out.println("Relaying will not start until you add some trusted nodes");
                } else {
                    System.out.println("Trusted nodes: ");
                    for (Map.Entry<InetSocketAddress, TrustedPeerConnections> entry : trustedPeerConnectionsMap.entrySet()) {
                        boolean connected = true;
                        try {
                            entry.getValue().inbound.sendMessage(new Ping(0xDEADBEEF));
                        } catch (Exception e) {
                            connected = false;
                        }
                        System.out.println("  " + entry.getKey() + (connected ? " connected" : " not connected"));
                    }
                }

                System.out.println();
                System.out.println("Connected clients: " + clients.size());

                System.out.println();
                System.out.println("Commands:");
                System.out.println("q        \t\tquit");
                System.out.println("t IP:port\t\tadd node IP:port as a trusted peer");
            }

            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                System.err.println("Stats printing thread interrupted");
                System.exit(1);
            }
        }
    }
}
