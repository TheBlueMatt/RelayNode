package relaynodemonitor;

import com.google.bitcoin.core.*;
import com.google.bitcoin.params.MainNetParams;
import com.google.bitcoin.utils.Threading;
import com.google.common.util.concurrent.Uninterruptibles;

import java.net.InetSocketAddress;
import java.net.URL;
import java.net.URLConnection;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Monitors multiple relay nodes and prints the blocks they send (if you miss blocks, or you miss time targets, page
 * someone!)
 */
public class RelayNodeMonitor {
    private static Map<String, Sha256Hash> lookupAPIBlocks() {
        Map<String, Sha256Hash> res = new HashMap<String, Sha256Hash>();
        try {
            URL u = new URL("http://blockchain.info/q/latesthash");
            Scanner in = new Scanner(u.openStream());
            res.put("bc.i", new Sha256Hash(in.nextLine().toLowerCase()));
            in.close();
        } catch (Exception e) {
            System.err.println("WARNING: Failed to get bc.i's latest blockhash");
        }
        try {
            URL u = new URL("http://blockexplorer.com/q/latesthash");
            URLConnection c = u.openConnection();
            c.setRequestProperty("User-Agent", "Mozilla"); // Cloudfare hates Java
            Scanner in = new Scanner(c.getInputStream());
            res.put("bbe", new Sha256Hash(in.nextLine().toLowerCase()));
            in.close();
        } catch (Exception e) {
            System.err.println("WARNING: Failed to get bbe's latest blockhash");
        }
        return res;
    }
    public static void main(String[] args) {
        NetworkParameters params = MainNetParams.get();

        Threading.uncaughtExceptionHandler = new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread t, Throwable e) {
                System.out.println("Unhandled exception " + e.toString());
            }
        };

        final PeerGroup peerGroup = new PeerGroup(params);

        final Map<Sha256Hash, Set<InetSocketAddress>> nodesWithBlock = Collections.synchronizedMap(new HashMap<Sha256Hash, Set<InetSocketAddress>>());
        final Map<Sha256Hash, Long> apiPostTime = Collections.synchronizedMap(new HashMap<Sha256Hash, Long>());
        final InetSocketAddress missedFlag = new InetSocketAddress("0.0.0.0", 0);
        final Map<InetSocketAddress, Long> nodes = Collections.synchronizedMap(new HashMap<InetSocketAddress, Long>());
        final ScheduledExecutorService executor = Executors.newScheduledThreadPool(4);

        peerGroup.addEventListener(new AbstractPeerEventListener() {
            @Override
            public Message onPreMessageReceived(final Peer p, final Message m) {
                if (m instanceof Block) {
                    synchronized (nodesWithBlock) {
                        Set<InetSocketAddress> s = nodesWithBlock.get(m.getHash());
                        if (s == null) {
                            s = new HashSet<InetSocketAddress>();
                            nodesWithBlock.put(m.getHash(), s);
                        }
                        s.add(p.getAddress().toSocketAddress());
                        System.err.println(m.getHash() + " " + s.size() + " " + nodes.size());
                    }
                    System.err.println("Got " + m.getHash() + " from " + p + " " + System.currentTimeMillis());
                    executor.schedule(new Runnable() {
                        @Override
                        public void run() {
                            synchronized (nodesWithBlock) {
                                System.err.println("Scheduled " + m.getHash() + " " + System.currentTimeMillis());
                                Set<InetSocketAddress> s = nodesWithBlock.get(m.getHash());
                                if (s.size() < nodes.size() && !s.contains(missedFlag)) {
                                    System.out.println("Missed time target: " + m.getHash());
                                    s.add(missedFlag);
                                }
                            }
                        }
                    }, 7000, TimeUnit.MILLISECONDS); // All relay nodes must get us all blocks within 7s of each other (damn cross-continent TCP...)
                }
                return m;
            }

            @Override
            public void onPeerDisconnected(final Peer p, int peerCount) {
                synchronized (nodes) {
                    if (nodes.get(p.getAddress().toSocketAddress()) < System.currentTimeMillis() - 15*60*1000) { // Only notify once every 15 minutes per node
                        System.out.println("Peer disconnected: " + p);
                        nodes.put(p.getAddress().toSocketAddress(), System.currentTimeMillis());
                    }
                }
                System.err.println("Got onPeerDisconnected for " + p.getAddress() + " with peerCount " + peerCount);
                executor.schedule(new Runnable() {
                    @Override
                    public void run() {
                        for (Peer itp : peerGroup.getConnectedPeers())
                            if (itp.getAddress().equals(p.getAddress()))
                                return;
                        peerGroup.connectTo(p.getAddress().toSocketAddress());
                    }
                }, 1, TimeUnit.SECONDS);
            }
        }, Threading.SAME_THREAD);
        VersionMessage v = peerGroup.getVersionMessage();
        v.localServices = VersionMessage.NODE_NETWORK;
        peerGroup.setVersionMessage(v);
        peerGroup.startAndWait();

        for (Sha256Hash h : lookupAPIBlocks().values())
            apiPostTime.put(h, System.currentTimeMillis());
        Thread lookupThread = new Thread(new Runnable() {
            @Override
            public void run() {
                while (true) {
                    for (final Map.Entry<String, Sha256Hash> e : lookupAPIBlocks().entrySet())
                        if (!apiPostTime.containsKey(e.getValue())) {
                            apiPostTime.put(e.getValue(), System.currentTimeMillis());
                            System.err.println(e.getKey() + " provided block " + e.getValue() + " at " + System.currentTimeMillis());
                            executor.schedule(new Runnable() {
                                @Override
                                public void run() {
                                    if (!nodesWithBlock.containsKey(e.getValue()))
                                        System.out.println("Missed block: " + e.getValue() + " provided by " + e.getKey());
                                }
                            }, 500, TimeUnit.MILLISECONDS); // Must have heard from min. one node within 500 ms of bc.i+bbe
                        }
                    Uninterruptibles.sleepUninterruptibly(1, TimeUnit.SECONDS);
                }
            }
        });
        lookupThread.setName("lookupThread");
        lookupThread.start();

        Scanner in = new Scanner(System.in);
        while (true) {
            String line;
            try {
                line = in.nextLine();
            } catch (Exception e) {
                break;
            }
            if (line.startsWith("p ")) {
                System.err.println("Passing through " + line.substring(2));
                System.out.println(line.substring(2));
                continue;
            }
            String[] hostPort = line.split(":");
            if (hostPort.length != 2) {
                System.err.println("Invalid input");
                continue;
            }
            try {
                int port = Integer.parseInt(hostPort[1]);
                InetSocketAddress addr = new InetSocketAddress(hostPort[0], port);
                if (addr.isUnresolved()) {
                    System.err.println("Unable to resolve host " + hostPort[0]);
                    continue;
                }
                peerGroup.connectTo(addr);
                nodes.put(addr, Long.valueOf(0));
                System.err.println("Connected to " + addr);
            } catch (NumberFormatException e) {
                System.err.println("Invalid port");
            }
        }
        while (true)
            Uninterruptibles.sleepUninterruptibly(1, TimeUnit.DAYS);
    }
}
