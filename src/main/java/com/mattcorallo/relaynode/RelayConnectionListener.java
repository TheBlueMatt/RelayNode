package com.mattcorallo.relaynode;

import com.google.bitcoin.core.Block;
import com.google.bitcoin.core.PeerEventListener;
import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.net.NioServer;
import com.google.bitcoin.net.StreamParser;
import com.google.bitcoin.net.StreamParserFactory;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.jetbrains.annotations.NotNull;

import javax.annotation.Nullable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public class RelayConnectionListener {
	//TODO: Track memory usage and kill hungry connections

	private final Set<RelayConnection> connectionSet = Collections.synchronizedSet(new HashSet<RelayConnection>());
	private final Set<InetAddress> remoteSet = Collections.synchronizedSet(new HashSet<InetAddress>());

	private final Cache<InetAddress, Integer> oldHosts = CacheBuilder.newBuilder().expireAfterWrite(1, TimeUnit.HOURS).maximumSize(100).build();

	public RelayConnectionListener(int port, @NotNull final PeerEventListener clientPeerListener, @NotNull final RelayNode lineLogger) throws IOException {
		NioServer relayServer = new NioServer(new StreamParserFactory() {
			@Nullable
			@Override
			public StreamParser getNewParser(final InetAddress inetAddress, int port) {
				if (remoteSet.contains(inetAddress))
					return null;

				return new RelayConnection(false) {
					@Override
					void LogLine(String line) {
						if (line.startsWith("Connected to node with ")) {
							if (oldHosts.asMap().get(inetAddress) != null)
								return;
							else
								oldHosts.put(inetAddress, 42);
						}
						lineLogger.LogLine(inetAddress.getHostAddress() + ": " + line);
					}

					@Override void LogStatsRecv(@NotNull String lines) { }

					@Override void LogConnected(String line) { }

					@Override
					void receiveBlockHeader(Block b) { }

					@Override
					void receiveBlock(Block b) {
						clientPeerListener.onPreMessageReceived(null, b);
					}

					@Override
					void receiveTransaction(Transaction t) {
						clientPeerListener.onPreMessageReceived(null, t);
					}

					@Override
					public void connectionClosed() {
						connectionSet.remove(this);
						remoteSet.remove(inetAddress);
					}

					@Override
					public void connectionOpened() {
						connectionSet.add(this);
						remoteSet.add(inetAddress);
					}
				};
			}
		}, new InetSocketAddress(port));
		relayServer.startAsync().awaitRunning();
	}

	public void sendTransaction(@NotNull Transaction t) {
		synchronized (connectionSet) {
			for (RelayConnection connection : connectionSet)
				connection.sendTransaction(t);
		}
	}

	public void sendBlock(@NotNull Block b) {
		synchronized (connectionSet) {
			for (RelayConnection connection : connectionSet)
				connection.sendBlock(b);
		}
	}

	@NotNull
	public Set<InetAddress> getClientSet() {
		synchronized (remoteSet) {
			return new HashSet<>(remoteSet);
		}
	}
}
