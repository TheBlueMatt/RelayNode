/*
 * Relay Node Client
 *
 * Copyright (C) 2013 Matt Corallo <git@bluematt.me>
 *
 * This is free software: you can redistribute it under the
 * terms in the LICENSE file.
 */

package com.mattcorallo.relaynode;

import com.google.bitcoin.core.*;
import com.google.bitcoin.net.MessageWriteTarget;
import com.google.bitcoin.net.NioClient;
import com.google.bitcoin.net.NioClientManager;
import com.google.bitcoin.net.StreamParser;
import com.google.bitcoin.params.MainNetParams;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.channels.NotYetConnectedException;
import java.util.*;
import java.util.concurrent.*;

public class RelayNodeClient {
	private static void usage() {
		System.err.println("USAGE: RelayNodeClient relayNetworkHost localBitcoind:port");
		System.err.println("Please connect to bitcoind over a whitelisted port/connection so that we are not DOS removed (it should never happen but we do relay non-fully-verified blocks)");
		System.exit(1);
	}

	public static void main(@NotNull String[] args) {
		if (args.length != 2)
			usage();
		try {
			InetSocketAddress relayPeerAddress = new InetSocketAddress(args[0], 8336);

			String[] localPeerSplit = args[1].split(":");
			if (localPeerSplit.length != 2)
				usage();
			InetSocketAddress localPeerAddress = new InetSocketAddress(localPeerSplit[0], Integer.parseInt(localPeerSplit[1]));

			new RelayNodeClient(relayPeerAddress, localPeerAddress);
		} catch (NumberFormatException e) {
			usage();
		}
	}

	final NioClientManager connectionManager = new NioClientManager();

	final NetworkParameters params = MainNetParams.get();
	InetSocketAddress relayPeerAddress, localPeerAddress;
	@Nullable
	Peer localNetworkPeer;

	RelayConnection relayPeer;

	@NotNull
	ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);

	public RelayNodeClient(InetSocketAddress relayPeerAddress, InetSocketAddress localPeerAddress) {
		this.localPeerAddress = localPeerAddress;
		this.relayPeerAddress = relayPeerAddress;

		connectionManager.startAsync().awaitRunning();

		reconnectLocal();
		reconnectRelay();
	}

	void reconnectRelay() {
		relayPeer = new RelayConnection() {
			@Override
			void LogLine(String line) {
				System.err.println(line);
			}

			@Override
			void LogStatsRecv(String lines) {
				System.err.println(lines);
			}

			@Override
			void LogConnected(String line) {
				System.err.println(line);
			}

			@Override
			void receiveBlock(@NotNull Block b) {
				System.err.println("Received block " + b.getHashAsString());
				try {
					localNetworkPeer.sendMessage(b);
				} catch (NullPointerException | NotYetConnectedException e) { /* We'll catch them next time */ }
			}

			@Override
			void receiveTransaction(@NotNull Transaction t) {
				System.err.println("Received transaction " + t.getHashAsString());
				try {
					localNetworkPeer.sendMessage(t);
				} catch (NullPointerException | NotYetConnectedException e) { /* We'll catch them next time */ }
			}

			@Override
			public void connectionClosed() {
				System.err.println("Lost connection to relay peer");
				executor.schedule(new Runnable() {
					@Override
					public void run() {
						reconnectRelay();
					}
				}, 1, TimeUnit.SECONDS);
			}

			@Override
			public void connectionOpened() {
				System.err.println("Connected to relay peer!");
			}
		};
		connectionManager.openConnection(relayPeerAddress, relayPeer);
	}

	void reconnectLocal() {
		localNetworkPeer = new Peer(params, new VersionMessage(params, 1), new PeerAddress(localPeerAddress), null, null);
		localNetworkPeer.addEventListener(new AbstractPeerEventListener() {
			@Override
			public void onPeerConnected(Peer p, int peerCount) {
				System.out.println("Connected to local bitcoind!");
			}

			@Override
			public void onPeerDisconnected(Peer p, int peerCount) {
				System.err.println("Lost connection to local bitcoind!");
				executor.schedule(new Runnable() {
					@Override
					public void run() {
						reconnectLocal();
					}
				}, 1, TimeUnit.SECONDS);
			}

			@Override
			public Message onPreMessageReceived(@NotNull Peer p, Message m) {
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
				} else if (m instanceof Block) {
					System.out.println("Received local block " + ((Block) m).getHashAsString());
					relayPeer.sendBlock((Block) m);
				} else if (m instanceof Transaction) {
					System.out.println("Received local transaction " + ((Transaction) m).getHashAsString());
					relayPeer.sendTransaction((Transaction) m);
				}
				return m;
			}
		});

		connectionManager.openConnection(localPeerAddress, localNetworkPeer);
	}
}
