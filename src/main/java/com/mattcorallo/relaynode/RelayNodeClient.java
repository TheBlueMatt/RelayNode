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
import com.google.bitcoin.net.StreamParser;
import com.google.bitcoin.params.MainNetParams;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.*;

public class RelayNodeClient {
	private static void usage() {
		System.err.println("USAGE: RelayNodeClient relayNetworkHost localBitcoind:port");
		System.err.println("Please connect to bitcoind over a whitelisted port/connection so that we are not DOS removed (it should never happen but we do relay non-fully-verified blocks)");
		System.exit(1);
	}

	public static void main(String[] args) {
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

	final NetworkParameters params = MainNetParams.get();
	InetSocketAddress relayPeerAddress, localPeerAddress;
	Peer localNetworkPeer;

	Map<QuarterHash, Transaction> localTransactionCache = LimitedSynchronizedObjects.createMap(500);
	RelayConnection relayPeer;

	public RelayNodeClient(InetSocketAddress relayPeerAddress, InetSocketAddress localPeerAddress) {
		this.localPeerAddress = localPeerAddress;
		this.relayPeerAddress = relayPeerAddress;

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
			void receiveBlock(Block b) {
				System.err.println("Received block " + b.getHashAsString());
				localNetworkPeer.sendMessage(b);
			}

			@Override
			void receiveTransaction(Transaction t) {
				System.err.println("Received transaction " + t.getHashAsString());
				localNetworkPeer.sendMessage(t);
			}

			@Override
			public void connectionClosed() {
				System.err.println("Lost connection to relay peer");
			}

			@Override
			public void connectionOpened() {
				System.err.println("Connected to relay peer!");
			}
		};
		try {
			new NioClient(relayPeerAddress, relayPeer, 1000);
		} catch (IOException e) {
			e.printStackTrace();
		}
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
				reconnectLocal();
			}

			@Override
			public Message onPreMessageReceived(Peer p, Message m) {
				if (m instanceof Block) {
					System.out.println("Received local block " + ((Block) m).getHashAsString());
					relayPeer.sendBlock((Block) m);
				} else if (m instanceof Transaction) {
					System.out.println("Received local transaction " + ((Transaction) m).getHashAsString());
					relayPeer.sendTransaction((Transaction) m);
				}
				return m;
			}
		});

		try {
			new NioClient(localPeerAddress, localNetworkPeer, 1000);
		} catch (IOException e) {
			System.err.println("Error connecting to Peer: " + e.getLocalizedMessage());
		}
	}
}
