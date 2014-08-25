package com.mattcorallo.relaynode;

import com.google.bitcoin.core.Sha256Hash;
import org.jetbrains.annotations.NotNull;

import java.io.ByteArrayOutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class QuarterHash {
	// We transport transaction hashes as only 10 bytes instead of the full 32
	// and assume a hash collision is rare enough that the P2P network will take over the slack if it happens
	public byte[] bytes;
	public static final int BYTE_LENGTH = 10;

	QuarterHash(@NotNull Sha256Hash hash) {
		bytes = Arrays.copyOfRange(hash.getBytes(), 0, BYTE_LENGTH);
	}

	QuarterHash(@NotNull ByteBuffer buff) throws BufferUnderflowException {
		bytes = new byte[BYTE_LENGTH];
		buff.get(bytes);
	}

	@Override
	public int hashCode() {
		return (((bytes[9] ^ bytes[5]) & 0xff) << 3*8) |
			   (((bytes[8] ^ bytes[4]) & 0xff) << 2*8) |
			   (((bytes[7] ^ bytes[3]) & 0xff) << 1*8) |
			   (((bytes[6] ^ bytes[2]) & 0xff) << 0*8);
	}

	@Override
	public boolean equals(Object o) {
		return o instanceof QuarterHash &&
				Arrays.equals(this.bytes, ((QuarterHash) o).bytes);
	}

	public static void writeBytes(@NotNull Sha256Hash hash, @NotNull ByteArrayOutputStream buff) {
		buff.write(hash.getBytes(), 0, BYTE_LENGTH);
	}
}
