/**
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.mattcorallo.relaynode;

import com.google.bitcoin.core.*;
import com.google.bitcoin.store.BlockStore;
import com.google.bitcoin.store.BlockStoreException;

import java.util.HashMap;

/**
 * Keeps {@link com.google.bitcoin.core.StoredBlock}s in memory. Identical to MemoryBlockStore, but with an unlimited
 * blockMap.
 */
public class UnlimitedMemoryBlockStore implements BlockStore {
    private HashMap<Sha256Hash, StoredBlock> blockMap = new HashMap<>();
    private StoredBlock chainHead;

    public UnlimitedMemoryBlockStore(NetworkParameters params) {
        // Insert the genesis block.
        try {
            Block genesisHeader = params.getGenesisBlock().cloneAsHeader();
            StoredBlock storedGenesis = new StoredBlock(genesisHeader, genesisHeader.getWork(), 0);
            put(storedGenesis);
            setChainHead(storedGenesis);
        } catch (VerificationException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
	}

    @Override
    public synchronized void put(StoredBlock block) {
        Sha256Hash hash = block.getHeader().getHash();
        blockMap.put(hash, block);
    }

    @Override
    public synchronized StoredBlock get(Sha256Hash hash) {
        return blockMap.get(hash);
    }

    @Override
    public StoredBlock getChainHead() {
        return chainHead;
    }

    @Override
    public void setChainHead(StoredBlock chainHead) {
        this.chainHead = chainHead;
    }

    @Override
    public void close() {
        throw new RuntimeException();
    }
}