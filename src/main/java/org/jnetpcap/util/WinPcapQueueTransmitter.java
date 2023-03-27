/*
 * Apache License, Version 2.0
 * 
 * Copyright 2013-2022 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 *   
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jnetpcap.util;

import java.lang.foreign.Addressable;
import java.lang.foreign.MemorySession;

import org.jnetpcap.PcapException;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.windows.PcapSendQueue;
import org.jnetpcap.windows.WinPcap;

/**
 * Transmitter which uses the PcapSendQueue as a sink for packets. Each packet
 * sinked, is queued with the supplied PcapSendQueue until the queue is full,
 * then the entire queue is transmitted with the supplied WinPcap handle.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public class WinPcapQueueTransmitter implements AutoCloseable {

	/** The scope. */
	private final MemorySession scope;

	/** The header. */
	private final PcapHeader header;

	/** The capacity. */
	private final int capacity;

	/** The send queue. */
	private final PcapSendQueue sendQueue;

	/** The pcap. */
	private final WinPcap pcap;

	/** The sync. */
	private final boolean sync;

	/** The size. */
	private int size;

	/**
	 * Instantiates a new win pcap queue transmitter.
	 *
	 * @param sendQueue the send queue
	 * @param pcap      the pcap
	 * @param sync      the sync
	 */
	public WinPcapQueueTransmitter(PcapSendQueue sendQueue, WinPcap pcap, boolean sync) {
		this.sendQueue = sendQueue;
		this.pcap = pcap;
		this.sync = sync;
		this.capacity = sendQueue.maxlen();
		this.size = sendQueue.len(); // incase queue is not empty
		this.scope = MemorySession.openShared();

		this.header = PcapHeader.allocate(scope);
	}

	/**
	 * Sink packet.
	 *
	 * @param packet the packet
	 * @param length the length
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.PcapHandler.PacketSink.PcapPacketSink#sinkPacket(java.lang.foreign.Addressable,
	 *      int)
	 */
	public void sinkPacket(Addressable packet, int length) throws PcapException {
		if (!scope.isAlive())
			throw new IllegalStateException("transmitter is closed");

		synchronized (this) {
			if ((size + length + PcapHeader.PCAP_HEADER_PADDED_LENGTH) > capacity)
				flush();

			size += length + PcapHeader.PCAP_HEADER_PADDED_LENGTH;

			header.set(length);

			sendQueue.queue(header.asMemoryReference(), packet);

			assert (size == sendQueue.len()) : ""
					+ "internal size tracking [%d] doesn't match sendQueue.len field [%d]"
							.formatted(size, sendQueue.len());
		}
	}

	/**
	 * Close.
	 *
	 * @throws PcapException the pcap exception
	 * @see java.lang.AutoCloseable#close()
	 */
	@Override
	public void close() throws PcapException {
		flush();
		scope.close();
	}

	/**
	 * Transmits all the packets in the queue, if any, and clears the queue for more
	 * packets.
	 *
	 * @throws PcapException the pcap exception
	 */
	public void flush() throws PcapException {
		if (!scope.isAlive())
			throw new IllegalStateException("transmitter is closed");

		synchronized (this) {
			try {
				if (size > 0) {
					if (pcap.sendQueueTransmit(sendQueue, sync) < size)
						throw new PcapException(pcap.geterr());

				}
			} finally {
				size = sendQueue.len();
			}
		}
	}

}
