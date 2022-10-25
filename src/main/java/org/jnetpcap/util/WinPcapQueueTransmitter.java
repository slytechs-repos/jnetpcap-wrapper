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
import org.jnetpcap.PcapHandler.PacketSink.PcapPacketSink;
import org.jnetpcap.windows.PcapSendQueue;
import org.jnetpcap.windows.WinPcap;
import org.jnetpcap.PcapHeader;

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
public class WinPcapQueueTransmitter implements PcapPacketSink, AutoCloseable {

	private final MemorySession scope;
	private final PcapHeader header;
	private final int capacity;
	private final PcapSendQueue sendQueue;
	private final WinPcap pcap;
	private final boolean sync;
	private int size;

	/**
	 * 
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
	 * @see org.jnetpcap.PcapHandler.PacketSink.PcapPacketSink#sinkPacket(java.lang.foreign.Addressable,
	 *      int)
	 */
	@Override
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
	 * @throws PcapException
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
