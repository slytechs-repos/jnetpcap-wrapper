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

import java.lang.foreign.MemorySegment;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapHandler.PacketSink;
import org.jnetpcap.PcapHandler.PacketSink.PcapPacketSink;

/**
 * A utility class for transmitting packets on a network as a packet-sink.
 * Packet sinks and sources can be daisy chained to provide different levels of
 * functionality on top of Pcap API.
 * 
 * <p>
 * The PcapTransmitter class also provides many more transmit methods for
 * different storage options for packet data.
 * </p>
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public final class PcapTransmitter implements PcapPacketSink {

	/** User supplied packet sink where. */
	private final PcapPacketSink packetSink;

	/**
	 * Instantiates a new pcap packet sender using either {@link Pcap#inject()} or
	 * {@link Pcap#sendPacket()} methods. For example
	 * {@code new PcapTransmitter(pcap::inject)} or
	 * {@code new PcapTransmitter(pcap::sendPacket)}.
	 *
	 * @param sink the pcap packet sink where packets will be consumed and
	 *             potentially transmitted or saved to a savefile.
	 */
	public PcapTransmitter(PacketSink sink) {
		if (!(sink instanceof PcapPacketSink psink))
			throw new IllegalArgumentException("invalid packet sink %s".formatted(sink));

		this.packetSink = psink;
	}

	/**
	 * Sink packet.
	 *
	 * @param packet the packet
	 * @param length the length
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.PcapHandler.PacketSink.PcapPacketSink#sinkPacket(java.lang.foreign.MemorySegment,
	 *      int)
	 */
	@Override
	public void sinkPacket(MemorySegment packet, int length) throws PcapException {
		packetSink.sinkPacket(packet, length);
	}

	/**
	 * Transmit packet using the length of the memory segment as length of the
	 * packet.
	 *
	 * @param packet the packet memory segment
	 * @throws PcapException the pcap exception
	 */
	public void transmitPacket(MemorySegment packet) throws PcapException {
		sinkPacket(packet, (int) packet.byteSize());
	}
}
