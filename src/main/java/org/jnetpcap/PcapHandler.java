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
package org.jnetpcap;

import java.lang.foreign.Addressable;
import java.lang.foreign.MemoryAddress;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.nio.ByteBuffer;

/**
 * A marker interface for all Pcap packet handling functional interfaces.
 * 
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
public interface PcapHandler {

	/**
	 * A safe packet handler which receives copies of packets in a byte array.
	 *
	 * @param <U> the generic user type
	 */
	@FunctionalInterface
	public interface OfArray<U> extends PcapHandler {
		void handleArray(U user, PcapHeader header, byte[] packet);
	}

	/**
	 * A safe packet handler which receives copies of packets in a byte array at
	 * different offsets into a byte array. The memory for the byte[] may be
	 * allocated using bulk/arena type allocator and packets copied into it at
	 * different offsets.
	 * 
	 *
	 * @param <U> the generic user type
	 */
	@FunctionalInterface
	public interface OfArrayAtOffset<U> extends PcapHandler {
		void handleArray(U user, PcapHeader header, byte[] packet, int offset, int caplen);
	}

	/**
	 * A safe {@code ByteBuffer} packet handler. This handler may receive packets
	 * either by copy or scoped to a temporal existence.
	 *
	 * @param <U> the generic user type
	 */
	@FunctionalInterface
	public interface OfByteBuffer<U> extends PcapHandler {
		void handleByteBuffer(U user, PcapHeader header, ByteBuffer packet);
	}

	/**
	 * An advanced low level, no copy, packet handler. The packets dispatched using
	 * this handler are no copied and memory addresses point into native pcap
	 * ring-buffer and are only safe to use during the duration of handler call.
	 * After the handler returns that packet memory is no longer valid and may throw
	 * an exception if tried to access.
	 *
	 * @param <U> the generic user type
	 */
	@FunctionalInterface
	public interface OfMemoryAddress<U> extends PcapHandler {
		void handleAddress(U user, MemoryAddress header, MemoryAddress packet);
	}

	/**
	 * An advanced low level, no copy, packet handler. The packets dispatched using
	 * this handler are no copied and memory segments reference into native pcap
	 * ring-buffer and are only safe to use during the duration of handler call.
	 * After the handler returns that packet memory is no longer valid and may throw
	 * an exception if tried to access.
	 *
	 * @param <U> the generic user type
	 */
	@FunctionalInterface
	public interface OfMemorySegment<U> extends PcapHandler {
		void handleMemorySegment(U user, MemorySegment header, MemorySegment Packet, MemorySession scope);
	}

	/**
	 * Low level packet handler interface.
	 */
	@FunctionalInterface
	public interface OfRawPacket extends PcapHandler {
		void handleRawPacket(Addressable headerAddress, Addressable packetAddress);
	}

	/**
	 * A marker interface implemented by all packet sinks. A packet sink consumes
	 * raw packets which contain DLT header.
	 */
	public interface PacketSink extends PcapHandler {

		/**
		 * A functional interface and specialization implemented by packet sinks. The
		 * implementation of this interface is designed to be used by the Pcap library
		 * and not by user directly.
		 */
		@FunctionalInterface
		public interface PcapPacketSink extends PacketSink {

			void sinkPacket(Addressable packet, int length) throws PcapException;
		}
	}

	/**
	 * A marker interface implemented by all packet sources. A packet source
	 * provides raw packets {@link OfRawPacket} to a consumer or a sink.
	 */
	interface PacketSource {

		/**
		 * A functional interface and specialization implemented by packet sources. The
		 * implementation of this interface is designed to be used by the Pcap library
		 * and not by user directly.
		 */
		@FunctionalInterface
		public interface PcapPacketSource extends PacketSource {

			int sourcePackets(int count, OfRawPacket handler);
		}
	}
}
