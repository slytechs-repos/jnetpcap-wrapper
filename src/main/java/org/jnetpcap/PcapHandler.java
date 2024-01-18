/*
 * Copyright 2023 Sly Technologies Inc
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
package org.jnetpcap;

import java.lang.foreign.MemorySegment;
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

		/**
		 * Packet handler method. This method get called to handle or consume a pcap
		 * packet.
		 *
		 * @param user   the user
		 * @param header the header
		 * @param packet the packet
		 */
		void handleArray(U user, PcapHeader header, byte[] packet);
	}

	/**
	 * A safe {@code ByteBuffer} packet handler. This handler may receive packets
	 * either by copy or scoped to a temporal existence.
	 *
	 * @param <U> the generic user type
	 */
	@FunctionalInterface
	public interface OfByteBuffer<U> extends PcapHandler {

		/**
		 * Packet handler method. This method get called to handle or consume a pcap
		 * packet.
		 *
		 * @param user   the user
		 * @param header the header
		 * @param packet the packet
		 */
		void handleByteBuffer(U user, PcapHeader header, ByteBuffer packet);
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

		/**
		 * Packet handler method. This method get called to handle or consume a pcap
		 * packet.
		 *
		 * @param user   the user
		 * @param header the header
		 * @param Packet the packet
		 */
		void handleSegment(U user, MemorySegment header, MemorySegment Packet);
	}

	/**
	 * A native pcap callback which is called with packets captured using the
	 * {@link Pcap#loop} or {@link Pcap#dispatch} calls.
	 */
	@FunctionalInterface
	public interface NativeCallback extends PcapHandler {

		/**
		 * Receive native packets.
		 *
		 * @param user   user opaque data
		 * @param header libpcap header
		 * @param packet packet data
		 */
		void nativeCallback(MemorySegment user, MemorySegment header, MemorySegment packet);

	}

}
