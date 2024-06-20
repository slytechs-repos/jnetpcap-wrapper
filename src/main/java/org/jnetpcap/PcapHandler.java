/*
 * Copyright 2024 Sly Technologies Inc
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
	 * A native pcap callback which is called with packets captured using the
	 * {@link Pcap#loop} or {@link Pcap#dispatch} calls.
	 */
	@FunctionalInterface
	public interface NativeCallback extends PcapHandler {

		/**
		 * Wrap array.
		 *
		 * @param array the array
		 * @return the native callback
		 */
		static NativeCallback wrapArray(NativeCallback[] array) {
			return (u, h, p) -> {
				for (var a : array)
					a.nativeCallback(u, h, p);
			};
		}

		/**
		 * Receive native packets.
		 *
		 * @param user   user opaque data
		 * @param header libpcap header
		 * @param packet packet data
		 */
		void nativeCallback(MemorySegment user, MemorySegment header, MemorySegment packet);

		/**
		 * Wrap user.
		 *
		 * @param newUser the new user
		 * @return the native callback
		 */
		default NativeCallback wrapUser(MemorySegment newUser) {
			return (u, h, p) -> nativeCallback(newUser, h, p);
		}

	}

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

		/**
		 * Creates a new handler that passes on new user data to the old handler. The
		 * original user data supplied is ignored.
		 *
		 * @param newUser the new userdata to supply
		 * @return new handler which overrides the original user data
		 */
		default OfArray<U> wrapUser(U newUser) {
			return (u, h, p) -> handleArray(newUser, h, p);
		}
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
		 * Wrap array.
		 *
		 * @param <U>   the generic type
		 * @param array the array
		 * @return the of memory segment
		 */
		static <U> OfByteBuffer<U> wrapArray(OfByteBuffer<U>[] array) {
			return (u, h, p) -> {
				for (var a : array)
					a.handleByteBuffer(u, h, p);
			};
		}

		/**
		 * Packet handler method. This method get called to handle or consume a pcap
		 * packet.
		 *
		 * @param user   the user
		 * @param header the header
		 * @param packet the packet
		 */
		void handleByteBuffer(U user, PcapHeader header, ByteBuffer packet);

		/**
		 * Creates a new handler that passes on new user data to the old handler. The
		 * original user data supplied is ignored.
		 *
		 * @param newUser the new userdata to supply
		 * @return new packet handler which overrides the original user data
		 */
		default OfByteBuffer<U> wrapUser(U newUser) {
			return (u, h, p) -> handleByteBuffer(newUser, h, p);
		}
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
		 * Wrap array.
		 *
		 * @param <U>   the generic type
		 * @param array the array
		 * @return the of memory segment
		 */
		static <U> OfMemorySegment<U> wrapArray(OfMemorySegment<U>[] array) {
			return (u, h, p) -> {
				for (var a : array)
					a.handleSegment(u, h, p);
			};
		}

		/**
		 * Packet handler method. This method get called to handle or consume a pcap
		 * packet.
		 *
		 * @param user   the user
		 * @param header the header
		 * @param packet the packet
		 */
		void handleSegment(U user, MemorySegment header, MemorySegment packet);

		/**
		 * Creates a new handler that passes on new user data to the old handler. The
		 * original user data supplied is ignored.
		 *
		 * @param newUser the new userdata to supply
		 * @return new packet handler which overrides the original user data
		 */
		default OfMemorySegment<U> wrapUser(U newUser) {
			return (u, h, p) -> handleSegment(newUser, h, p);
		}
	}

}
