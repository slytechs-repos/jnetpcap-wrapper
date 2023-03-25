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

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.util.function.Supplier;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapHandler;
import org.jnetpcap.PcapHandler.OfMemoryAddress;
import org.jnetpcap.PcapHandler.OfMemorySegment;
import org.jnetpcap.PcapHandler.PacketSource.PcapPacketSource;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.constant.PcapConstants;
import org.jnetpcap.internal.ArrayAllocator;

/**
 * A utility class with numerous Pcap packet handler interfaces used in the
 * packet capture. Also provides extensive set of additional, more advanced,
 * packet callbacks, including no-copy ones. The handler interfaces are purposes
 * functional, to be implemented by user full to receive packets from Pcap.
 * 
 * <p>
 * Here is an example which uses PcapHandler and several of its functional
 * packet handler interfaces.
 * </p>
 * 
 * <pre>
 * <code>
try (Pcap pcap = Pcap.openOffline(PCAP_FILE)) {

	BpFilter filter = pcap.compile("tcp", true);

	pcap.setFilter(filter);

	pcap.loop(1, PcapExample1::nextDefault, "Hello, this is copy to byte[] from Pcap class dispatch");

	PcapReceiver receiver = new PcapReceiver(pcap::loop);

	receiver.forEachCopy(1, PcapExample1::nextDefault, "Hello, this is copy to byte[] dispatch");
	receiver.forEachCopy(1, PcapExample1::nextByteBuffer, "Hello, this is copy to ByteBuffer dispatch");
	receiver.forEachDirect(1, PcapExample1::nextByteBuffer, "Hello, this is no-copy, direct ByteBuffer dispatch");
}
...
private static void nextByteBuffer(String message, PcapHeader header, ByteBuffer packet) {

	System.out.println(message);
	System.out.printf("Packet [timestamp=%s, wirelen=%-4d caplen=%-4d %s]%n",
			Instant.ofEpochMilli(header.toEpochMillis()),
			header.wireLength(),
			header.captureLength(),
			PcapUtils.toHexCurleyString(packet.limit(6)));
}

private static void nextDefault(String message, PcapHeader header, byte[] packet) {

	System.out.println(message);
	System.out.printf("Packet [timestamp=%s, wirelen=%-4d caplen=%-4d %s]%n",
			Instant.ofEpochMilli(header.toEpochMillis()),
			header.wireLength(),
			header.captureLength(),
			PcapUtils.toHexCurleyString(packet, 0, 6));
}
 * </code>
 * </pre>
 * 
 * Output:
 * 
 * <pre>
Hello, this is copy to byte[] from Pcap class dispatch
Packet [timestamp=2011-03-01T20:45:13.266Z, wirelen=74   caplen=74   {00:26:62:2f:47:87}]
Hello, this is copy to byte[] dispatch
Packet [timestamp=2011-03-01T20:45:13.313Z, wirelen=74   caplen=74   {00:1d:60:b3:01:84}]
Hello, this is copy to ByteBuffer dispatch
Packet [timestamp=2011-03-01T20:45:13.313Z, wirelen=66   caplen=66   {00:26:62:2f:47:87}]
Hello, this is no-copy, direct ByteBuffer dispatch
Packet [timestamp=2011-03-01T20:45:13.313Z, wirelen=200  caplen=200  {00:26:62:2f:47:87}]
 * </pre>
 * 
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
public final class PcapReceiver implements PcapPacketSource {

	/**
	 * Common array-handler, shared between PcapReceiver and Pcap0_4 implementation.
	 *
	 * @param <U>          the generic type
	 * @param packetSource the packet source
	 * @param count        the count
	 * @param handler      the handler
	 * @param user         the user
	 * @return the int
	 */
	public static <U> int commonArrayHandler(PcapPacketSource packetSource, int count,
			PcapHandler.OfArray<U> handler, U user) {

		return packetSource.sourcePackets(count, (ignore, header, bytes) -> {

			try (var arena = newArena()) {
				PcapHeader hdr = PcapHeader.newReadOnlyInstance(header);

				int caplen = hdr.captureLength();
				assert caplen < PcapConstants.MAX_SNAPLEN : "caplen/wirelen out of range " + caplen;

				byte[] packet = MemorySegment.ofAddress(bytes.address(), caplen, arena.scope())
						.toArray(ValueLayout.JAVA_BYTE);

				handler.handleArray(user, hdr, packet);
			}
		});
	}

	/**
	 * New scope.
	 *
	 * @return the memory session
	 */
	private static final Arena newArena() {
		return Arena.openShared();
	}

	/** The packet source from which we receive packets. */
	private final PcapPacketSource packetSource;

	/**
	 * Instantiates a new pcap handler using either Pcap.loop() or Pcap.dispatch()
	 * methods. For example {@code new PcapReceiver(pcap::loop)} or {@code new
	 * PcapHandler(pcap::dispatch)}.
	 *
	 * @param source the packet source
	 */
	public PcapReceiver(Supplier<PcapHandler.PacketSource> source) {
		if (!(source.get() instanceof PcapPacketSource psource))
			throw new IllegalArgumentException("invalid packet source %s".formatted(source));

		this.packetSource = psource;
	}

	/**
	 * Todo: array allocator needs a better design, or does it even makes sense? -
	 * mark.
	 *
	 * @param <U>            the generic type
	 * @param count          the count
	 * @param handler        the handler
	 * @param user           the user
	 * @param arenaAllocator the arena allocator
	 * @return the int
	 */
	@SuppressWarnings("unused")
	@Deprecated
	private <U> int copyEach(int count, PcapHandler.OfArrayAtOffset<U> handler, U user,
			ArrayAllocator arenaAllocator) {
		ArrayAllocator heap = arenaAllocator;

		return sourcePackets(count, (ignore, header, bytes) -> {
			try (var arena = newArena()) {
				PcapHeader hdr = PcapHeader.newReadOnlyInstance(header);

				int caplen = hdr.captureLength();
				assert caplen < 1560 : "caplen/wirelen out of range " + caplen;

				int offset = heap.allocate(caplen);
				heap.copy(MemorySegment.ofAddress(bytes.address(), caplen, arena.scope()));

				assert heap.length() == caplen;

				handler.handleArray(user, hdr, heap.array(), offset, caplen);
			}
		});
	}

	/**
	 * Dispatch, by no-copy, up to max count of packets to the memory address
	 * handler.
	 *
	 * @param <U>     the generic type
	 * @param count   the count
	 * @param handler the handler
	 * @param user    the user
	 * @return the int
	 * @throws PcapException the pcap exception
	 */
	public <U> int forEach(int count, OfMemoryAddress<U> handler, U user) throws PcapException {
		return packetSource.sourcePackets(count, (ignore, header, bytes) -> {
			handler.handleAddress(user, header, bytes);
		});
	}

	/**
	 * Dispatch, by no-copy, up to max count of packets to the memory segment
	 * handler.
	 *
	 * @param <U>     the generic type
	 * @param count   the count
	 * @param handler the handler
	 * @param user    the user
	 * @return the int
	 * @throws PcapException the pcap exception
	 */
	public <U> int forEach(int count, OfMemorySegment<U> handler, U user) throws PcapException {
		return sourcePackets(count, (ignore, header, bytes) -> {
			try (var arena = newArena()) {
				MemorySegment hseg = MemorySegment.ofAddress(header.address(),
						PcapHeader.PCAP_HEADER_PADDED_LENGTH,
						arena.scope());

				int caplen = PcapHeader.readCaptureLength(hseg);
				MemorySegment pseg = MemorySegment.ofAddress(bytes.address(), caplen, arena.scope());

				handler.handleMemorySegment(user, hseg, pseg, arena.scope());
			}
		});
	}

	/**
	 * Dispatch, by copy, up to max count packet to the byte array handler.
	 *
	 * @param <U>     the generic user type
	 * @param count   the max packet count to capture depending if
	 *                {@link Pcap#loop()} or {@link Pcap#dispatch()} is used.
	 * @param handler the user packet handler
	 * @param user    the user opaque data object
	 * @return the number of packets actually dispatched
	 */
	public <U> int forEachCopy(int count, PcapHandler.OfArray<U> handler, U user) {
		return commonArrayHandler(packetSource, count, handler, user);
	}

	/**
	 * Dispatch, by copy, up to max count packet to the byte ByteBuffer handler.
	 *
	 * @param <U>     the generic type
	 * @param count   the count
	 * @param handler the handler
	 * @param user    the user
	 * @return the int
	 */
	public <U> int forEachCopy(int count, PcapHandler.OfByteBuffer<U> handler, U user) {
		return sourcePackets(count, (ignore, header, bytes) -> {
			try (var arena = newArena()) {

				PcapHeader hdr = PcapHeader.newReadOnlyInstance(header);

				var pseg = MemorySegment.ofAddress(bytes.address(), hdr.captureLength(), arena.scope());

				ByteBuffer packet = ByteBuffer.wrap(pseg.toArray(ValueLayout.JAVA_BYTE));

				handler.handleByteBuffer(user, hdr, packet);
			}
		});
	}

	/**
	 * Dispatch, by no-copy or direct, up to max count packet to the byte ByteBuffer
	 * handler.
	 *
	 * @param <U>     the generic type
	 * @param count   the count
	 * @param handler the handler
	 * @param user    the user
	 * @return the int
	 * @throws PcapException the pcap exception
	 */
	public <U> int forEachDirect(int count, PcapHandler.OfByteBuffer<U> handler, U user) throws PcapException {

		return sourcePackets(count, (ignore, header, bytes) -> {
			try (var arena = newArena()) {
				PcapHeader hdr = PcapHeader.newReadOnlyInstance(header);

				ByteBuffer packet = MemorySegment
						.ofAddress(bytes.address(), hdr.captureLength(), arena.scope())
						.asByteBuffer();

				handler.handleByteBuffer(user, hdr, packet);
			}
		});
	}

	/**
	 * Source packets.
	 *
	 * @param count   the count
	 * @param handler the handler
	 * @return the int
	 * @see org.jnetpcap.PcapHandler.PacketSource.PcapPacketSource#sourcePackets(int,
	 *      org.jnetpcap.PcapHandler.OfRawPacket)
	 */
	@Override
	public int sourcePackets(int count, PcapHandler handler) {
		return packetSource.sourcePackets(count, handler);
	}

}
