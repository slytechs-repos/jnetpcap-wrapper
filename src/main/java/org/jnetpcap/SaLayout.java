/*
 * Copyright 2023-2024 Sly Technologies Inc
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

import static org.jnetpcap.internal.ForeignUtils.*;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemoryLayout.PathElement;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.util.stream.Stream;

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;
import static java.lang.foreign.ValueLayout.*;

/**
 * Defines the memory layouts for various socket address (sockaddr) structures
 * used in network programming. This enum provides access to the internal
 * structure and fields of different address family types supported by the
 * operating system.
 * 
 * <h2>Supported Address Families</h2> The layout supports several socket
 * address types:
 * <ul>
 * <li>AF_INET - IPv4 addresses (sockaddr_in)</li>
 * <li>AF_INET6 - IPv6 addresses (sockaddr_in6)</li>
 * <li>AF_IPX - IPX/SPX protocol addresses</li>
 * <li>AF_PACKET - Low-level packet interface (Linux)</li>
 * <li>AF_LINK - Link layer interface (BSD systems)</li>
 * <li>AF_IRDA - Infrared Data Association (Windows)</li>
 * </ul>
 * 
 * <h2>Structure Layout</h2> Each socket address structure begins with a common
 * header:
 * <ul>
 * <li>BSD style: uint8_t sa_len + uint8_t sa_family</li>
 * <li>POSIX style: uint16_t sa_family</li>
 * </ul>
 * 
 * <p>
 * Following the header is address family-specific data organized in a union
 * structure.
 * </p>
 * 
 * @see java.lang.foreign.MemoryLayout
 * @see java.lang.foreign.MemorySegment
 */
enum SaLayout {

	/** The family16. */

	/* Shared SA fields */
	FAMILY16("u1.family16"),

	/** The family8. */
	FAMILY8("u1.s1.family8"),

	/** The addr len. */
	ADDR_LEN("u1.s1.addr_len"),

	/** The data. */
	DATA("u2.data", sequenceElement(0)),

	/* AF_FAMILY type specific data */

	/** The af inet. */
	AF_INET("u2.af_inet.last"),

	/** The af inet port. */
	AF_INET_PORT("u2.af_inet.port"),

	/** The af inet addr. */
	AF_INET_ADDR("u2.af_inet.addr", sequenceElement(0)),

	/** The af inet6. */
	AF_INET6("u2.af_inet6.last"),

	/** The af inet6 port. */
	AF_INET6_PORT("u2.af_inet6.port"),

	/** The af inet6 flowinfo. */
	AF_INET6_FLOWINFO("u2.af_inet6.flowinfo"),

	/** The af inet6 scopeid. */
	AF_INET6_SCOPEID("u2.af_inet6.scope_id"),

	/** The af inet6 addr. */
	AF_INET6_ADDR("u2.af_inet6.addr", sequenceElement(0)),

	/** The af ipx. */
	AF_IPX("u2.af_ipx.last"),

	/** The af ipx netnum. */
	AF_IPX_NETNUM("u2.af_ipx.netnum"),

	/** The af ipx nodenum. */
	AF_IPX_NODENUM("u2.af_ipx.nodenum", sequenceElement(0)),

	/** The af ipx socket. */
	AF_IPX_SOCKET("u2.af_ipx.socket"),

	/** The af packet. */
	AF_PACKET("u2.af_packet.last"),

	/** The af packet protocol. */
	AF_PACKET_PROTOCOL("u2.af_packet.protocol"),

	/** The af packet ifindex. */
	AF_PACKET_IFINDEX("u2.af_packet.ifindex"),

	/** The af packet hatype. */
	AF_PACKET_HATYPE("u2.af_packet.hatype"),

	/** The af packet pkttype. */
	AF_PACKET_PKTTYPE("u2.af_packet.pkttype"),

	/** The af packet halen. */
	AF_PACKET_HALEN("u2.af_packet.halen"),

	/** The af packet addr. */
	AF_PACKET_ADDR("u2.af_packet.addr", sequenceElement(0)),

	/**
	 * The sockaddr_dl structure, used with AF_LINK sockets on macOS to access
	 * link-layer information.
	 */
	AF_LINK("u2.af_link.last"),

	/** The AF_LINK Interface index. */
	AF_LINK_INDEX("u2.af_link.sdl_index"),

	/** The AF_LINK Link-layer address type. */
	AF_LINK_TYPE("u2.af_link.sdl_type"),

	/** The AF_LINK Length of interface name. */
	AF_LINK_NLEN("u2.af_link.sdl_nlen"),

	/** The AF_LINK Length of link-layer address. */
	AF_LINK_ALEN("u2.af_link.sdl_alen"),

	/** The AF_LINK Length of link-layer selector. */
	AF_LINK_SLEN("u2.af_link.sdl_slen"),

	/** The AF_LINK Interface name, link-layer address, and selector. */
	AF_LINK_DATA("u2.af_link.sdl_data", sequenceElement(0)),

	/**
	 * AF_IRDA definition (winsock2.h)
	 */
	AF_IRDA("u2.af_irda.last"),

	/** 4-byte device identifier for the IrDA device */
	AF_IRDA_DEVICE_ID("u2.af_irda.irdaDeviceID", sequenceElement(0)),

	/** null-terminated string specifying the service name */
	AF_IRDA_SERVICE_NAME("u2.af_irda.irdaServiceName", sequenceElement(0)),
	;

	/**
	 * Needed inorder to initialize before enum constants.
	 */
	private final class Initializer {

		/** The Constant LAST. */
		private static final MemoryLayout LAST = sequenceLayout(0, JAVA_BYTE).withName("last");

		/** The Constant LAYOUT. */
		private static final MemoryLayout SOCK_ADDR_LAYOUT = structLayout(

				/* Common sockaddr header */
				unionLayout(
						JAVA_SHORT.withName("family16"),
						structLayout(
								JAVA_BYTE.withName("addr_len"),
								JAVA_BYTE.withName("family8"),
								LAST).withName("s1")

				).withName("u1"),

				/* AF_FAMILY type specific data */
				unionLayout(

						/* AF_INET */
						structLayout(
								JAVA_SHORT.withName("port").withOrder(ByteOrder.BIG_ENDIAN),
								sequenceLayout(4, JAVA_BYTE).withName("addr"),
								LAST).withName("af_inet"),

						/* AF_INET6 */
						structLayout(
								JAVA_SHORT.withName("port"),
								JAVA_INT.withName("flowinfo").withByteAlignment(2),
								sequenceLayout(16, JAVA_BYTE).withName("addr"),
								JAVA_INT.withName("scope_id").withByteAlignment(2),
								LAST).withName("af_inet6"),

						/* AF_IPX */
						structLayout(
								JAVA_SHORT.withName("netnum"),
								sequenceLayout(6, JAVA_BYTE).withName("nodenum"),
								JAVA_SHORT.withName("socket"),
								LAST).withName("af_ipx"),

						/* AF_PACKET */
						structLayout(
								JAVA_SHORT.withName("protocol"),
								JAVA_INT.withName("ifindex").withByteAlignment(2),
								JAVA_SHORT.withName("hatype"),
								JAVA_BYTE.withName("pkttype"),
								JAVA_BYTE.withName("halen"),
								sequenceLayout(8, JAVA_BYTE).withName("addr"),
								LAST).withName("af_packet"),

						/* AF_LINK - non-POSIX/BSD */
						structLayout(
								JAVA_SHORT.withName("sdl_index"),
								JAVA_BYTE.withName("sdl_type"),
								JAVA_BYTE.withName("sdl_nlen"),
								JAVA_BYTE.withName("sdl_alen"),
								JAVA_BYTE.withName("sdl_slen"),
								sequenceLayout(12 + 18, JAVA_BYTE).withName("sdl_data"),
								LAST).withName("af_link"),

						/* AF_IRDA - POSIX/Windows (winsock2.h) */
						structLayout(
								sequenceLayout(4, JAVA_BYTE).withName("irdaDeviceID"),
								sequenceLayout(25, JAVA_BYTE).withName("irdaServiceName"),
								LAST).withName("af_irda"),

						/* Generic MIN size sockaddr structure */
						sequenceLayout(MIM_SOCKADDR_ADDRESS_LEN, JAVA_BYTE).withName("data")

				).withName("u2")

		);
	}

	/** Maximum sockaddr_t structure address data length. */
	private final static int MIM_SOCKADDR_ADDRESS_LEN = 14;

	/**
	 * Returns the total size in bytes of the sockaddr structure layout. This size
	 * accommodates the largest possible socket address structure among all
	 * supported address families.
	 *
	 * @return The size in bytes of the complete sockaddr structure
	 */
	public static long sizeOf() {
		return Initializer.SOCK_ADDR_LAYOUT.byteSize();
	}

	/** The var handle. */
	public final VarHandle varHandle;

	/** The full paths. */
	private final PathElement[] fullPaths;

	/**
	 * Instantiates a new sa layout.
	 *
	 * @param path     the path
	 * @param elements the elements
	 */
	SaLayout(String path, PathElement... elements) {
		fullPaths = Stream.concat(Stream.of(path(path)), Stream.of(elements))
				.toArray(PathElement[]::new);

		if (path.endsWith(".last"))
			this.varHandle = null;
		else
			this.varHandle = Initializer.SOCK_ADDR_LAYOUT.varHandle(fullPaths);
	}

	/**
	 * Returns the byte offset of this field within the sockaddr structure. Useful
	 * for direct memory access to specific fields.
	 *
	 * @return The byte offset of this field
	 */
	public long byteOffset() {
		return Initializer.SOCK_ADDR_LAYOUT.byteOffset(fullPaths);
	}

	/**
	 * Retrieves the value of this field from the given memory segment. The return
	 * type depends on the field's data type in the native structure.
	 *
	 * @param mseg The memory segment containing the sockaddr structure
	 * @return The value of this field
	 * @throws IllegalStateException if this enum constant represents a structure
	 *                               rather than a field
	 */
	public Object get(MemorySegment mseg) {
		if (varHandle == null)
			throw new IllegalStateException("Not a value constant");

		return varHandle.get(mseg, 0L);
	}

	/**
	 * Retrieves the numeric value of this field from the given memory segment. This
	 * method should only be used for numeric fields (e.g., ports, lengths).
	 *
	 * @param mseg The memory segment containing the sockaddr structure
	 * @return The numeric value of this field
	 * @throws ClassCastException if the field is not numeric
	 */
	public Number getNumber(MemorySegment mseg) {
		return (Number) get(mseg);
	}

	/**
	 * Gets the value of this field as an unsigned short. Useful for fields like
	 * ports that are naturally unsigned 16-bit values.
	 *
	 * @param mseg The memory segment containing the sockaddr structure
	 * @return The unsigned short value (as an integer between 0 and 65535)
	 */
	public Number getUnsignedShort(MemorySegment mseg) {
		return Short.toUnsignedInt(getNumber(mseg).shortValue());
	}

	/**
	 * Gets the value of this field as an unsigned byte. Useful for fields like
	 * address lengths that are naturally unsigned 8-bit values.
	 *
	 * @param mseg The memory segment containing the sockaddr structure
	 * @return The unsigned byte value (as an integer between 0 and 255)
	 */
	public Number getUnsignedByte(MemorySegment mseg) {
		return Byte.toUnsignedInt(getNumber(mseg).byteValue());
	}

	/**
	 * Reinterprets a memory segment as a sockaddr structure. This method ensures
	 * proper alignment and size constraints are maintained.
	 *
	 * @param address The memory segment to reinterpret
	 * @param arena   The arena managing the lifetime of the memory
	 * @return A memory segment representing the sockaddr structure
	 */
	public MemorySegment reinterpret(MemorySegment address, Arena arena) {
		return address.reinterpret(sizeOf(), arena, __ -> {});
	}
}