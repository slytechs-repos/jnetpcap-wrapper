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
 * MemoryLayout for SockAddr structures, including various AF_FAMILY struct
 * types.
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
	DATA("u2.data", sequenceElement()),

	/* AF_FAMILY type specific data */

	/** The af inet. */
	AF_INET("u2.af_inet.last"),

	/** The af inet port. */
	AF_INET_PORT("u2.af_inet.port"),

	/** The af inet addr. */
	AF_INET_ADDR("u2.af_inet.addr", sequenceElement()),

	/** The af inet6. */
	AF_INET6("u2.af_inet6.last"),

	/** The af inet6 port. */
	AF_INET6_PORT("u2.af_inet6.port"),

	/** The af inet6 flowinfo. */
	AF_INET6_FLOWINFO("u2.af_inet6.flowinfo"),

	/** The af inet6 scopeid. */
	AF_INET6_SCOPEID("u2.af_inet6.scope_id"),

	/** The af inet6 addr. */
	AF_INET6_ADDR("u2.af_inet6.addr", sequenceElement()),

	/** The af ipx. */
	AF_IPX("u2.af_ipx.last"),

	/** The af ipx netnum. */
	AF_IPX_NETNUM("u2.af_ipx.netnum"),

	/** The af ipx nodenum. */
	AF_IPX_NODENUM("u2.af_ipx.nodenum", sequenceElement()),

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
	AF_PACKET_ADDR("u2.af_packet.addr", sequenceElement()),

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
	AF_LINK_DATA("u2.af_link.sdl_data", sequenceElement()),

	/**
	 * AF_IRDA definition (winsock2.h)
	 */
	AF_IRDA("u2.af_irda.last"),

	/** 4-byte device identifier for the IrDA device */
	AF_IRDA_DEVICE_ID("u2.af_irda.irdaDeviceID", sequenceElement()),

	/** null-terminated string specifying the service name */
	AF_IRDA_SERVICE_NAME("u2.af_irda.irdaServiceName", sequenceElement()),
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
	 * Size of.
	 *
	 * @return the long
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
		PathElement[] parsed = path(path);
		fullPaths = Stream.concat(Stream.of(path(path)), Stream.of(elements))
				.toArray(PathElement[]::new);

		if (path.endsWith(".last"))
			this.varHandle = null;
		else
			this.varHandle = Initializer.SOCK_ADDR_LAYOUT.varHandle(fullPaths);

	}

	/**
	 * Byte offset.
	 *
	 * @return the long
	 */
	public long byteOffset() {
		return Initializer.SOCK_ADDR_LAYOUT.byteOffset(fullPaths);
	}

	/**
	 * Gets the.
	 *
	 * @param mseg the mseg
	 * @return the object
	 */
	public Object get(MemorySegment mseg) {
		if (varHandle == null)
			throw new IllegalStateException("Not a value constant");

		return varHandle.get(mseg, 0L);
	}

	/**
	 * Reinterpret.
	 *
	 * @param address the address
	 * @param arena   the arena
	 * @return the memory segment
	 */
	public MemorySegment reinterpret(MemorySegment address, Arena arena) {
		long offset = Initializer.SOCK_ADDR_LAYOUT.byteOffset(fullPaths);

		return address.reinterpret(offset, arena, __ -> {});
	}
}