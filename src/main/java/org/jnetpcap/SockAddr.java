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

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Optional;
import java.util.OptionalInt;

import org.jnetpcap.constant.SockAddrFamily;
import org.jnetpcap.internal.ForeignUtils;
import org.jnetpcap.internal.NativeABI;
import org.jnetpcap.util.PcapUtils;

import static java.lang.foreign.ValueLayout.*;

/**
 * The low level <code>sockaddr</code> structure containing an address of
 * different types, depending on the protocol family value. The class is
 * extended by specific subclasses which provide additional fields relating to
 * each protocol address family (AF).
 *
 * <p>
 * BSD style structure
 * </p>
 * 
 * <pre>
 * <code>
 * struct sockaddr {
    u_char sa_len;     // Total length of the structure
    u_char sa_family;  // Address family (e.g., AF_INET for IPv4)
    char   sa_data[14]; // Address data (actual size may vary)
   };
 * </code>
 * </pre>
 * 
 * <p>
 * POSIX style structure
 * </p>
 * 
 * <pre>
 * <code>
 * struct sockaddr {
    u_short sa_family;  // Address family (e.g., AF_INET for IPv4)
    char    sa_data[14]; // Address data (actual size may vary)
   };
 * </code>
 * </pre>
 * 
 */
public class SockAddr {

	/**
	 * The structure of <code>sockaddr_in6</code>, used for IPv6 sockets.
	 */
	public static final class Inet6SockAddr extends SockAddr {

		/** The addr. */
		private final byte[] addr;

		/** The port. */
		private final int port;

		/** The flow info. */
		private final int flowInfo;

		/** The scope id. */
		private final int scopeId;

		/**
		 * Instantiates a new inet sock addr.
		 *
		 * @param addr  the addr
		 * @param arena the arena
		 */
		Inet6SockAddr(MemorySegment addr, Arena arena) {
			super(SaLayout.AF_INET6.reinterpret(addr, arena), SockAddrFamily.INET6, SockAddrFamily.INET6.totalLength());

			this.port = Short.toUnsignedInt((short) SaLayout.AF_INET6_PORT.get(saSegment));
			this.flowInfo = (int) SaLayout.AF_INET6_FLOWINFO.get(saSegment);
			this.scopeId = (int) SaLayout.AF_INET6_SCOPEID.get(saSegment);
			this.addr = saSegment.asSlice(8, 16).toArray(JAVA_BYTE);
		}

		/**
		 * IPv6 address.
		 *
		 * @return address field value
		 */
		public byte[] address() {
			return addr;
		}

		/**
		 * IPv6 flow information.
		 *
		 * @return 32 bit field value
		 */
		public int flowInfo() {
			return flowInfo;
		}

		/**
		 * Transport layer port number.
		 *
		 * @return 16 bit port field value
		 */
		public int port() {
			return port;
		}

		/**
		 * Scope ID (interface for link-local addresses).
		 *
		 * @return 32 bit scope ID field value
		 */
		public int scopeId() {
			return scopeId;
		}

		/**
		 * String representation of the structure fields.
		 *
		 * @return the string
		 * @see java.lang.Object#toString()
		 */
		@Override
		public String toString() {
			return "AF_INET6" + "[port=" + port
					+ " flowInfo=" + flowInfo
					+ " addr=" + PcapUtils.toAddressString(address())
					+ " scopeId=" + scopeId
					+ "]";
		}

	}

	/**
	 * The structure of <code>sockaddr_in</code>, used for IPv4 sockets.
	 */
	public static final class InetSockAddr extends SockAddr {

		/** The addr. */
		private final byte[] addr;

		/** The port. */
		private final int port;

		/**
		 * Instantiates a new inet sock addr.
		 *
		 * @param addr  the addr
		 * @param arena the arena
		 */
		InetSockAddr(MemorySegment addr, Arena arena) {
			super(SaLayout.AF_INET.reinterpret(addr, arena), SockAddrFamily.INET, SockAddrFamily.INET.totalLength());

			this.port = Short.toUnsignedInt((short) SaLayout.AF_INET_PORT.get(saSegment));
			this.addr = saSegment.asSlice(4, 4).toArray(JAVA_BYTE);
		}

		/**
		 * IPv4 address.
		 *
		 * @return address field value
		 */
		public byte[] address() {
			return addr;
		}

		/**
		 * Port number in network byte order.
		 *
		 * @return port field value
		 */
		public int port() {
			return port;
		}

		/**
		 * String representation of the structure field values.
		 *
		 * @return the string
		 * @see java.lang.Object#toString()
		 */
		@Override
		public String toString() {
			return "AF_INET" + "[port=" + port
					+ ", addr=" + PcapUtils.toAddressString(address()) + "]";
		}
	}

	/**
	 * The structure of <code>sockaddr_ipx</code>, used for AF_IPX sockets.
	 */
	public static final class IpxSockAddr extends SockAddr {

		/** The addr. */
		private final byte[] nodenum;

		/** The port. */
		private final int netnum;

		/** The socket. */
		private final int socket;

		/**
		 * Instantiates a new inet sock addr.
		 *
		 * @param addr  the addr
		 * @param arena the arena
		 */
		IpxSockAddr(MemorySegment addr, Arena arena) {
			super(SaLayout.AF_IPX.reinterpret(addr, arena), SockAddrFamily.IPX, SockAddrFamily.IPX.totalLength());

			this.netnum = Short.toUnsignedInt((short) SaLayout.AF_IPX_NETNUM.get(saSegment));
			this.nodenum = saSegment.asSlice(4, 6).toArray(JAVA_BYTE);
			this.socket = Short.toUnsignedInt((short) SaLayout.AF_IPX_SOCKET.get(saSegment));
		}

		/**
		 * IPX node number (MAC address).
		 *
		 * @return address field value
		 */
		public byte[] nodeNum() {
			return nodenum;
		}

		/**
		 * IPX network number.
		 *
		 * @return port field value
		 */
		public int netNum() {
			return netnum;
		}

		/**
		 * IPX socket number.
		 *
		 * @return the int
		 */
		public int socket() {
			return socket;
		}

		/**
		 * String representation of the structure field values.
		 *
		 * @return the string
		 * @see java.lang.Object#toString()
		 */
		@Override
		public String toString() {
			return "AF_IPX" + "["
					+ "port=" + netnum
					+ ", addr=" + PcapUtils.toAddressString(nodeNum())
					+ ", socket=" + socket
					+ "]";
		}
	}

	/**
	 * The structure of <code>sockaddr_ll</code>, used with AF_PACKET sockets for
	 * raw packet access on Linux.
	 */
	public static final class PacketSockAddr extends SockAddr {

		/** The addr. */
		private final byte[] addr;

		/** The port. */
		private final int protocol;

		/** The pkt type. */
		private final int pktType;

		/** The if index. */
		private final int ifIndex;

		/** The ha type. */
		private final int haType;

		/** The ha len. */
		private final byte haLen;

		/**
		 * Instantiates a new inet sock addr.
		 *
		 * @param addr  the addr
		 * @param arena the arena
		 */
		PacketSockAddr(MemorySegment addr, Arena arena) {
			super(SaLayout.AF_PACKET.reinterpret(addr, arena), SockAddrFamily.PACKET, SockAddrFamily.PACKET
					.totalLength());

			this.protocol = Short.toUnsignedInt((short) SaLayout.AF_PACKET_PROTOCOL.get(saSegment));
			this.ifIndex = (int) SaLayout.AF_PACKET_IFINDEX.get(saSegment);
			this.haType = Short.toUnsignedInt((short) SaLayout.AF_PACKET_HATYPE.get(saSegment));
			this.pktType = (byte) SaLayout.AF_PACKET_PKTTYPE.get(saSegment);
			this.haLen = (byte) SaLayout.AF_PACKET_HALEN.get(saSegment);
			this.addr = saSegment.asSlice(12, this.haLen).toArray(JAVA_BYTE);
		}

		/**
		 * Hardware address.
		 *
		 * @return address field value
		 */
		public byte[] address() {
			return addr;
		}

		/**
		 * Hardware length.
		 *
		 * @return the int
		 */
		public int hardwareLength() {
			return haLen;
		}

		/**
		 * Hardware type.
		 *
		 * @return haType field value
		 */
		public int hardwareType() {
			return haType;
		}

		/**
		 * Interface index.
		 *
		 * @return ifIndex field value
		 */
		public int interfaceIndex() {
			return ifIndex;
		}

		/**
		 * Packet type.
		 *
		 * @return pktType field value
		 */
		public int packetType() {
			return pktType;
		}

		/**
		 * Protocol (e.g., ETH_P_ALL, ETH_P_IP) .
		 *
		 * @return protocol field value
		 */
		public int protocol() {
			return protocol;
		}

		/**
		 * String representation of the structure field values.
		 *
		 * @return the string
		 * @see java.lang.Object#toString()
		 */
		@Override
		public String toString() {
			return "AF_PACKET" + "["
					+ "protocol=" + protocol
					+ ", ifIndex=" + ifIndex
					+ ", haType=" + haType
					+ ", pktType=" + pktType
					+ ", haLen=" + haLen
					+ ", addr=" + PcapUtils.toAddressString(address())
					+ "]";
		}
	}

	/**
	 * The structure of <code>sockaddr_dl</code>, used with AF_LINK sockets on macOS
	 * to access link-layer information.
	 */
	public static final class LinkSockAddr extends SockAddr {

		/** The addr. */
		private final byte[] data;

		/** The port. */
		private final int index;

		/** The type. */
		private final int type;

		/** The nlen. */
		private final int nlen;

		/** The alen. */
		private final int alen;

		/** The slen. */
		private final int slen;

		/** The selector. */
		private OptionalInt selector;

		/** The name. */
		private Optional<String> name;

		/** The address. */
		private byte[] address;

		/**
		 * Instantiates a new inet sock addr.
		 *
		 * @param addr        the addr
		 * @param arena       the arena
		 * @param totalLength the total length
		 */
		LinkSockAddr(MemorySegment addr, Arena arena, int totalLength) {
			super(addr.reinterpret(totalLength, arena, __ -> {}), SockAddrFamily.LINK, OptionalInt.of(totalLength));

			this.index = Short.toUnsignedInt((short) SaLayout.AF_LINK_INDEX.get(saSegment));
			this.type = Byte.toUnsignedInt((byte) SaLayout.AF_LINK_TYPE.get(saSegment));
			this.nlen = Byte.toUnsignedInt((byte) SaLayout.AF_LINK_NLEN.get(saSegment));
			this.alen = Byte.toUnsignedInt((byte) SaLayout.AF_LINK_ALEN.get(saSegment));
			this.slen = Byte.toUnsignedInt((byte) SaLayout.AF_LINK_SLEN.get(saSegment));
			this.data = saSegment.asSlice(4, 4).toArray(JAVA_BYTE);

			int off = 8; // Keep a running offset

			this.name = (nlen == 0)
					? Optional.empty()
					: Optional.of(new String(saSegment.asSlice(off, nlen).toArray(JAVA_BYTE)));
			off += nlen;

			this.address = saSegment.asSlice(off, alen).toArray(JAVA_BYTE);
			off += alen;

			this.selector = readNumberByLength(saSegment.asSlice(off, slen), slen);
		}

		/**
		 * Read number by length.
		 *
		 * @param mseg the mseg
		 * @param len  the len
		 * @return the optional int
		 */
		private static OptionalInt readNumberByLength(MemorySegment mseg, int len) {
			return switch (len) {
			case 1 -> OptionalInt.of(Byte.toUnsignedInt(mseg.get(JAVA_BYTE, 0)));
			case 2 -> OptionalInt.of(Short.toUnsignedInt(mseg.get(JAVA_SHORT, 0)));
			case 4 -> OptionalInt.of(mseg.get(JAVA_INT, 0));

			default -> OptionalInt.empty();
			};
		}

		/**
		 * Variable-length data containing, interface name (null-terminated), Link-layer
		 * address Link-layer and selector (if any).
		 *
		 * 
		 * @return data field value
		 */
		@Override
		public byte[] data() {
			return data;
		}

		/**
		 * Interface index of the network device.
		 *
		 * @return index field value
		 */
		public int index() {
			return index;
		}

		/**
		 * Link-layer address type (e.g., IFT_ETHER for Ethernet).
		 *
		 * @return type field value
		 */
		public int addressType() {
			return type;
		}

		/**
		 * Length of the interface name string.
		 *
		 * @return nlen field value
		 */
		public int nameLength() {
			return nlen;
		}

		/**
		 * Length of the link-layer address in bytes.
		 *
		 * @return alen field value
		 */
		public int addressLength() {
			return alen;
		}

		/**
		 * Selector length.
		 *
		 * @return type field value
		 */
		public int selectorLength() {
			return slen;
		}

		/**
		 * Length of the link-layer selector (usually 0).
		 *
		 * @return address field value
		 */
		public byte[] address() {
			return address;
		}

		/**
		 * interface name.
		 *
		 * @return name field value
		 */
		public Optional<String> name() {
			return name;
		}

		/**
		 * Link-layer selector.
		 *
		 * @return selector field value
		 */
		public OptionalInt selector() {
			return selector;
		}

		/**
		 * String representation of the structure field values.
		 *
		 * @return the string
		 * @see java.lang.Object#toString()
		 */
		@Override
		public String toString() {
			return "AF_LINK(len=%d)".formatted(totalLength().orElse(20))
					+ "["
					+ "index=" + index
					+ "type=" + type
					+ "nlen=" + nlen
					+ "alen=" + alen
					+ "slen=" + slen
					+ (name.isEmpty() ? "" : ", name=" + name.get())
					+ ", addr=" + PcapUtils.toAddressString(address())
					+ (selector.isEmpty() ? "" : ", sel=0x%x".formatted(selector.getAsInt()))
					+ "]";
		}
	}

	/** Maximum sockaddr_t structure address data length. */
	public final static int MIM_SOCKADDR_ADDRESS_LEN = 14;

	/** The Constant MIM_SOCKADDR_STRUCT_LEN. */
	public final static int MIM_SOCKADDR_STRUCT_LEN = 16;

	/** The Constant MAX_SOCKADDR_ADDRESS_LEN. */
	public final static int MAX_SOCKADDR_ADDRESS_LEN = 255;

	/**
	 * Factory method call to instantiate a new SockAddr instance based on AF_FAMILY
	 * type.
	 *
	 * @param <T>   the generic type
	 * @param value the value
	 * @param arena the scope
	 * @return the sock addr
	 */
	@SuppressWarnings("unchecked")
	static <T extends SockAddr> T newInstance(Object value, Arena arena) {

		MemorySegment addr = (MemorySegment) value;
		if (ForeignUtils.isNullAddress(addr))
			return null;

		MemorySegment first2BytesSeg = addr.reinterpret(2); // Enough to read family field

		int af = readFamilyField(first2BytesSeg);
		OptionalInt totalLength = readTotalLengthField(first2BytesSeg);
		SockAddrFamily familyConst = SockAddrFamily.lookup(af).orElse(null);

		return switch (familyConst) {

		case INET -> (T) new InetSockAddr(addr, arena);
		case INET6 -> (T) new Inet6SockAddr(addr, arena);
		case IPX -> (T) new IpxSockAddr(addr, arena);
		case PACKET -> (T) new PacketSockAddr(addr, arena);
		case LINK -> (T) new LinkSockAddr(addr, arena, totalLength.getAsInt());

		default -> {
			if (totalLength.isPresent()) {
				yield (T) new SockAddr(addr.reinterpret(totalLength.getAsInt(), arena, __ -> {}), af, totalLength);
			} else {
				yield (T) new SockAddr(addr.reinterpret(MIM_SOCKADDR_STRUCT_LEN, arena, __ -> {}), af, totalLength);
			}
		}
		};
	}

	/**
	 * Read family field.
	 *
	 * @param mseg the mseg
	 * @return the int
	 */
	private static int readFamilyField(MemorySegment mseg) {

		if (NativeABI.isBsdAbi())
			return Byte.toUnsignedInt((byte) SaLayout.FAMILY8.get(mseg));
		else
			return Short.toUnsignedInt((short) SaLayout.FAMILY16.get(mseg));
	}

	/**
	 * Read address length field.
	 *
	 * @param mseg the mseg
	 * @return the optional int
	 */
	private static OptionalInt readTotalLengthField(MemorySegment mseg) {

		if (!NativeABI.isBsdAbi())
			return OptionalInt.empty();

		int addrLen = Byte.toUnsignedInt((byte) SaLayout.ADDR_LEN.get(mseg));

		return OptionalInt.of(addrLen);
	}

	/** The family. */
	private final int saFamily;

	/** Minimum 14 bytes of protocol address. */
	private final byte[] saData;

	/**
	 * (Optional and BSD-specific) The native structure <code>sa_len</code> field is
	 * primarily found in BSD-derived systems (FreeBSD, OpenBSD, NetBSD). It's not
	 * present in the POSIX-specified sockaddr structure.
	 */
	private final OptionalInt saLen;

	/** The sa segment. */
	protected final MemorySegment saSegment;

	/**
	 * Sock address base structure containing common and generic fields identifying
	 * the actual SA type. The subclass is identified by the native
	 * <code>sa_family</code> structure field.
	 *
	 * @param mseg        the memory segment containing the off-heap
	 *                    <code>sockaddr</code> structure
	 * @param family      the SA family type
	 * @param totalLength the total length in bytes of the entire socket structure
	 */
	private SockAddr(MemorySegment mseg, int family, OptionalInt totalLength) {
		this.saSegment = mseg;
		this.saFamily = family;
		this.saLen = totalLength;

		/*
		 * skip first 2 bytes (1 byte sa_len on BSD system and 1 or 2 bytes sa_field on
		 * all the rest) and convert the rest to a byte array.
		 */
		this.saData = mseg.asSlice(2).toArray(ValueLayout.JAVA_BYTE);
	}

	/**
	 * Instantiates a new sock addr.
	 *
	 * @param mseg           the mseg
	 * @param familyConstant the family.
	 * @param totalLength    the addr len.
	 */
	protected SockAddr(MemorySegment mseg, SockAddrFamily familyConstant, OptionalInt totalLength) {
		this(mseg, familyConstant.getAsInt(), totalLength);
	}

	/**
	 * Socket Address data (actual size may vary).
	 *
	 * @return the byte array containing socket raw data
	 */
	public byte[] data() {
		return saData;
	}

	/**
	 * Address family (e.g., INET for IPv4)
	 *
	 * @return 8 (BSD sockets) or 16 (Posix sockets) bit address family value
	 */
	public int family() {
		return saFamily;
	}

	/**
	 * Gets the AF family value as a constant.
	 *
	 * @return the socket address family constant
	 * @throws IllegalArgumentException thrown if the constant for the family value
	 *                                  is not found.
	 */
	public Optional<SockAddrFamily> familyConstant() {
		return SockAddrFamily.lookup(saFamily);
	}

	/**
	 * Checks if this AF address is of specifc family type.
	 *
	 * @param family the AF family type
	 * @return true, if address is of AF type specified
	 */
	public boolean isFamily(SockAddrFamily family) {
		return family.isMatch(this.saFamily);
	}

	/**
	 * String representation of the structure field values.
	 *
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "AF_%s[".formatted(familyConstant().orElse(null))
				+ "fam=%s(%d)".formatted(SockAddrFamily.lookup(saFamily).orElse(null), saFamily)
				+ " addr=" + PcapUtils.toAddressString(saData)
				+ "]";
	}

	/**
	 * The total length of the socket address structure in bytes. The value is only
	 * returned on certain platforms (BSD style sockets)..
	 *
	 * @return the length of the address structure if available on this particular
	 *         platform
	 */
	public OptionalInt totalLength() {
		return saLen;
	}
}