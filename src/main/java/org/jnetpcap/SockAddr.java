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
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Optional;
import java.util.OptionalInt;

import org.jnetpcap.constant.ArpHdr;
import org.jnetpcap.constant.SockAddrFamily;
import org.jnetpcap.internal.ForeignUtils;
import org.jnetpcap.internal.NativeABI;
import org.jnetpcap.util.PcapUtils;

import static java.lang.foreign.ValueLayout.*;

/**
 * A Java representation of the native socket address (sockaddr) structure and
 * its protocol-specific variants. Socket addresses are used to identify network
 * endpoints in various networking protocols.
 * 
 * <h2>Platform-Specific Variants</h2> The native sockaddr structure has two
 * main variants:
 * 
 * <h3>BSD-style Structure</h3>
 * 
 * <pre>{@code
 * struct sockaddr {
 *     uint8_t  sa_len;     // Total length of the structure
 *     uint8_t  sa_family;  // Address family (AF_*)
 *     char     sa_data[14];// Protocol-specific address data
 * };
 * }</pre>
 * 
 * <h3>POSIX-style Structure</h3>
 * 
 * <pre>{@code
 * struct sockaddr {
 *     uint16_t sa_family;  // Address family (AF_*)
 *     char     sa_data[14];// Protocol-specific address data
 * };
 * }</pre>
 * 
 * <h2>Protocol Families</h2> This class serves as the base for
 * protocol-specific socket address structures:
 * <ul>
 * <li>{@link InetSockAddr} - IPv4 addresses (AF_INET)</li>
 * <li>{@link Inet6SockAddr} - IPv6 addresses (AF_INET6)</li>
 * <li>{@link PacketSockAddr} - Link-layer packet info (AF_PACKET) [Linux]</li>
 * <li>{@link LinkSockAddr} - Link-layer info (AF_LINK) [BSD platforms]</li>
 * <li>{@link IpxSockAddr} - IPX/SPX addresses (AF_IPX)</li>
 * <li>{@link IrdaSockAddr} - IrDA addresses (AF_IRDA) [Windows]</li>
 * </ul>
 * 
 * <h2>Memory Management</h2> This class manages native memory through the
 * {@link java.lang.foreign.MemorySegment} API. The lifetime of the native
 * memory is controlled by the provided {@link java.lang.foreign.Arena}.
 * 
 * <h2>Platform Detection</h2> The class automatically detects the platform's
 * socket address format (BSD vs POSIX) and adjusts its behavior accordingly.
 * This detection affects how the family field is read and whether the length
 * field is present.
 * 
 * @see java.lang.foreign.MemorySegment
 * @see java.lang.foreign.Arena
 * @see org.jnetpcap.constant.SockAddrFamily
 */
public class SockAddr {

	/**
	 * Represents an IPv6 socket address (sockaddr_in6 structure). Provides access
	 * to IPv6-specific address fields including flow information and scope IDs.
	 * 
	 * <h2>Native Structure</h2>
	 * 
	 * <pre>{@code
	 * struct sockaddr_in6 {
	 *     uint8_t         sin6_len;    // Length of structure (BSD only)
	 *     sa_family_t     sin6_family; // AF_INET6
	 *     in_port_t       sin6_port;   // Transport layer port
	 *     uint32_t        sin6_flowinfo;// IPv6 flow information
	 *     struct in6_addr sin6_addr;   // IPv6 address
	 *     uint32_t        sin6_scope_id;// Set of interfaces for scope
	 * };
	 * }</pre>
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

			this.port = SaLayout.AF_INET6_PORT.getUnsignedShort(saSegment).intValue();
			this.flowInfo = SaLayout.AF_INET6_FLOWINFO.getNumber(saSegment).intValue();
			this.scopeId = SaLayout.AF_INET6_SCOPEID.getNumber(saSegment).intValue();
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
			return "AF_INET6" + "["
					+ PcapUtils.toAddressString(address())
					+ (port == 0 ? "" : ", port=" + port)
					+ (flowInfo == 0 ? "" : ", flowInfo=" + flowInfo)
					+ (scopeId == 0 ? "" : ", scopeId=" + scopeId)
					+ "]";
		}

	}

	/**
	 * Represents an IPv4 socket address (sockaddr_in structure).
	 * 
	 * <h2>Native Structure</h2>
	 * 
	 * <pre>{@code
	 * struct sockaddr_in {
	 *     uint8_t         sin_len;    // Length of structure (BSD only)
	 *     sa_family_t     sin_family; // AF_INET
	 *     in_port_t       sin_port;   // Transport layer port
	 *     struct in_addr  sin_addr;   // IPv4 address
	 *     char            sin_zero[8];// Padding to sockaddr size
	 * };
	 * }</pre>
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

			this.port = SaLayout.AF_INET_PORT.getUnsignedShort(saSegment).intValue();
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
			return "AF_INET" + "["
					+ PcapUtils.toAddressString(address())
					+ (port == 0 ? "" : "port=" + port)
					+ "]";
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

			this.netnum = SaLayout.AF_IPX_NETNUM.getUnsignedShort(saSegment).intValue();
			this.nodenum = saSegment.asSlice(4, 6).toArray(JAVA_BYTE);
			this.socket = SaLayout.AF_IPX_SOCKET.getUnsignedShort(saSegment).intValue();
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
		 * IPX node number (MAC address).
		 *
		 * @return address field value
		 */
		public byte[] nodeNum() {
			return nodenum;
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
					+ PcapUtils.toAddressString(nodeNum())
					+ (netnum == 0 ? "" : ", netnum=" + netnum)
					+ (socket == 0 ? "" : ", socket=" + socket)
					+ "]";
		}
	}

	/**
	 * The structure of <code>sockaddr_irda</code>, used with AF_IRDA sockets on
	 * windows (winsock2.h) to access link-layer information.
	 */
	public static final class IrdaSockAddr extends SockAddr {
		private static final int SOCK_ADDR_IRDA_LEN = 31;

		private final byte[] irdaDeviceID;
		private final String irdaServiceName;

		IrdaSockAddr(MemorySegment addr, Arena arena) {
			super(addr.reinterpret(SOCK_ADDR_IRDA_LEN, arena, EMPTY_CLEANUP), SockAddrFamily.IRDA, OptionalInt.of(
					SOCK_ADDR_IRDA_LEN));

			this.irdaDeviceID = saSegment.asSlice(2, 4).toArray(JAVA_BYTE);
			this.irdaServiceName = saSegment.getString(6, java.nio.charset.StandardCharsets.UTF_8);
		}

		/**
		 * A 4-byte device identifier for the IrDA device.
		 *
		 * @return device id
		 */
		public byte[] deviceId() {
			return irdaDeviceID;
		}

		/**
		 * String specifying the service name.
		 *
		 * @return service name
		 */
		public String serviceName() {
			return irdaServiceName;
		}

		/**
		 * String representation of the structure field values.
		 *
		 * @return the string
		 * @see java.lang.Object#toString()
		 */
		@Override
		public String toString() {
			return "AF_IRDA ["
					+ "id=" + PcapUtils.toAddressString(irdaDeviceID)
					+ (irdaServiceName.isBlank() ? "" : ", \"%s\"".formatted(irdaServiceName))
					+ "]";
		}
	}

	/**
	 * The structure of <code>sockaddr_dl</code>, used with AF_LINK sockets on macOS
	 * to access link-layer information.
	 */
	public static final class LinkSockAddr extends SockAddr {

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
		private Optional<byte[]> address;

		/**
		 * Instantiates a new inet sock addr.
		 *
		 * @param addr        the addr
		 * @param arena       the arena
		 * @param totalLength the total length
		 */
		LinkSockAddr(MemorySegment addr, Arena arena, int totalLength) {
			super(addr.reinterpret(totalLength, arena, __ -> {}), SockAddrFamily.LINK, OptionalInt.of(totalLength));

			this.index = SaLayout.AF_LINK_INDEX.getUnsignedShort(saSegment).intValue();
			this.type = SaLayout.AF_LINK_TYPE.getUnsignedByte(saSegment).intValue();
			this.nlen = SaLayout.AF_LINK_NLEN.getUnsignedByte(saSegment).intValue();
			this.alen = SaLayout.AF_LINK_ALEN.getUnsignedByte(saSegment).intValue();
			this.slen = SaLayout.AF_LINK_SLEN.getUnsignedByte(saSegment).intValue();
			this.data = saSegment.asSlice(4, 4).toArray(JAVA_BYTE);

			int off = 8; // Keep a running offset

			this.name = (nlen == 0)
					? Optional.empty()
					: Optional.of(new String(saSegment.asSlice(off, nlen).toArray(JAVA_BYTE)));
			off += nlen;

			this.address = (alen == 0)
					? Optional.empty()
					: Optional.of(saSegment.asSlice(off, alen).toArray(JAVA_BYTE));
			off += alen;

			this.selector = readNumberByLength(saSegment.asSlice(off, slen), slen);
		}

		/**
		 * Length of the link-layer selector (usually 0).
		 *
		 * @return address field value
		 */
		public Optional<byte[]> address() {
			return address;
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
		 * Link-layer address type (e.g., IFT_ETHER for Ethernet).
		 *
		 * @return type field value
		 */
		public int addressType() {
			return type;
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
		 * interface name.
		 *
		 * @return name field value
		 */
		public Optional<String> name() {
			return name;
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
		 * Link-layer selector.
		 *
		 * @return selector field value
		 */
		public OptionalInt selector() {
			return selector;
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
		 * String representation of the structure field values.
		 *
		 * @return the string
		 * @see java.lang.Object#toString()
		 */
		@Override
		public String toString() {
			return "AF_LINK ["
					+ "#" + index
					+ (name.isEmpty() ? "" : ", \"%s\"".formatted(name.get()))
					+ (address.isEmpty() ? "" : ", %s".formatted(PcapUtils.toAddressString(address.get())))
					+ (selector.isEmpty() ? "" : ", sel=0x%x".formatted(selector.getAsInt()))
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
		private final int haLen;

		/**
		 * Instantiates a new inet sock addr.
		 *
		 * @param addr  the addr
		 * @param arena the arena
		 */
		PacketSockAddr(MemorySegment addr, Arena arena) {
			super(SaLayout.AF_PACKET.reinterpret(addr, arena), SockAddrFamily.PACKET, OptionalInt.of((int) SaLayout
					.sizeOf()));

			this.protocol = SaLayout.AF_PACKET_PROTOCOL.getUnsignedShort(saSegment).intValue();
			this.ifIndex = SaLayout.AF_PACKET_IFINDEX.getNumber(saSegment).intValue();
			this.haType = SaLayout.AF_PACKET_HATYPE.getUnsignedShort(saSegment).intValue();
			this.pktType = SaLayout.AF_PACKET_PKTTYPE.getUnsignedByte(saSegment).intValue();
			this.haLen = SaLayout.AF_PACKET_HALEN.getUnsignedByte(saSegment).intValue();
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
					+ "#%d".formatted(ifIndex)
					+ ", " + PcapUtils.toAddressString(address())
					+ (protocol == 0 ? "" : ", protocol=" + protocol)
					+ (pktType == 0 ? "" : ", pktType=" + pktType)
					+ ", haType=%d<%s>".formatted(haType, ArpHdr.toLabel(haType).orElse(""))
					+ "]";
		}
	}

	/** The Constant MIM_SOCKADDR_STRUCT_LEN. */
	@SuppressWarnings("unused")
	private final static int MIM_SOCKADDR_STRUCT_LEN = 16;

	/**
	 * Creates a new socket address instance based on the address family in the
	 * native structure. This factory method reads the family field from the native
	 * memory and instantiates the appropriate subclass based on the address family
	 * value.
	 *
	 * @param <T>   The specific SockAddr subclass type to be returned
	 * @param value A MemorySegment containing the native sockaddr structure
	 * @param arena The arena controlling the lifetime of the native memory
	 * @return A new SockAddr instance of the appropriate subclass, or null if the
	 *         input is null
	 * @throws IllegalArgumentException if the address family is invalid or
	 *                                  unsupported
	 */
	@SuppressWarnings("unchecked")
	static <T extends SockAddr> T newInstance(Object value, Arena arena) {

		MemorySegment addr = (MemorySegment) value;
		if (ForeignUtils.isNullAddress(addr))
			return null;

		MemorySegment first2BytesSeg = addr.reinterpret(SaLayout.sizeOf()); // Enough to read family field

		int af = readFamilyField(first2BytesSeg);
		int structSize = (int) SaLayout.sizeOf();
		SockAddrFamily familyConst = SockAddrFamily.lookup(af).orElse(null);

		return (T) switch (familyConst) {

		case INET -> new InetSockAddr(addr, arena);
		case INET6 -> new Inet6SockAddr(addr, arena);
		case IPX -> new IpxSockAddr(addr, arena);
		case PACKET -> new PacketSockAddr(addr, arena);
		case LINK -> new LinkSockAddr(addr, arena, structSize); // BSD platforms only
		case IRDA -> new IrdaSockAddr(addr, arena);

		default -> new SockAddr(addr.reinterpret(structSize, arena, __ -> {}), af, OptionalInt.of(structSize));
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
	@SuppressWarnings("unused")
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
	 * Returns the protocol-specific address data from the sa_data field. The format
	 * and meaning of this data depends on the address family.
	 *
	 * @return A byte array containing the raw address data
	 */
	public byte[] data() {
		return saData;
	}

	/**
	 * Returns the address family identifier as defined in the sa_family field.
	 * Common values include AF_INET (IPv4), AF_INET6 (IPv6), AF_PACKET (Linux raw),
	 * AF_LINK (BSD raw), etc.
	 *
	 * @return The address family value as an integer
	 */
	public int family() {
		return saFamily;
	}

	/**
	 * Returns the address family as an enumerated constant.
	 *
	 * @return An Optional containing the SockAddrFamily constant, or empty if the
	 *         family value doesn't match any known constant
	 * @see org.jnetpcap.constant.SockAddrFamily
	 */
	public Optional<SockAddrFamily> familyConstant() {
		return SockAddrFamily.lookup(saFamily);
	}

	/**
	 * Checks if this socket address belongs to the specified address family.
	 *
	 * @param family The address family to check against
	 * @return true if this address belongs to the specified family
	 */
	public boolean isFamily(SockAddrFamily family) {
		return family.isMatch(this.saFamily);
	}

	/**
	 * Creates a string representation of the socket address. The format varies
	 * depending on the address family and includes relevant address information in
	 * a human-readable format.
	 *
	 * @return A string representation of the address
	 */
	@Override
	public String toString() {
		return "AF_%s[".formatted(familyConstant().orElse(null))
				+ PcapUtils.toAddressString(saData)
				+ "fam=%s(%d)".formatted(SockAddrFamily.lookup(saFamily).orElse(null), saFamily)
				+ "]";
	}

	/**
	 * Returns the total length of the socket address structure. This method is
	 * primarily relevant for BSD-style socket addresses which include an explicit
	 * length field.
	 *
	 * @return An OptionalInt containing the structure length on BSD systems, or
	 *         empty on POSIX systems
	 */
	public OptionalInt totalLength() {
		return saLen;
	}
}