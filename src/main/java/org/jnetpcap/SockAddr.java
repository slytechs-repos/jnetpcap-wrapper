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
 * The low level sockaddr structure containing an address of different types,
 * depending on the protocol family value.
 */
public class SockAddr {

	/**
	 * The Class Inet6SockAddr.
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
			super(SaLayout.AF_INET6.reinterpret(addr, arena), SockAddrFamily.INET6, OptionalInt.empty());

			this.port = Short.toUnsignedInt((short) SaLayout.AF_INET6_PORT.get(saSegment));
			this.flowInfo = (int) SaLayout.AF_INET6_FLOWINFO.get(saSegment);
			this.scopeId = (int) SaLayout.AF_INET6_SCOPEID.get(saSegment);
			this.addr = saSegment.asSlice(8, 16).toArray(JAVA_BYTE);
		}

		/**
		 * Address.
		 *
		 * @return address field value
		 */
		public byte[] address() {
			return addr;
		}

		/**
		 * Flow info.
		 *
		 * @return the int
		 */
		public int flowInfo() {
			return flowInfo;
		}

		/**
		 * Port.
		 *
		 * @return port field value
		 */
		public int port() {
			return port;
		}

		/**
		 * Scope id.
		 *
		 * @return the int
		 */
		public int scopeId() {
			return scopeId;
		}

		/**
		 * To string.
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
	 * Socket address structure for AF_INET type.
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
			super(SaLayout.AF_INET.reinterpret(addr, arena), SockAddrFamily.INET, OptionalInt.empty());

			this.port = Short.toUnsignedInt((short) SaLayout.AF_INET_PORT.get(saSegment));
			this.addr = saSegment.asSlice(4, 4).toArray(JAVA_BYTE);
		}

		/**
		 * Address.
		 *
		 * @return address field value
		 */
		public byte[] address() {
			return addr;
		}

		/**
		 * Port.
		 *
		 * @return port field value
		 */
		public int port() {
			return port;
		}

		/**
		 * To string.
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
	 * Socket address structure for AF_INET type.
	 */
	public static final class IpxSockAddr extends SockAddr {

		/** The addr. */
		private final byte[] addr;

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
			super(SaLayout.AF_IPX.reinterpret(addr, arena), SockAddrFamily.IPX, OptionalInt.empty());

			this.netnum = Short.toUnsignedInt((short) SaLayout.AF_IPX_NETNUM.get(saSegment));
			this.addr = saSegment.asSlice(4, 6).toArray(JAVA_BYTE);
			this.socket = Short.toUnsignedInt((short) SaLayout.AF_IPX_SOCKET.get(saSegment));
		}

		/**
		 * Address.
		 *
		 * @return address field value
		 */
		public byte[] address() {
			return addr;
		}

		/**
		 * Port.
		 *
		 * @return port field value
		 */
		public int port() {
			return netnum;
		}

		/**
		 * Socket.
		 *
		 * @return the int
		 */
		public int socket() {
			return socket;
		}

		/**
		 * To string.
		 *
		 * @return the string
		 * @see java.lang.Object#toString()
		 */
		@Override
		public String toString() {
			return "AF_IPX" + "["
					+ "port=" + netnum
					+ ", addr=" + PcapUtils.toAddressString(address())
					+ ", socket=" + socket
					+ "]";
		}
	}

	/**
	 * The Class PacketSockAddr.
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
			super(SaLayout.AF_PACKET.reinterpret(addr, arena), SockAddrFamily.PACKET, OptionalInt.empty());

			this.protocol = Short.toUnsignedInt((short) SaLayout.AF_PACKET_PROTOCOL.get(saSegment));
			this.ifIndex = (int) SaLayout.AF_PACKET_IFINDEX.get(saSegment);
			this.haType = Short.toUnsignedInt((short) SaLayout.AF_PACKET_HATYPE.get(saSegment));
			this.pktType = (byte) SaLayout.AF_PACKET_PKTTYPE.get(saSegment);
			this.haLen = (byte) SaLayout.AF_PACKET_HALEN.get(saSegment);
			this.addr = saSegment.asSlice(12, this.haLen).toArray(JAVA_BYTE);
		}

		/**
		 * Address.
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
		 * @return the int
		 */
		public int hardwareType() {
			return haType;
		}

		/**
		 * Interface index.
		 *
		 * @return the int
		 */
		public int interfaceIndex() {
			return ifIndex;
		}

		/**
		 * Packet type.
		 *
		 * @return the int
		 */
		public int packetType() {
			return pktType;
		}

		/**
		 * Port.
		 *
		 * @return port field value
		 */
		public int protocol() {
			return protocol;
		}

		/**
		 * To string.
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
					+ ", addr=" + PcapUtils.toAddressString(address()) + "]";
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
	 * @param value the value
	 * @param arena the scope
	 * @return the sock addr
	 */
	static SockAddr newInstance(Object value, Arena arena) {
		MemorySegment addr = (MemorySegment) value;
		if (ForeignUtils.isNullAddress(addr))
			return null;

		MemorySegment first2BytesSeg = addr.reinterpret(2); // Enough to read family field
		int af = readFamilyField(first2BytesSeg);
		OptionalInt totalLength = readTotalLengthField(first2BytesSeg);
		SockAddrFamily familyConst = SockAddrFamily.lookup(af)
				.orElse(null);

		return switch (familyConst) {

		case INET -> new InetSockAddr(addr, arena);
		case INET6 -> new Inet6SockAddr(addr, arena);
		case IPX -> new IpxSockAddr(addr, arena);
		case PACKET -> new PacketSockAddr(addr, arena);

		default -> {
			if (totalLength.isPresent()) {
				yield new SockAddr(addr.reinterpret(totalLength.getAsInt(), arena, __ -> {}), af, totalLength);
			} else {
				yield new SockAddr(addr.reinterpret(MIM_SOCKADDR_STRUCT_LEN, arena, __ -> {}), af, totalLength);
			}
		}
		};
	}

	/**
	 * Read address length field.
	 *
	 * @param mseg   the mseg
	 * @param family the family
	 * @return the optional int
	 */
	private static OptionalInt readTotalLengthField(MemorySegment mseg) {

		if (!NativeABI.isBsdAbi())
			return OptionalInt.empty();

		int addrLen = Byte.toUnsignedInt((byte) SaLayout.ADDR_LEN.get(mseg));

		return OptionalInt.of(addrLen);
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

	/** The family. */
	private final int family;

	/** Minimum 14 bytes of protocol address. */
	private final byte[] data;

	/** The addr len. */
	private final OptionalInt totalLength;

	/** The sa segment. */
	protected final MemorySegment saSegment;

	/**
	 * Instantiates a new sock addr.
	 *
	 * @param addr  the addr
	 * @param arena the scope
	 */
	private SockAddr(MemorySegment mseg, int family, OptionalInt totalLength) {
		this.saSegment = mseg;
		this.family = family;
		this.totalLength = totalLength;

		MemorySegment dataSeg = mseg.asSlice(2);
		this.data = dataSeg.toArray(ValueLayout.JAVA_BYTE);
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
	 * Socket data structure.
	 *
	 * @return the byte[]
	 */
	public byte[] data() {
		return data;
	}

	/**
	 * Address family value.
	 *
	 * @return 8 or 16 bit address family value
	 */
	public int family() {
		return family;
	}

	/**
	 * Gets the family as a constant.
	 *
	 * @return the socket address family constant
	 * @throws IllegalArgumentException thrown if the constant for the family value
	 *                                  is not found.
	 */
	public Optional<SockAddrFamily> familyConstant() {
		return SockAddrFamily.lookup(family);
	}

	/**
	 * To string.
	 *
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "AF_%s".formatted(familyConstant())
				+ "[fam=" + SockAddrFamily.lookup(family)
				+ " addr=" + PcapUtils.toAddressString(data) + "]";
	}

	/**
	 * The total length of the socket address structure in bytes. The value is only
	 * returned on certain platforms the length can be either calculated or is
	 * provided (ie. MacOS/Bsd).
	 *
	 * @return the length of the address structure if available on this particular
	 *         platform
	 */
	public OptionalInt totalLength() {
		return totalLength;
	}
}