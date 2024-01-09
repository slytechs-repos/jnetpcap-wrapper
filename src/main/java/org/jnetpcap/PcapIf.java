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
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;

import org.jnetpcap.constant.SockAddrFamily;
import org.jnetpcap.internal.ForeignUtils;
import org.jnetpcap.internal.NativeABI;
import org.jnetpcap.util.PcapUtils;

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;
import static java.lang.foreign.ValueLayout.*;

/**
 * Native Type pcap_if_t has the following members.
 * 
 * <dl>
 * <dt>next</dt>
 * <dd>if not NULL, a pointer to the next element in the list; NULL for the last
 * element of the list</dd>
 * <dt>name</dt>
 * <dd>a pointer to a string giving a name for the device to pass to
 * pcap_open_live()</dd>
 * <dt>description</dt>
 * <dd>if not NULL, a pointer to a string giving a human-readable description of
 * the device</dd>
 * <dt>addresses</dt>
 * <dd>a pointer to the first element of a list of network addresses for the
 * device, or NULL if the device has no addresses</dd>
 * </dl>
 * 
 * <dl>
 * <dt>flags</dt>
 * <dd>device flags:
 * <dt>PCAP_IF_LOOPBACK</dt>
 * <dd>set if the device is a loopback interface</dd>
 * <dt>PCAP_IF_UP</dt>
 * <dd>set if the device is up</dd>
 * <dt>PCAP_IF_RUNNING</dt>
 * <dd>set if the device is running</dd>
 * <dt>PCAP_IF_WIRELESS</dt>
 * <dd>set if the device is a wireless interface; this includes IrDA as well as
 * radio-based networks such as IEEE 802.15.4 and IEEE 802.11, so it doesn't
 * just mean Wi-Fi</dd>
 * </dl>
 * 
 * <dl>
 * <dt>PCAP_IF_CONNECTION_STATUS</dt>
 * <dd>a bitmask for an indication of whether the adapter is connected or not;
 * for wireless interfaces, "connected" means "associated with a network"
 * <dt>PCAP_IF_CONNECTION_STATUS_UNKNOWN</dt>
 * <dd>it's unknown whether the adapter is connected or not</dd>
 * <dt>PCAP_IF_CONNECTION_STATUS_CONNECTED</dt>
 * <dd>the adapter is connected</dd>
 * <dt>PCAP_IF_CONNECTION_STATUS_DISCONNECTED</dt>
 * <dd>the adapter is disconnected</dd>
 * <dt>PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE</dt>
 * <dd>the notion of "connected" and "disconnected" don't apply to this
 * interface; for example, it doesn't apply to a loopback device</dd>
 * </dl>
 * 
 * <p>
 * Each element of the list of addresses is of type pcap_addr_t, and has the
 * following members:
 * </p>
 * 
 * <dl>
 * <dt>next</dt>
 * <dd>if not NULL, a pointer to the next element in the list; NULL for the last
 * element of the list</dd>
 * <dt>addr</dt>
 * <dd>a pointer to a struct sockaddr containing an address</dd>
 * <dt>netmask</dt>
 * <dd>if not NULL, a pointer to a struct sockaddr that contains the netmask
 * corresponding to the address pointed to by addr</dd>
 * <dt>broadaddr</dt>
 * <dd>if not NULL, a pointer to a struct sockaddr that contains the broadcast
 * address corresponding to the address pointed to by addr; may be null if the
 * device doesn't support broadcasts</dd>
 * <dt>dstaddr</dt>
 * <dd>if not NULL, a pointer to a struct sockaddr that contains the destination
 * address corresponding to the address pointed to by addr; may be null if the
 * device isn't a point-to-point interface</dd>
 * </dl>
 * 
 * <p>
 * Note that the addresses in the list of addresses might be IPv4 addresses,
 * IPv6 addresses, or some other type of addresses, so you must check the
 * sa_family member of the struct sockaddr before interpreting the contents of
 * the address; do not assume that the addresses are all IPv4 addresses, or even
 * all IPv4 or IPv6 addresses. IPv4 addresses have the value AF_INET, IPv6
 * addresses have the value AF_INET6 (which older operating systems that don't
 * support IPv6 might not define), and other addresses have other values.
 * Whether other addresses are returned, and what types they might have is
 * platform-dependent. For IPv4 addresses, the struct sockaddr pointer can be
 * interpreted as if it pointed to a struct sockaddr_in; for IPv6 addresses, it
 * can be interpreted as if it pointed to a struct sockaddr_in6.
 * </p>
 * 
 * @author Sly Technologies
 * @author repos@slytechs.com since libpcap 0.7
 */
public class PcapIf {

	/**
	 * The struct pcap_addr structure containing network interfaces/devices
	 * addresses.
	 */
	public static class PcapAddr {

		/** The Constant LAYOUT. */
		private static final MemoryLayout PCAP_ADDR_LAYOUT = structLayout(

				ADDRESS.withName("next"),
				ADDRESS.withName("addr"),
				ADDRESS.withName("netmask"),
				ADDRESS.withName("broadaddr"),
				ADDRESS.withName("dstaddr")

		);

		/** The Constant nextHandle. */
		private static final VarHandle nextHandle = PCAP_ADDR_LAYOUT.varHandle(groupElement("next"));

		/** The Constant addrHandle. */
		private static final VarHandle addrHandle = PCAP_ADDR_LAYOUT.varHandle(groupElement("addr"));

		/** The Constant netmaskHandle. */
		private static final VarHandle netmaskHandle = PCAP_ADDR_LAYOUT.varHandle(groupElement("netmask"));

		/** The Constant broadaddrHandle. */
		private static final VarHandle broadaddrHandle = PCAP_ADDR_LAYOUT.varHandle(groupElement("broadaddr"));

		/** The Constant dstaddrHandle. */
		private static final VarHandle dstaddrHandle = PCAP_ADDR_LAYOUT.varHandle(groupElement("dstaddr"));

		/**
		 * List all.
		 *
		 * @param next  the next
		 * @param scope the scope
		 * @return the list
		 */
		private static List<PcapAddr> listAll(MemorySegment next, Arena scope) {
			List<PcapAddr> list = new ArrayList<>();

			while (!ForeignUtils.isNullAddress(next)) {
				MemorySegment mseg = next.reinterpret(PCAP_ADDR_LAYOUT.byteSize());
				list.add(new PcapAddr(mseg, scope));

				next = (MemorySegment) nextHandle.get(mseg);
			}
			return list;
		}

		/** The addr. */
		private final SockAddr addr;

		/** The netmask. */
		private final Optional<SockAddr> netmask;

		/** The broadaddr. */
		private final Optional<SockAddr> broadaddr;

		/** The dstaddr. */
		private final Optional<SockAddr> dstaddr;

		/**
		 * Instantiates a new pcap addr.
		 *
		 * @param mseg  the mseg
		 * @param scope the scope
		 */
		PcapAddr(MemorySegment mseg, Arena scope) {
			addr = SockAddr.newInstance(ForeignUtils.readAddress(addrHandle, mseg), scope);
			netmask = Optional.ofNullable(SockAddr.newInstance(ForeignUtils.readAddress(netmaskHandle, mseg), scope));
			broadaddr = Optional.ofNullable(SockAddr.newInstance(ForeignUtils.readAddress(broadaddrHandle, mseg),
					scope));
			dstaddr = Optional.ofNullable(SockAddr.newInstance(ForeignUtils.readAddress(dstaddrHandle, mseg), scope));
		}

		/**
		 * To string.
		 *
		 * @return the string
		 * @see java.lang.Object#toString()
		 */
		@Override
		public String toString() {
			return "PcapAddr [" + "addr=" + addr + ", netmask=" + netmask + ", broadaddr=" + broadaddr + ", dstaddr="
					+ dstaddr + "]";
		}

		/**
		 * A familty specific socket address for this interface.
		 *
		 * @return network family specific interface address
		 */
		public SockAddr socketAddress() {
			return addr;
		}

		/**
		 * The netmask corresponding to {@link #socketAddress}.
		 *
		 * @return interface's optional netmask address
		 */
		public Optional<SockAddr> netmask() {
			return netmask;
		}

		/**
		 * The broadcast address corresponding to {@link #socketAddress}, if the
		 * interface supports broadcasts.
		 *
		 * @return optional broadcast address interface
		 */
		public Optional<SockAddr> broadcast() {
			return broadaddr;
		}

		/**
		 * The destination address corresponding to {@link #socketAddress} if the
		 * interface is a point-to-point interface.
		 *
		 * @return the optional destination address of a point-to-point interface
		 */
		public Optional<SockAddr> destination() {
			return dstaddr;
		}
	}

	/**
	 * The low level sockaddr structure containing an address of different types,
	 * depending on the protocol family value.
	 */
	public static class SockAddr {

		/**
		 * Checks platform type to see how socket types are defined on this platform.
		 *
		 * @return true if platform socket structure definition has addr_len field
		 */
		private static boolean hasAddressLength() {
			return (NativeABI.current() == NativeABI.MACOS64);
		}

		/** Maximum sockaddr_t structure address data length. */
		public final static int MAX_SOCKADDR_ADDRESS_LEN = 16;

		/** The Constant LAYOUT. */
		private static final MemoryLayout SOCK_ADDR_LAYOUT = structLayout(

				unionLayout(

						JAVA_SHORT.withName("family16"),
						structLayout(

								JAVA_BYTE.withName("addr_len"),
								JAVA_BYTE.withName("family8")

						).withName("s1")

				).withName("u1"),
				JAVA_SHORT.withName("port"),
				sequenceLayout(MAX_SOCKADDR_ADDRESS_LEN,

						JAVA_BYTE

				).withName("addr")

		);

		/** The Constant familyHandle. */
		private static final VarHandle family16Handle = SOCK_ADDR_LAYOUT.varHandle(path("u1.family16"));
		private static final VarHandle family8Handle = SOCK_ADDR_LAYOUT.varHandle(path("u1.s1.family8"));
		private static final VarHandle addrLenHandle = SOCK_ADDR_LAYOUT.varHandle(path("u1.s1.addr_len"));

		/** The Constant portHandle. */
		private static final VarHandle portHandle = SOCK_ADDR_LAYOUT.varHandle(path("port"));

		/** The Constant addrHandle. */
		private static final VarHandle addrHandle = SOCK_ADDR_LAYOUT.varHandle(groupElement("addr"), sequenceElement());

		/**
		 * New instance.
		 *
		 * @param value the value
		 * @param scope the scope
		 * @return the sock addr
		 */
		static SockAddr newInstance(Object value, Arena scope) {
			MemorySegment addr = (MemorySegment) value;
			if (ForeignUtils.isNullAddress(addr))
				return null;

			return new SockAddr(addr, scope);
		}

		private static OptionalInt readAddressLengthField(MemorySegment mseg, int family) {

			if (!hasAddressLength()) {
				return switch (family) {

				case 2 -> OptionalInt.of(4);
				case 10 -> OptionalInt.of(16);
				default -> OptionalInt.empty();

				};
			}

			int addrLen = Byte.toUnsignedInt((byte) addrLenHandle.get(mseg));

			return OptionalInt.of(addrLen);
		}

		private static int readFamilyField(MemorySegment mseg) {

			if (hasAddressLength())
				return Byte.toUnsignedInt((byte) family8Handle.get(mseg));
			else
				return Short.toUnsignedInt((short) family16Handle.get(mseg));
		}

		private static int readPortField(MemorySegment mseg) {
			return Short.toUnsignedInt((short) portHandle.get(mseg));

		}

		/** The family. */
		private final int family;

		/** The port. */
		private final int port;

		/** The addr. */
		private final byte[] addr;

		/** The addr len. */
		private final OptionalInt addrLen;

		/**
		 * Instantiates a new sock addr.
		 *
		 * @param addr  the addr
		 * @param arena the scope
		 */
		SockAddr(MemorySegment addr, Arena arena) {
			MemorySegment mseg = addr.reinterpret(SOCK_ADDR_LAYOUT.byteSize(), arena, __ -> {});

			this.family = readFamilyField(mseg);
			this.addrLen = readAddressLengthField(mseg, family);
			this.port = readPortField(mseg);

			this.addr = new byte[addrLen.orElse(MAX_SOCKADDR_ADDRESS_LEN)];

			for (int i = 0; i < this.addr.length; i++)
				this.addr[i] = (byte) addrHandle.get(mseg, i);
		}

		/**
		 * Socket address structure bytes.
		 *
		 * @return the byte[]
		 */
		public byte[] addressBytes() {
			return addr;
		}

		/**
		 * Family.
		 *
		 * @return the int
		 */
		public int family() {
			return family;
		}

		/**
		 * The length of the address structure in bytes. The value is only returned on
		 * certain platforms the length can be either calculated or is provided (ie.
		 * MacOS/Bsd).
		 *
		 * @return the length of the address structure if available on this particular
		 *         platform
		 */
		public OptionalInt addressLength() {
			return addrLen;
		}

		/**
		 * Port.
		 *
		 * @return the int
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
//			if (family != SockAddrFamily.INET.ordinal() && family != SockAddrFamily.INET6.ordinal())
//				return "family(" + SockAddrFamily.valueOf(family) + ")";

			return "SockAddr " + "[fam=" + SockAddrFamily.valueOf(family)
//					+ " port=" + port
					+ " addr=" + PcapUtils.toAddressString(addr) + "]";
		}
	}

	/** The Constant LAYOUT. */
	private static final MemoryLayout PCAP_IF_LAYOUT = structLayout(

			ADDRESS.withName("next"),
			ADDRESS.withName("name"),
			ADDRESS.withName("description"),
			ADDRESS.withName("addresses"),
			JAVA_INT.withName("flags")

	);

	/** The Constant nextHandle. */
	private static final VarHandle nextHandle = PCAP_IF_LAYOUT.varHandle(path("next"));

	/** The Constant nameHandle. */
	private static final VarHandle nameHandle = PCAP_IF_LAYOUT.varHandle(path("name"));

	/** The Constant descHandle. */
	private static final VarHandle descHandle = PCAP_IF_LAYOUT.varHandle(path("description"));

	/** The Constant addrsHandle. */
	private static final VarHandle addrsHandle = PCAP_IF_LAYOUT.varHandle(path("addresses"));

	/** The Constant flagsHandle. */
	private static final VarHandle flagsHandle = PCAP_IF_LAYOUT.varHandle(path("flags"));

	/** interface is loopback. */
	public final static int PCAP_IF_LOOPBACK = 0x00000001;

	/** interface is up. */
	public final static int PCAP_IF_UP = 0x00000002;

	/** interface is running. */
	public final static int PCAP_IF_RUNNING = 0x00000004;

	/**
	 * List all.
	 *
	 * @param next  the next
	 * @param arena the scope
	 * @return the list
	 */
	static List<PcapIf> listAll(MemorySegment next, Arena arena) {
		List<PcapIf> list = new ArrayList<>();

		while (!ForeignUtils.isNullAddress(next)) {
			MemorySegment mseg = next.reinterpret(PCAP_IF_LAYOUT.byteSize(), arena, __ -> {});
			list.add(new PcapIf(mseg, arena));

			next = (MemorySegment) nextHandle.get(mseg);
		}

		return list;
	}

	/** The name. */
	private final String name;

	/** The description. */
	private final String description;

	/** The flags. */
	private final int flags;

	/** The addresses. */
	private final List<PcapAddr> addresses;

	/**
	 * Instantiates a new pcap if.
	 *
	 * @param mseg  the mseg
	 * @param scope the scope
	 */
	PcapIf(MemorySegment mseg, Arena scope) {
		MemorySegment addrs = (MemorySegment) addrsHandle.get(mseg);

		name = toJavaString(nameHandle.get(mseg));
		description = toJavaString(descHandle.get(mseg));
		flags = (int) flagsHandle.get(mseg);

		addresses = PcapAddr.listAll(addrs, scope);
	}

	/**
	 * Addresses.
	 *
	 * @return the list
	 */
	public List<PcapAddr> addresses() {
		return addresses;
	}

	/**
	 * Retrieves an optional PCAP address of a specific socket address family type.
	 *
	 * @param family the socket address family type
	 * @return the optional PCAP address if found
	 */
	public Optional<PcapAddr> addressOfFamily(SockAddrFamily family) {

		var list = addresses();

		return list.stream()
				.filter(a -> a.addr.family == family.getAsInt())
				.findAny();
	}

	/**
	 * Description.
	 *
	 * @return the string
	 */
	public String description() {
		return description;
	}

	/**
	 * Flags.
	 *
	 * @return the int
	 */
	public int flags() {
		return flags;
	}

	/**
	 * Name.
	 *
	 * @return the string
	 */
	public String name() {
		return name;
	}

	/**
	 * To string.
	 *
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "PcapIf [" + "name=" + name + ", description=" + description + ", flags=" + flags + ", addresses="
				+ addresses + "]";
	}

}
