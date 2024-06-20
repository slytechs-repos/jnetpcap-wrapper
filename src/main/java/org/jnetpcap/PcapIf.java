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

import static org.jnetpcap.internal.ForeignUtils.*;
import static org.jnetpcap.internal.FunctionThrowable.*;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.jnetpcap.SockAddr.Inet6SockAddr;
import org.jnetpcap.SockAddr.InetSockAddr;
import org.jnetpcap.constant.PcapIfFlag;
import org.jnetpcap.constant.SockAddrFamily;
import org.jnetpcap.internal.ForeignUtils;
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
	 *
	 * @param <T> the generic socket address subclass type
	 */
	public static class PcapAddr<T extends SockAddr> {

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
		 * List all addresses by iterating over the linked list.
		 *
		 * @param next  the first element of a linked list of addresses
		 * @param arena the memory scope
		 * @return a list of all PCAP addresses found in the supplied linked list
		 */
		private static List<PcapAddr<? extends SockAddr>> listAll(MemorySegment next, Arena arena) {
			List<PcapAddr<?>> list = new ArrayList<>();

			while (!ForeignUtils.isNullAddress(next)) {
				MemorySegment mseg = next.reinterpret(PCAP_ADDR_LAYOUT.byteSize());
				list.add(new PcapAddr<SockAddr>(mseg, arena));

				next = (MemorySegment) nextHandle.get(mseg, 0L);
			}
			return list;
		}

		/** The addr. */
		private final T addr;

		/** The netmask. */
		private final Optional<T> netmask;

		/** The broadaddr. */
		private final Optional<T> broadaddr;

		/** The dstaddr. */
		private final Optional<T> dstaddr;

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
		 * The broadcast address corresponding to {@link #socketAddress}, if the
		 * interface supports broadcasts.
		 *
		 * @return optional broadcast address interface
		 */
		public Optional<T> broadcast() {
			return broadaddr;
		}

		/**
		 * The destination address corresponding to {@link #socketAddress} if the
		 * interface is a point-to-point interface.
		 *
		 * @return the optional destination address of a point-to-point interface
		 */
		public Optional<T> destination() {
			return dstaddr;
		}

		/**
		 * The netmask corresponding to {@link #socketAddress} if the interface supports
		 * netmasks.
		 *
		 * @return interface's optional netmask address
		 */
		public Optional<T> netmask() {
			return netmask;
		}

		/**
		 * A family specific socket address for this interface.
		 *
		 * @return network family specific interface address
		 */
		public T socketAddress() {
			return addr;
		}

		/**
		 * String representation of the structure field values.
		 *
		 * @return the string
		 * @see java.lang.Object#toString()
		 */
		@Override
		public String toString() {
			return "PcapAddr ["
					+ "addr=" + addr
					+ netmask.map(SockAddr::toString).map(", netmask=%s"::formatted).orElse("")
					+ broadaddr.map(SockAddr::toString).map(", netmask=%s"::formatted).orElse("")
					+ dstaddr.map(SockAddr::toString).map(", netmask=%s"::formatted).orElse("")
//					+ (netmask.isEmpty() ? "" : ", netmask=" + netmask.get())
//					+ (broadaddr.isEmpty() ? "" : ", broadaddr=" + broadaddr.get())
//					+ (dstaddr.isEmpty() ? "" : ", dstaddr=" + dstaddr.get())
					+ "]";
		}
	}

	/**
	 * System property if set to true, pcap uses BSD style sockaddr structure which
	 * has the addr_len field. Otherwise the default heuristic are used to determine
	 * the sock address structure format.
	 */
	public static final String SYSTEM_PROPERTY_PCAPIF_SOCKADDR_BSD_STYLE = "org.jnetpcap.sockaddr.bsd";

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

			next = (MemorySegment) nextHandle.get(mseg, 0L);
		}

		return list;
	}

	/** The name. */
	private final String name;

	/** The description. */
	private final Optional<String> description;

	/** The flags. */
	private final int flags;

	/** The addresses. */
	private final List<PcapAddr<?>> addresses;

	/** The hardware/Mac address. */
	private final Optional<byte[]> hardwareAddress;

	/**
	 * New instanceof PcapIf structure class.
	 *
	 * @param mseg  the memory segment containing off heap pcap_if structure
	 * @param arena the memory scope
	 */
	PcapIf(MemorySegment mseg, Arena arena) {
		MemorySegment addrs = (MemorySegment) addrsHandle.get(mseg, 0L);

		name = toJavaString(nameHandle.get(mseg, 0L));
		description = Optional.ofNullable(toJavaString(descHandle.get(mseg, 0L)));
		flags = (int) flagsHandle.get(mseg, 0L);

		addresses = PcapAddr.listAll(addrs, arena);
		hardwareAddress = Optional.ofNullable(selectJavaNetInterface());
	}

	private byte[] selectJavaNetInterface() {

		/* 1 - select by name */
		try {
			return NetworkInterface.getByName(name()).getHardwareAddress();
		} catch(Throwable e) {}

		/* 2 - select by IPv4/INET address */
		try {
			var ip4 = findAddressOfType(InetSockAddr.class)
					.map(PcapAddr::socketAddress)
					.map(InetSockAddr::address)
					.orElseThrow();

			String str = PcapUtils.toAddressString(ip4);

			return NetworkInterface.getByInetAddress(InetAddress.getByAddress(ip4)).getHardwareAddress();
		} catch(Throwable e) {}

		/* 3 - select by IPv6/INET6 address */
		try {
			var ip6 = findAddressOfType(Inet6SockAddr.class)
					.map(PcapAddr::socketAddress)
					.map(Inet6SockAddr::address)
					.orElseThrow();

			return NetworkInterface.getByInetAddress(InetAddress.getByAddress(ip6)).getHardwareAddress();
		} catch(Throwable e) {}

		return null;
	}

	/**
	 * Gets a list of all the addresses (PcapAddr) associated with this pcap
	 * interface.
	 *
	 * @return the list of addresses
	 */
	public List<PcapAddr<?>> addresses() {
		return addresses;
	}

	/**
	 * Search for a PCAP address of a specific socket address family type.
	 *
	 * @param family the socket address family type
	 * @return the optional PCAP address if found
	 */
	public Optional<PcapAddr<? extends SockAddr>> findAddressOfFamily(SockAddrFamily family) {

		var list = addresses();

		for (PcapAddr<?> a : list) {
			var af = a.addr.familyConstant().orElse(null);
			if (af == family)
				return Optional.of(a);
		}

		return Optional.empty();
	}

	/**
	 * Finds the first address in the list of PcapAddr addresses, which is of AF
	 * (Address Family) type represented but the supplied family subclass type.
	 *
	 * @param <T>             the generic AF subclass type
	 * @param faimlyClassType the actual AF subclass type
	 * @return an optional if address represented by the family subclass if found
	 */
	@SuppressWarnings({ "unchecked" })
	public <T extends SockAddr> Optional<PcapAddr<T>> findAddressOfType(Class<T> faimlyClassType) {

		var list = addresses();

		return list.stream()
				.filter(a -> faimlyClassType.isAssignableFrom(a.addr.getClass()))
				.map(a -> (PcapAddr<T>) a)
				.findFirst();
	}

	/**
	 * Optional textual description of the interface.
	 *
	 * @return the interface description if available
	 */
	public Optional<String> description() {
		return description;
	}

	/**
	 * Interface flags (e.g., PCAP_IF_LOOPBACK for loopback interfaces).
	 *
	 * @return the interface bitmask of flags
	 */
	public int flags() {
		return flags;
	}

	/**
	 * Interface flags (e.g., PCAP_IF_LOOPBACK for loopback interfaces), as an enum
	 * set.
	 *
	 * @return the set containing enum flag constants for each flag bit
	 */
	public Set<PcapIfFlag> flagsAsEnumSet() {
		return PcapIfFlag.toEnumSet(flags);
	}

	/**
	 * Returns the hardware address (usually MAC) of the interface if it has one and
	 * if it can be accessed given the current privileges.
	 *
	 * @return an optional byte array containing the address
	 */
	public Optional<byte[]> hardwareAddress() {
		return hardwareAddress;
	}

	/**
	 * Name of the interface (e.g., "eth0") .
	 *
	 * @return the string
	 */
	public String name() {
		return name;
	}

	/**
	 * String representation of the structure field values.
	 *
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {

		var set = flagsAsEnumSet();
		String flagString = set.stream().map(PcapIfFlag::label).collect(Collectors.joining(","));

		if (flagString.isBlank())
			flagString = "0b%s/0x%X".formatted(Integer.toBinaryString(flags), flags);

		return "PcapIf ["
				+ "\"%s\"".formatted(name)
				+ ", flags=%s<%s>".formatted(flags, flagString)
				+ (description.isEmpty() ? "" : ", description=\"%s\"".formatted(description.get()))
				+ (addresses.isEmpty() ? "" : ", addresses=" + addresses)
				+ "]";
	}

}
