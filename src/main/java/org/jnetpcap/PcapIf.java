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

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;
import static java.lang.foreign.ValueLayout.*;

/**
 * A Java representation of the native {@code pcap_if_t} structure which
 * contains information about a network interface. This class provides access to
 * interface properties such as name, addresses, flags, and hardware
 * information.
 * 
 * <h2>Structure Members</h2> The native pcap_if_t structure contains the
 * following members:
 * <ul>
 * <li>{@code next} - Points to the next interface in the list, or NULL if this
 * is the last interface</li>
 * <li>{@code name} - A string containing the name of the interface (e.g.,
 * "eth0", "en0")</li>
 * <li>{@code description} - A human-readable string describing the interface,
 * may be NULL</li>
 * <li>{@code addresses} - A pointer to the first element in a linked list of
 * addresses for the interface</li>
 * <li>{@code flags} - Interface flags indicating various interface properties
 * and states</li>
 * </ul>
 * 
 * <h2>Interface Flags</h2> The {@code flags} field can include the following
 * values:
 * <ul>
 * <li>{@code PCAP_IF_LOOPBACK} - Set if the interface is a loopback
 * interface</li>
 * <li>{@code PCAP_IF_UP} - Set if the interface is up (active)</li>
 * <li>{@code PCAP_IF_RUNNING} - Set if the interface is running</li>
 * <li>{@code PCAP_IF_WIRELESS} - Set if the interface is wireless (includes
 * IrDA, IEEE 802.15.4, IEEE 802.11)</li>
 * </ul>
 * 
 * <h2>Connection Status</h2> The flags field also includes connection status
 * information through {@code PCAP_IF_CONNECTION_STATUS}:
 * <ul>
 * <li>{@code PCAP_IF_CONNECTION_STATUS_UNKNOWN} - Connection status is
 * unknown</li>
 * <li>{@code PCAP_IF_CONNECTION_STATUS_CONNECTED} - Interface is connected</li>
 * <li>{@code PCAP_IF_CONNECTION_STATUS_DISCONNECTED} - Interface is
 * disconnected</li>
 * <li>{@code PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE} - Connection status
 * doesn't apply (e.g., loopback)</li>
 * </ul>
 * 
 * <h2>Network Addresses</h2> The interface may have multiple network addresses,
 * accessible through the {@link #addresses()} method. Each address is
 * represented by a {@link PcapAddr} object which may contain:
 * <ul>
 * <li>Network address (IPv4, IPv6, or other)</li>
 * <li>Netmask (if applicable)</li>
 * <li>Broadcast address (if the interface supports broadcasts)</li>
 * <li>Destination address (for point-to-point interfaces)</li>
 * </ul>
 * 
 * <h2>Address Types</h2> The addresses can be of different types, determined by
 * the {@code sa_family} field:
 * <ul>
 * <li>{@code AF_INET} - IPv4 addresses (struct sockaddr_in)</li>
 * <li>{@code AF_INET6} - IPv6 addresses (struct sockaddr_in6)</li>
 * <li>Other address types may be present depending on the platform</li>
 * </ul>
 * 
 * <h2>Usage Example</h2>
 * 
 * <pre>{@code 
 * PcapIf iface = ...;
 * 
 * // Get interface name
 * String name = iface.name();
 * 
 * // Check if interface is up and running
 * Set<PcapIfFlag> flags = iface.flagsAsEnumSet();
 * boolean isUp = flags.contains(PcapIfFlag.UP);
 * 
 * // Get IPv4 address if available
 * Optional<PcapAddr<InetSockAddr>> ipv4Addr = iface.findAddressOfType(InetSockAddr.class);
 * }</pre>
 * 
 * @see PcapAddr For detailed information about network addresses
 * @see org.jnetpcap.constant.PcapIfFlag For interface flag constants
 * @since libpcap 0.7
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
	 * Creates a list of PcapIf instances by traversing a linked list of native
	 * pcap_if_t structures. This method is used internally by libpcap functions
	 * that return lists of interfaces, such as pcap_findalldevs().
	 *
	 * @param next  The memory segment pointing to the first pcap_if_t structure in
	 *              the linked list
	 * @param arena The memory arena that manages the lifetime of the native memory
	 * @return A list of PcapIf instances representing all network interfaces in the
	 *         linked list
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
	 * Creates a new PcapIf instance from a native pcap_if_t structure.
	 *
	 * @param mseg  The memory segment containing the native pcap_if_t structure
	 * @param arena The memory arena that manages the lifetime of the native memory
	 */
	PcapIf(MemorySegment mseg, Arena arena) {
		MemorySegment addrs = (MemorySegment) addrsHandle.get(mseg, 0L);

		name = toJavaString(nameHandle.get(mseg, 0L));
		description = Optional.ofNullable(toJavaString(descHandle.get(mseg, 0L)));
		flags = (int) flagsHandle.get(mseg, 0L);

		addresses = PcapAddr.listAll(addrs, arena);
		hardwareAddress = Optional.ofNullable(selectJavaNetInterface());
	}

	/**
	 * Attempts to find the corresponding Java NetworkInterface for this pcap
	 * interface. This private method is used by the constructor to initialize the
	 * hardware address. It tries multiple strategies:
	 * <ol>
	 * <li>Look up by interface name</li>
	 * <li>Look up by IPv4 address</li>
	 * <li>Look up by IPv6 address</li>
	 * </ol>
	 *
	 * @return The hardware address as a byte array, or null if not found/accessible
	 */
	private byte[] selectJavaNetInterface() {

		/* 1 - select by name */
		try {
			return NetworkInterface.getByName(name()).getHardwareAddress();
		} catch (Throwable e) {}

		/* 2 - select by IPv4/INET address */
		try {
			var ip4 = findAddressOfType(InetSockAddr.class)
					.map(PcapAddr::socketAddress)
					.map(InetSockAddr::address)
					.orElseThrow();

			return NetworkInterface.getByInetAddress(InetAddress.getByAddress(ip4)).getHardwareAddress();
		} catch (Throwable e) {}

		/* 3 - select by IPv6/INET6 address */
		try {
			var ip6 = findAddressOfType(Inet6SockAddr.class)
					.map(PcapAddr::socketAddress)
					.map(Inet6SockAddr::address)
					.orElseThrow();

			return NetworkInterface.getByInetAddress(InetAddress.getByAddress(ip6)).getHardwareAddress();
		} catch (Throwable e) {}

		return null;
	}

	/**
	 * Returns all network addresses associated with this interface. The returned
	 * list may contain IPv4, IPv6, and other types of addresses. Each PcapAddr
	 * object contains the network address and optional netmask, broadcast, and
	 * destination addresses.
	 *
	 * @return An unmodifiable list of all addresses associated with this interface
	 */
	public List<PcapAddr<?>> addresses() {
		return addresses;
	}

	/**
	 * Searches for a network address of a specific address family (e.g., AF_INET,
	 * AF_INET6).
	 *
	 * @param family The address family to search for, as defined in SockAddrFamily
	 * @return An Optional containing the first matching address, or empty if no
	 *         address of the specified family exists on this interface
	 * @see SockAddrFamily
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
	 * Searches for the first network address of a specific type. This method allows
	 * finding addresses of a particular class, such as IPv4 (InetSockAddr) or IPv6
	 * (Inet6SockAddr) addresses.
	 *
	 * @param <T>             The type of socket address to find
	 * @param familyClassType The Class object representing the desired address type
	 * @return An Optional containing the first matching address, or empty if no
	 *         address of the specified type exists on this interface
	 */
	@SuppressWarnings({ "unchecked"
	})
	public <T extends SockAddr> Optional<PcapAddr<T>> findAddressOfType(Class<T> familyClassType) {

		var list = addresses();

		return list.stream()
				.filter(a -> familyClassType.isAssignableFrom(a.addr.getClass()))
				.map(a -> (PcapAddr<T>) a)
				.findFirst();
	}

	/**
	 * Returns the human-readable description of this interface. The description is
	 * typically more detailed than the interface name and may include information
	 * about the interface type, manufacturer, or other details.
	 *
	 * @return An Optional containing the interface description, or empty if no
	 *         description is available
	 */
	public Optional<String> description() {
		return description;
	}

	/**
	 * Returns the interface flags as a raw integer value. The returned value is a
	 * bitmask containing various interface state flags such as PCAP_IF_LOOPBACK,
	 * PCAP_IF_UP, PCAP_IF_RUNNING, etc.
	 *
	 * @return The raw interface flags as an integer bitmask
	 * @see PcapIfFlag for individual flag definitions
	 */
	public int flags() {
		return flags;
	}

	/**
	 * Returns the interface flags as an EnumSet of PcapIfFlag values. This method
	 * provides a more type-safe way to check interface flags compared to using raw
	 * integer values.
	 *
	 * @return An EnumSet containing the active flags for this interface
	 * @see PcapIfFlag
	 */
	public Set<PcapIfFlag> flagsAsEnumSet() {
		return PcapIfFlag.toEnumSet(flags);
	}

	/**
	 * Returns the hardware (MAC) address of this interface. This method attempts to
	 * retrieve the hardware address using the Java NetworkInterface API, which may
	 * require appropriate system permissions.
	 *
	 * @return An Optional containing the hardware address as a byte array, or empty
	 *         if the address is not available or accessible
	 */
	public Optional<byte[]> hardwareAddress() {
		return hardwareAddress;
	}

	/**
	 * Returns the name of this interface. The interface name is system-dependent
	 * (e.g., "eth0" on Linux, "en0" on macOS, "\\Device\\NPF_{GUID}" on Windows)
	 * and can be used with pcap_open_live() to open this interface for packet
	 * capture.
	 *
	 * @return The system-dependent name of this interface
	 */
	public String name() {
		return name;
	}

	/**
	 * Returns a string representation of this interface, including its name, flags,
	 * description (if available), and addresses (if any).
	 *
	 * @return A string representation of the interface
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
