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
package org.jnetpcap;

import static java.lang.foreign.MemoryAddress.NULL;
import static java.lang.foreign.MemoryLayout.PathElement.groupElement;
import static java.lang.foreign.MemoryLayout.PathElement.sequenceElement;
import static java.lang.foreign.MemorySegment.ofAddress;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;
import static org.jnetpcap.internal.ForeignUtils.toJavaString;

import java.lang.foreign.MemoryAddress;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.VarHandle;
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.constant.SockAddrFamily;
import org.jnetpcap.util.PcapUtils;

/**
 * Native Type pcap_if_t has the following members:
 * 
 * <p>
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
 * <dt>flags</dt>
 * <dd>device flags:
 * <dl>
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
 * <dt>PCAP_IF_CONNECTION_STATUS</dt>
 * <dd>a bitmask for an indication of whether the adapter is connected or not;
 * for wireless interfaces, "connected" means "associated with a network"
 * <dl>
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
 * </dd></dd>
 * </dl>
 * </p>
 * 
 * <p>
 * Each element of the list of addresses is of type pcap_addr_t, and has the
 * following members:
 * </dl>
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
 * </p>
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
 * @author repos@slytechs.com
 * @apiNote libpcap 0.7
 */
public class PcapIf {

	/**
	 * The struct pcap_addr structure containing network interfaces/devices
	 * addresses.
	 */
	public static class PcapAddr {
		private static final MemoryLayout LAYOUT = MemoryLayout.structLayout(
				ValueLayout.ADDRESS.withName("next"),
				ValueLayout.ADDRESS.withName("addr"),
				ValueLayout.ADDRESS.withName("netmask"),
				ValueLayout.ADDRESS.withName("broadaddr"),
				ValueLayout.ADDRESS.withName("dstaddr"));

		private static final VarHandle nextHandle = LAYOUT.varHandle(groupElement("next"));
		private static final VarHandle addrHandle = LAYOUT.varHandle(groupElement("addr"));
		private static final VarHandle netmaskHandle = LAYOUT.varHandle(groupElement("netmask"));
		private static final VarHandle broadaddrHandle = LAYOUT.varHandle(groupElement("broadaddr"));
		private static final VarHandle dstaddrHandle = LAYOUT.varHandle(groupElement("dstaddr"));

		private static List<PcapAddr> listAll(MemoryAddress next, MemorySession scope) {
			List<PcapAddr> list = new ArrayList<>();

			while (next != null && next != NULL) {
				MemorySegment mseg = ofAddress(next, LAYOUT.byteSize(), scope);
				list.add(new PcapAddr(mseg, scope));

				next = (MemoryAddress) nextHandle.get(mseg);
			}
			return list;
		}

		private final SockAddr addr;
		private final SockAddr netmask;
		private final SockAddr broadaddr;
		private final SockAddr dstaddr;

		PcapAddr(MemorySegment mseg, MemorySession scope) {
			addr = SockAddr.newInstance(addrHandle.get(mseg), scope);
			netmask = SockAddr.newInstance(netmaskHandle.get(mseg), scope);
			broadaddr = SockAddr.newInstance(broadaddrHandle.get(mseg), scope);
			dstaddr = SockAddr.newInstance(dstaddrHandle.get(mseg), scope);
		}

		@Override
		public String toString() {
			return "PcapAddr ["
					+ "addr=" + addr
					+ ", netmask=" + netmask
					+ ", broadaddr=" + broadaddr
					+ ", dstaddr=" + dstaddr
					+ "]";
		}
	}

	/**
	 * The low level sockaddr structure containing an address of different types,
	 * depending on the protocol family value.
	 */
	public static class SockAddr {

		private static final MemoryLayout LAYOUT = MemoryLayout.structLayout(
				JAVA_SHORT.withName("family"),
				JAVA_SHORT.withName("port"),
				MemoryLayout.sequenceLayout(32, JAVA_BYTE).withName("addr"));

		private static final VarHandle familyHandle = LAYOUT.varHandle(groupElement("family"));
		private static final VarHandle portHandle = LAYOUT.varHandle(groupElement("port"));
		private static final VarHandle addrHandle = LAYOUT.varHandle(groupElement("addr"), sequenceElement());

		static SockAddr newInstance(Object value, MemorySession scope) {
			MemoryAddress addr = (MemoryAddress) value;
			if (addr == null || addr == NULL)
				return null;

			return new SockAddr(addr, scope);
		}

		private final int family;
		private final int port;
		private final byte[] addr;

		SockAddr(MemoryAddress addr, MemorySession scope) {
			MemorySegment mseg = ofAddress(addr, LAYOUT.byteSize(), scope);

			this.family = Short.toUnsignedInt((short) familyHandle.get(mseg));
			this.port = Short.toUnsignedInt((short) portHandle.get(mseg));

			this.addr = switch (family) {
			case 2 -> new byte[4];
			case 10 -> new byte[16];
			default -> new byte[8];
			};

			for (int i = 0; i < this.addr.length; i++)
				this.addr[i] = (byte) addrHandle.get(mseg, i);
		}

		protected byte[] addr() {
			return addr;
		}

		protected int family() {
			return family;
		}

		protected int port() {
			return port;
		}

		@Override
		public String toString() {
//			if (family != SockAddrFamily.INET.ordinal() && family != SockAddrFamily.INET6.ordinal())
//				return "family(" + SockAddrFamily.valueOf(family) + ")";

			return "SockAddr "
					+ "[fam=" + SockAddrFamily.valueOf(family)
//					+ " port=" + port
					+ " addr=" + PcapUtils.toAddressString(addr)
					+ "]";
		}
	}

	private static final MemoryLayout LAYOUT = MemoryLayout.structLayout(
			ValueLayout.ADDRESS.withName("next"),
			ValueLayout.ADDRESS.withName("name"),
			ValueLayout.ADDRESS.withName("description"),
			ValueLayout.ADDRESS.withName("addresses"),
			ValueLayout.JAVA_INT.withName("flags"));

	private static final VarHandle nextHandle = LAYOUT.varHandle(groupElement("next"));
	private static final VarHandle nameHandle = LAYOUT.varHandle(groupElement("name"));
	private static final VarHandle descHandle = LAYOUT.varHandle(groupElement("description"));
	private static final VarHandle addrsHandle = LAYOUT.varHandle(groupElement("addresses"));
	private static final VarHandle flagsHandle = LAYOUT.varHandle(groupElement("flags"));

	/** interface is loopback */
	public final static int PCAP_IF_LOOPBACK = 0x00000001;
	/** interface is up */
	public final static int PCAP_IF_UP = 0x00000002;
	/** interface is running */
	public final static int PCAP_IF_RUNNING = 0x00000004;

	static List<PcapIf> listAll(MemoryAddress next, MemorySession scope) {
		List<PcapIf> list = new ArrayList<>();

		while (next != null && next != NULL) {
			MemorySegment mseg = ofAddress(next, LAYOUT.byteSize(), scope);
			list.add(new PcapIf(mseg, scope));

			next = (MemoryAddress) nextHandle.get(mseg);
		}

		return list;
	}

	private final String name;

	private final String description;

	private final int flags;

	private final List<PcapAddr> addresses;

	PcapIf(MemorySegment mseg, MemorySession scope) {
		MemoryAddress addrs = (MemoryAddress) addrsHandle.get(mseg);

		name = toJavaString(nameHandle.get(mseg));
		description = toJavaString(descHandle.get(mseg));
		flags = (int) flagsHandle.get(mseg);

		addresses = PcapAddr.listAll(addrs, scope);
	}

	public List<PcapAddr> addresses() {
		return addresses;
	}

	protected String description() {
		return description;
	}

	protected int flags() {
		return flags;
	}

	public String name() {
		return name;
	}

	@Override
	public String toString() {
		return "PcapIf ["
				+ "name=" + name
				+ ", description=" + description
				+ ", flags=" + flags
				+ ", addresses=" + addresses
				+ "]";
	}

}
