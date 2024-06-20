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

import static org.jnetpcap.constant.PcapConstants.*;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.jnetpcap.constant.PcapCode;
import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.internal.PcapForeignDowncall;
import org.jnetpcap.internal.PcapForeignInitializer;
import org.jnetpcap.internal.PcapHeaderABI;

import static java.lang.foreign.ValueLayout.*;

/**
 * Provides Pcap API method calls for up to libpcap version 0.7
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public sealed class Pcap0_7 extends Pcap0_6 permits Pcap0_8 {

	/**
	 * The Constant pcap_findalldevs.
	 *
	 * @see {@code int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)}
	 * @since libpcap 0.7
	 */
	private final static PcapForeignDowncall pcap_findalldevs;

	/**
	 * The Constant pcap_freealldevs.
	 *
	 * @see {@code void pcap_freealldevs(pcap_if_t *alldevs)}
	 * @since libpcap 0.7
	 */
	private final static PcapForeignDowncall pcap_freealldevs;

	/**
	 * The Constant pcap_getnonblock.
	 *
	 * @see {@code int pcap_getnonblock(pcap_t *, char *)}
	 * @since libpcap 0.7
	 */
	private static final PcapForeignDowncall pcap_getnonblock;

	/**
	 * The Constant pcap_setnonblock.
	 *
	 * @see {@code int pcap_setnonblock(pcap_t *p, int nonblock, char *errbuf)}
	 * @since libpcap 0.7
	 */
	private static final PcapForeignDowncall pcap_setnonblock;

	static {
		try (var foreign = new PcapForeignInitializer(Pcap0_7.class)) {

			// @formatter:off
			pcap_findalldevs = foreign.downcall("pcap_findalldevs(AA)I");
			pcap_freealldevs = foreign.downcall("pcap_freealldevs(A)V");
			pcap_getnonblock = foreign.downcall("pcap_getnonblock(AA)I");
			pcap_setnonblock = foreign.downcall("pcap_setnonblock(AIA)I");
			// @formatter:on

		}
	}

	/**
	 * Constructs a list of network devices that can be opened with
	 * pcap_create(3PCAP) and pcap_activate(3PCAP) or with pcap_open_live(3PCAP).
	 * (Note that there may be network devices that cannot be opened by the process
	 * calling pcap_findalldevs(), because, for example, that process does not have
	 * sufficient privileges to open them for capturing; if so, those devices will
	 * not appear on the list.) If pcap_findalldevs() succeeds, the pointer pointed
	 * to by alldevsp is set to point to the first element of the list, or to NULL
	 * if no devices were found (this is considered success).
	 * 
	 * <p>
	 * Each element of the list is of type pcap_if_t, and has the following members:
	 * </p>
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
	 * <p>
	 * <b>For example</b>
	 * </p>
	 * 
	 * <pre>{@snippet : 
	 * 	List<PcapIf> list = Pcap.findAllDevs()
	 * }</pre>
	 *
	 * @return list of network devices
	 * @throws PcapException any pcap errors
	 * @since libpcap 0.7
	 */
	public static List<PcapIf> findAllDevs() throws PcapException {

		try (var arena = newArena()) {
			MemorySegment alldevsp = arena.allocate(ADDRESS);
			MemorySegment errbuf = arena.allocate(PCAP_ERRBUF_SIZE);

			/* int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf) */
			if (pcap_findalldevs.invokeInt(alldevsp, errbuf) == PcapCode.PCAP_ERROR)
				throw new PcapException(errbuf.getString(0, java.nio.charset.StandardCharsets.UTF_8));

			MemorySegment alldev = alldevsp.get(ValueLayout.ADDRESS, 0);

			List<PcapIf> list = PcapIf.listAll(alldev, arena);

			/* void pcap_freealldevs(pcap_if_t *alldevs) */
			pcap_freealldevs.invokeVoid(alldev);

			return Collections.unmodifiableList(list);
		}
	}

	/**
	 * Checks if the {@code Pcap} subclass at a specific <em>libpcap API
	 * version</em> is natively supported. This is a safe method to use anytime on
	 * any platform, weather native library is present or not.
	 * 
	 * <p>
	 * For example, {@code Pcap1_0.isSupported()} will accurately ascertain if
	 * libpcap API version 1.0 level calls are supported by the system runtime. Also
	 * a call such as {@code WinPcap.isSupported()} will determine if WinPcap
	 * related calls, ie. native WinPcap 4.1.3 or less, are supported and by
	 * extension if this is a Microsoft Windows platform.
	 * </p>
	 * <p>
	 * Due to <em>libpcap API versioning</em>, it is safe to assume that if
	 * {@code Pcap1_10.isSupported()} returns {@code true}, that at least
	 * <em>libpcap</em> API version 1.0 is installed on this platform, and that all
	 * lower version calls such as libpcap 0.8 and 0.9 are available as well. The
	 * subclass hierarchy of jNetPcap module reflects the versioning of libpcap and
	 * its derivatives and the public releases of the native libraries. For example
	 * {@code Npcap} class extends {@code WinPcap} class because <em>Npcap</em>
	 * project took over the support for <em>WinPcap</em> where it left off.
	 * </p>
	 * <p>
	 * Implementation notes: The check is performed by verifying that certain,
	 * subclass specific native symbols were linked with {@code Pcap} full which was
	 * introduced at a specific libpcap or related API levels.
	 * </p>
	 *
	 * @return true, if pcap is supported up to this specific version level,
	 *         otherwise false
	 * @see LibraryPolicy#setDefault(LibraryPolicy)
	 */
	public static boolean isSupported() {
		return pcap_findalldevs.isNativeSymbolResolved();
	}

	/**
	 * Open a fake pcap_t for compiling filters or opening a capture for output.
	 *
	 * <p>
	 * {@link #openDead} and pcap_open_dead_with_tstamp_precision() are used for
	 * creating a pcap_t structure to use when calling the other functions in
	 * libpcap. It is typically used when just using libpcap for compiling BPF full;
	 * it can also be used if using pcap_dump_open(3PCAP), pcap_dump(3PCAP), and
	 * pcap_dump_close(3PCAP) to write a savefile if there is no pcap_t that
	 * supplies the packets to be written.
	 * </p>
	 * 
	 * <p>
	 * When pcap_open_dead_with_tstamp_precision(), is used to create a pcap_t for
	 * use with pcap_dump_open(), precision specifies the time stamp precision for
	 * packets; PCAP_TSTAMP_PRECISION_MICRO should be specified if the packets to be
	 * written have time stamps in seconds and microseconds, and
	 * PCAP_TSTAMP_PRECISION_NANO should be specified if the packets to be written
	 * have time stamps in seconds and nanoseconds. Its value does not affect
	 * pcap_compile(3PCAP).
	 * </p>
	 * 
	 * @param linktype specifies the link-layer type for the pcap handle
	 * @param snaplen  specifies the snapshot length for the pcap handle
	 * @return A dead pcap handle
	 * @throws PcapException any errors
	 * @since libpcap 0.6
	 */
	public static Pcap0_7 openDead(PcapDlt linktype, int snaplen) throws PcapException {
		return Pcap0_6.openDead(Pcap0_7::new, linktype, snaplen);
	}

	/**
	 * Open a device for capturing.
	 * 
	 * <p>
	 * {@code openLive} is used to obtain a packet capture handle to look at packets
	 * on the network. device is a string that specifies the network device to open;
	 * on Linux systems with 2.2 or later kernels, a device argument of "any" or
	 * NULL can be used to capture packets from all interfaces.
	 * </p>
	 *
	 * @param device  the device name
	 * @param snaplen specifies the snapshot length to be set on the handle
	 * @param promisc specifies whether the interface is to be put into promiscuous
	 *                mode. If promisc is non-zero, promiscuous mode will be set,
	 *                otherwise it will not be set
	 * @param timeout the packet buffer timeout, as a non-negative value, in units
	 * @param unit    time timeout unit
	 * @return the pcap handle
	 * @throws PcapException any errors
	 * @since libpcap 0.4
	 */
	public static Pcap0_7 openLive(String device,
			int snaplen,
			boolean promisc,
			long timeout,
			TimeUnit unit) throws PcapException {

		return Pcap0_4.openLive(Pcap0_7::new, device, snaplen, promisc, timeout, unit);
	}

	/**
	 * Open a saved capture file for reading.
	 * 
	 * <p>
	 * pcap_open_offline() and pcap_open_offline_with_tstamp_precision() are called
	 * to open a ``savefile'' for reading.
	 * </p>
	 *
	 * @param fname specifies the name of the file to open. The file can have the
	 *              pcap file format as described in pcap-savefile(5), which is the
	 *              file format used by, among other programs, tcpdump(1) and
	 *              tcpslice(1), or can have the pcapng file format, although not
	 *              all pcapng files can be read
	 * @return the pcap handle
	 * @throws PcapException any errors
	 * @since libpcap 0.4
	 */
	public static Pcap0_7 openOffline(String fname) throws PcapException {
		return Pcap0_4.openOffline(Pcap0_7::new, fname);
	}

	/**
	 * Instantiates a new pcap 080.
	 *
	 * @param pcapHandle the pcap handle
	 * @param name       the handle name
	 * @param abi        the abi
	 */
	protected Pcap0_7(MemorySegment pcapHandle, String name, PcapHeaderABI abi) {
		super(pcapHandle, name, abi);
	}

	/**
	 * Gets the non block.
	 *
	 * @return the non block
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#getNonBlock()
	 */
	@Override
	public final boolean getNonBlock() throws PcapException {
		try (var arena = newArena()) {
			return pcap_getnonblock.invokeInt(this::getErrorString, getPcapHandle(), arena.allocate(
					PCAP_ERRBUF_SIZE)) == 1;
		}
	}

	/**
	 * Sets the non block.
	 *
	 * @param b the b
	 * @return the pcap 0 7
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#setNonBlock(boolean)
	 */
	@Override
	public final Pcap0_7 setNonBlock(boolean b) throws PcapException {
		try (var arena = newArena()) {
			pcap_setnonblock.invokeInt(this::getErrorString, getPcapHandle(), b ? 1 : 0, arena.allocate(
					PCAP_ERRBUF_SIZE));

			return this;
		}
	}

}
