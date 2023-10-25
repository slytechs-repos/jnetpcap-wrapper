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

import java.lang.foreign.MemorySegment;
import java.util.concurrent.TimeUnit;

import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.internal.PcapForeignDowncall;
import org.jnetpcap.internal.PcapForeignInitializer;
import org.jnetpcap.internal.PcapHeaderABI;

/**
 * Provides Pcap API method calls for up to libpcap version 0.9
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public sealed class Pcap0_9 extends Pcap0_8 permits Pcap1_0 {

	/**
	 * Symbol container for lazy initialization.
	 */
	protected static class Linux0_9 {

		/**
		 * The Constant pcap_set_protocol_linux.
		 *
		 * @see {@code int pcap_set_protocol_linux(pcap_t *, int)}
		 * @since libpcap 1.9 (Linux only)
		 */
		private static final PcapForeignDowncall pcap_set_protocol_linux;

		static {
			try (var foreign = new PcapForeignInitializer(Linux0_9.class)) {
				pcap_set_protocol_linux = foreign.downcall("pcap_set_protocol_linux(AI)I");
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
		 */
		public static boolean isSupported() {
			return pcap_set_protocol_linux.isNativeSymbolResolved();
		}

	}

	/**
	 * The Constant pcap_inject.
	 *
	 * @see {@code int pcap_inject(pcap_t *p, const void *buf, size_t size)}
	 * @since libpcap 1.9
	 */
	private static final PcapForeignDowncall pcap_inject;

	/**
	 * The Constant pcap_setdirection.
	 *
	 * @see {@code int pcap_setdirection(pcap_t *p, pcap_direction_t d)}
	 * @since libpcap 1.9
	 */
	private static final PcapForeignDowncall pcap_setdirection;

	static {
		try (var foreign = new PcapForeignInitializer(Pcap0_9.class)) {

			// @formatter:off
			pcap_inject       = foreign.downcall("pcap_inject(AAJ)I");
			pcap_setdirection = foreign.downcall("pcap_setdirection(AI)I");
			// @formatter:on

		}
	}

	/**
	 * Sets the direction.
	 *
	 * @param dir the dir
	 * @return the pcap 0 9
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#setDirection(int)
	 */
	@Override
	public Pcap0_9 setDirection(int dir) throws PcapException {
		pcap_setdirection.invokeInt(this::getErrorString, getPcapHandle(), dir);

		return this;
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
		return pcap_inject.isNativeSymbolResolved();
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
	public static Pcap0_9 openDead(PcapDlt linktype, int snaplen) throws PcapException {
		return Pcap0_6.openDead(Pcap0_9::new, linktype, snaplen);
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
	public static Pcap0_9 openLive(String device,
			int snaplen,
			boolean promisc,
			long timeout,
			TimeUnit unit) throws PcapException {

		return Pcap0_4.openLive(Pcap0_9::new, device, snaplen, promisc, timeout, unit);
	}

	/**
	 * Instantiates a new pcap 0 9.
	 *
	 * @param pcapHandle the pcap handle
	 * @param name       the handle name
	 * @param abi        the abi
	 */
	protected Pcap0_9(MemorySegment pcapHandle, String name, PcapHeaderABI abi) {
		super(pcapHandle, name, abi);
	}

	/**
	 * Inject.
	 *
	 * @param packet the packet
	 * @param length the length
	 * @return the int
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#inject(java.lang.foreign.MemorySegment, int)
	 */
	@Override
	public int inject(MemorySegment packet, int length) throws PcapException {
		return pcap_inject.invokeInt(this::getErrorString, getPcapHandle(), packet, (long) length);
	}

	/**
	 * set capture protocol for a not-yet-activated capture handle.
	 * 
	 * <p>
	 * On network interface devices on Linux, pcap_set_protocol_linux() sets the
	 * protocol to be used in the socket(2) call to create a capture socket when the
	 * handle is activated. The argument is a link-layer protocol value, such as the
	 * values in the {@code <linux/if_ether.h>} header file, specified in host byte
	 * order. If protocol is non-zero, packets of that protocol will be captured
	 * when the handle is activated, otherwise, all packets will be captured. This
	 * function is only provided on Linux, and, if it is used on any device other
	 * than a network interface, it will have no effect. It should not be used in
	 * portable full; instead, a filter should be specified with
	 * pcap_setfilter(3PCAP).
	 * </p>
	 * <p>
	 * If a given network interface provides a standard link-layer header, with a
	 * standard packet type, but provides some packet types with a different
	 * socket-layer protocol type from the one in the link-layer header, that packet
	 * type cannot be filtered with a filter specified with pcap_setfilter() but can
	 * be filtered by specifying the socket-layer protocol type using
	 * pcap_set_protocol_linux().
	 * </p>
	 * 
	 * @param protocol the protocol
	 * @return the int
	 * @throws PcapException the pcap exception
	 * @since libpcap 0.9 (Linux only)
	 */
	protected int setProtocolLinux(int protocol) throws PcapException {
		return Linux0_9.pcap_set_protocol_linux.invokeInt(this::getErrorString, getPcapHandle(), protocol);
	}
}
