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
 * Provides Pcap API method calls for up to libpcap version 0.5
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public sealed class Pcap0_5 extends Pcap0_4 permits Pcap0_6 {

	/**
	 * The Constant pcap_compile_nopcap.
	 *
	 * @see {@code int pcap_compile_nopcap (int snaplen, int linktype,
	 * struct bpf_program *bpf, const char *str, int optimize, bpf_u_int32 netmask)}
	 * @since libpcap 0.5
	 */
	private final static PcapForeignDowncall pcap_compile_nopcap;

	static {
		try (var foreign = new PcapForeignInitializer(Pcap0_5.class)) {

			// @formatter:off
			pcap_compile_nopcap = foreign.downcall("pcap_compile_nopcap(IIAAII)I");
			// @formatter:on

		}
	}

	/**
	 * Compile a filter expression against a dead handle opened using
	 * {@code openDead}.
	 * <p>
	 * pcap_compile() is used to compile the string str into a filter program. See
	 * pcap-filter(7) for the syntax of that string. fp is a pointer to a
	 * bpf_program struct and is filled in by pcap_compile(). optimize controls
	 * whether optimization on the resulting full is performed. netmask specifies
	 * the IPv4 netmask of the network on which packets are being captured; it is
	 * used only when checking for IPv4 broadcast addresses in the filter program.
	 * If the netmask of the network on which packets are being captured isn't known
	 * to the program, or if packets are being captured on the Linux "any"
	 * pseudo-interface that can capture on more than one network, a value of
	 * PCAP_NETMASK_UNKNOWN can be supplied; tests for IPv4 broadcast addresses will
	 * fail to compile, but all other tests in the filter program will be OK.
	 * </p>
	 * <p>
	 * NOTE: in libpcap 1.8.0 and later, pcap_compile() can be used in multiple
	 * threads within a single process. However, in earlier versions of libpcap, it
	 * is not safe to use pcap_compile() in multiple threads in a single process
	 * without some form of mutual exclusion allowing only one thread to call it at
	 * any given time.
	 * </p>
	 *
	 * @param snaplen  the snaplen
	 * @param pcapDlt  the dlt
	 * @param str      filter expression to be compiled
	 * @param optimize controls whether optimization on the resulting full is
	 *                 performed
	 * @param netmask  specifies the IPv4 netmask of the network on which packets
	 *                 are being captured; it is used only when checking for IPv4
	 *                 broadcast addresses in the filter program. If the netmask of
	 *                 the network on which packets are being captured isn't known
	 *                 to the program, or if packets are being captured on the Linux
	 *                 "any" pseudo-interface that can capture on more than one
	 *                 network, a value of PCAP_NETMASK_UNKNOWN can be supplied;
	 *                 tests for IPv4 broadcast addresses will fail to compile, but
	 *                 all other tests in the filter program will be OK
	 * @return the compiled filter
	 * @throws PcapException any errors
	 */
	public static BpFilter compileNoPcap(
			int snaplen,
			PcapDlt pcapDlt,
			String str,
			boolean optimize,
			int netmask) throws PcapException {

		int opt = optimize ? 1 : 0;

		try (var arena = newArena()) {
			BpFilter bpFilter = new BpFilter(str);

			MemorySegment c_filter = arena.allocateFrom(str, java.nio.charset.StandardCharsets.UTF_8);

			int code = pcap_compile_nopcap.invokeInt(snaplen, pcapDlt.getAsInt(), bpFilter.address(), c_filter, opt,
					netmask);
			PcapException.throwIfNotOk(code);

			return bpFilter;
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
		return pcap_compile_nopcap.isNativeSymbolResolved();
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
	public static Pcap0_5 openLive(String device,
			int snaplen,
			boolean promisc,
			long timeout,
			TimeUnit unit) throws PcapException {

		return Pcap0_4.openLive(Pcap0_5::new, device, snaplen, promisc, timeout, unit);
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
	public static Pcap0_5 openOffline(String fname) throws PcapException {
		return Pcap0_4.openOffline(Pcap0_5::new, fname);
	}

	/**
	 * Instantiates a new pcap 050.
	 *
	 * @param pcapHandle the pcap handle
	 * @param name       the name
	 * @param abi        the abi
	 */
	protected Pcap0_5(MemorySegment pcapHandle, String name, PcapHeaderABI abi) {
		super(pcapHandle, name, abi);
	}

}
