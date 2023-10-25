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
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.constant.PcapTstampType;
import org.jnetpcap.internal.PcapForeignDowncall;
import org.jnetpcap.internal.PcapForeignInitializer;
import org.jnetpcap.internal.PcapHeaderABI;

import static java.lang.foreign.ValueLayout.*;

/**
 * Provides Pcap API method calls for up to libpcap version 1.2
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public sealed class Pcap1_2 extends Pcap1_0 permits Pcap1_5 {

	/**
	 * The Constant pcap_list_tstamp_types.
	 *
	 * @see {@code int pcap_list_tstamp_types(pcap_t *p, int **tstamp_typesp)}
	 * @since libpcap 1.2
	 */
	private static final PcapForeignDowncall pcap_list_tstamp_types;

	/**
	 * The Constant pcap_free_tstamp_types.
	 *
	 * @see {@code void pcap_free_tstamp_types(int *tstamp_types)}
	 * @since libpcap 1.2
	 */
	private static final PcapForeignDowncall pcap_free_tstamp_types;

	/**
	 * The Constant pcap_set_tstamp_type.
	 *
	 * @see {@code int pcap_set_tstamp_type(pcap_t *p, int tstamp_type)}
	 * @since libpcap 1.2
	 */
	private static final PcapForeignDowncall pcap_set_tstamp_type;

	static {
		try (var foreign = new PcapForeignInitializer(Pcap1_2.class)) {

			// @formatter:off
			pcap_list_tstamp_types = foreign.downcall("pcap_list_tstamp_types(AA)I");
			pcap_free_tstamp_types = foreign.downcall("pcap_free_tstamp_types(A)V");
			pcap_set_tstamp_type   = foreign.downcall("pcap_set_tstamp_type(AI)I");
			// @formatter:on

		}
	}

	/**
	 * Create a live capture handle.
	 * 
	 * {@code create} is used to create a packet capture handle to look at packets
	 * on the network. source is a string that specifies the network device to open;
	 * on Linux systems with 2.2 or later kernels, a source argument of "any" or
	 * NULL can be used to capture packets from all interfaces. The returned handle
	 * must be activated with pcap_activate() before pack' ets can be captured with
	 * it; options for the capture, such as promiscu' ous mode, can be set on the
	 * handle before activating it.
	 *
	 * @param device a string that specifies the network device to open; on Linux
	 *               systems with 2.2 or later kernels, a source argument of "any"
	 *               or NULL can be used to capture packets from all interfaces.
	 * @return a new pcap object that needs to be activated using
	 *         {@link #activate()} call
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.0
	 */
	public static Pcap1_2 create(String device) throws PcapException {
		return Pcap1_0.create(Pcap1_2::new, device);
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
		return pcap_free_tstamp_types.isNativeSymbolResolved();
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
	public static Pcap1_2 openDead(PcapDlt linktype, int snaplen) throws PcapException {
		return Pcap0_6.openDead(Pcap1_2::new, linktype, snaplen);
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
	public static Pcap1_2 openLive(String device,
			int snaplen,
			boolean promisc,
			long timeout,
			TimeUnit unit) throws PcapException {

		return Pcap0_4.openLive(Pcap1_2::new, device, snaplen, promisc, timeout, unit);
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
	public static Pcap1_2 openOffline(String fname) throws PcapException {
		return Pcap0_4.openOffline(Pcap1_2::new, fname);
	}

	/**
	 * Instantiates a new pcap 1 2.
	 *
	 * @param pcapHandle the pcap handle
	 * @param name       the handle name
	 * @param abi        the abi
	 */
	protected Pcap1_2(MemorySegment pcapHandle, String name, PcapHeaderABI abi) {
		super(pcapHandle, name, abi);
	}

	/**
	 * List tstamp types.
	 *
	 * @return the list
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#listTstampTypes()
	 */
	@Override
	public final List<PcapTstampType> listTstampTypes() throws PcapException {

		try (var arena = newArena()) {

			/* Pcap allocates space to hold int[] natively */
			int len = pcap_list_tstamp_types.invokeInt(this::getErrorString, getPcapHandle(), POINTER_TO_POINTER1);

			/* Dereference to int[] address */
			MemorySegment arrayAddress = POINTER_TO_POINTER1.get(ADDRESS, 0);
			int[] array = arrayAddress.reinterpret(JAVA_INT.byteSize() * len, arena, __ ->{})
					.toArray(JAVA_INT);

			/* Copy from native int[] to java int[] */
			List<PcapTstampType> result = IntStream.of(array)
					.mapToObj(PcapTstampType::valueOf)
					.toList();

			/* free int[] allocated by libpcap */
			pcap_free_tstamp_types.invokeVoid(arrayAddress);

			return Collections.unmodifiableList(result);
		}
	}

	/**
	 * Sets the tstamp type.
	 *
	 * @param type the type
	 * @return the pcap
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#setTstampType(org.jnetpcap.constant.PcapTstampType)
	 */
	@Override
	public final Pcap setTstampType(PcapTstampType type) throws PcapException {
		pcap_set_tstamp_type.invokeInt(this::getErrorString, getPcapHandle(), type.getAsInt());

		return this;
	}

}
