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
import java.util.concurrent.TimeoutException;
import java.util.stream.IntStream;

import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.internal.PcapForeignDowncall;
import org.jnetpcap.internal.PcapForeignInitializer;
import org.jnetpcap.internal.PcapHeaderABI;
import org.jnetpcap.util.PcapPacketRef;

import static java.lang.foreign.ValueLayout.*;

/**
 * Provides Pcap API method calls for up to libpcap version 0.8
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public sealed class Pcap0_8 extends Pcap0_7 permits Pcap0_9 {

	/**
	 * Symbol container for lazy initialization.
	 */
	protected static class Unix0_8 {

		/**
		 * The Constant pcap_get_selectable_fd.
		 *
		 * @see {@code int pcap_get_selectable_fd(pcap_t *p);}
		 * @since libpcap 1.8 (Unix only)
		 */
		private static final PcapForeignDowncall pcap_get_selectable_fd;

		static {
			try (var foreign = new PcapForeignInitializer(Pcap0_8.class)) {
				pcap_get_selectable_fd = foreign.downcall("pcap_get_selectable_fd(A)I");
			}
		}

		/**
		 * Instantiates a new unix specifc Pcap version 0.8 implementation.
		 */
		private Unix0_8() {

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
			return pcap_get_selectable_fd.isNativeSymbolResolved();
		}

	}

	/**
	 * The Constant pcap_breakloop.
	 *
	 * @see {@code void pcap_breakloop(pcap_t *p)}
	 * @since libpcap 0.8
	 */
	private static final PcapForeignDowncall pcap_breakloop;

	/**
	 * The Constant pcap_datalink_val_to_name.
	 *
	 * @see {@code const char *pcap_datalink_val_to_name(int dlt)}
	 * @since libpcap 0.8
	 */
	private static final PcapForeignDowncall pcap_datalink_val_to_name;

	/**
	 * The Constant pcap_datalink_val_to_description.
	 *
	 * @see {@code const char *pcap_datalink_val_to_description(int dlt)}
	 * @since libpcap 0.8
	 */
	private static final PcapForeignDowncall pcap_datalink_val_to_description;

	/**
	 * The Constant pcap_next_ex.
	 *
	 * @see {@code int pcap_next_ex (pcap_t *p, struct pcap_pkthdr **pkt_header,
	 *      const u_char **pkt_data)}
	 * @since libpcap 0.8
	 */
	private static final PcapForeignDowncall pcap_next_ex;

	/**
	 * The Constant pcap_list_datalinks.
	 *
	 * @see {@code int pcap_list_datalinks(pcap_t *p, int **dlt_buf)}
	 * @since libpcap 0.8
	 */
	private static final PcapForeignDowncall pcap_list_datalinks;

	/**
	 * The Constant pcap_free_datalinks.
	 *
	 * @see {@code void pcap_free_datalinks(int *dlt_list)}
	 * @since libpcap 0.8
	 */
	private static final PcapForeignDowncall pcap_free_datalinks;

	/**
	 * The Constant pcap_sendpacket.
	 *
	 * @see {@code int pcap_sendpacket(pcap_t *p, const u_char *buf, int size)}
	 * @since libpcap 0.8
	 */
	private static final PcapForeignDowncall pcap_sendpacket;

	/**
	 * The Constant pcap_set_datalink.
	 *
	 * @see {@code int pcap_set_datalink(pcap_t *p, int dlt)}
	 * @since libpcap 0.8
	 */
	private static final PcapForeignDowncall pcap_set_datalink;

	/**
	 * The Constant pcap_datalink_name_to_val.
	 *
	 * @see {@code int pcap_datalink_name_to_val(const char *name)}
	 * @since libpcap 0.8
	 */
	private static final PcapForeignDowncall pcap_datalink_name_to_val;

	/**
	 * The Constant pcap_lib_version.
	 *
	 * @see {@code const char *pcap_lib_version(void)}
	 * @since libpcap 0.8
	 */
	private static final PcapForeignDowncall pcap_lib_version;

	static {
		try (var foreign = new PcapForeignInitializer(Pcap0_8.class)) {

		// @formatter:off
		pcap_breakloop                   = foreign.downcall("pcap_breakloop(A)V");
		pcap_datalink_val_to_name        = foreign.downcall("pcap_datalink_val_to_name(I)A");
		pcap_datalink_val_to_description = foreign.downcall("pcap_datalink_val_to_description(I)A");
		pcap_next_ex                     = foreign.downcall("pcap_next_ex(AAA)I");
		pcap_list_datalinks              = foreign.downcall("pcap_list_datalinks(AA)I");
		pcap_free_datalinks              = foreign.downcall("pcap_free_datalinks(A)V");
		
		pcap_sendpacket                  = foreign.downcall("pcap_sendpacket(AAI)I");
		pcap_set_datalink                = foreign.downcall("pcap_set_datalink(AI)I");
		pcap_datalink_name_to_val        = foreign.downcall("pcap_datalink_name_to_val(A)I");
		
		pcap_lib_version                 = foreign.downcall("pcap_lib_version()A");
		// @formatter:on
		}
	}

	/**
	 * Translates a link-layer header type name, which is a DLT_ name with the DLT_
	 * removed, to the corresponding link-layer header type value. The translation
	 * is case-insensitive.
	 *
	 * @param name link-layer header type name
	 * @return the pcap data link type
	 * @since libpcap 0.8
	 */
	public static PcapDlt datalinkNameToVal(String name) {
		try (var arena = newArena()) {
			MemorySegment mseg = arena.allocateFrom(name, java.nio.charset.StandardCharsets.UTF_8);

			return PcapDlt.valueOf(pcap_datalink_name_to_val.invokeInt(mseg));
		}
	}

	/**
	 * Translates a link-layer header type value to a short description of that
	 * link-layer header type. NULL is returned if the type value does not
	 * correspond to a known DLT_ value..
	 *
	 * @param pcapDlt link-layer header type
	 * @return short description of that link-layer header type
	 * @since libpcap 0.8
	 */
	public static String dataLinkValToDescription(PcapDlt pcapDlt) {
		return pcap_datalink_val_to_description.invokeString(pcapDlt.getAsInt());
	}

	/**
	 * Translates a link-layer header type value to the corresponding link-layer
	 * header type name, which is the DLT_ name for the link-layer header type value
	 * with the DLT_ removed. NULL is returned if the type value does not correspond
	 * to a known DLT_ value..
	 *
	 * @param pcapDlt link-layer header type
	 * @return corresponding link-layer header type name
	 * @since libpcap 0.8
	 */
	public static String dataLinkValToName(PcapDlt pcapDlt) {
		return pcap_datalink_val_to_name.invokeString(pcapDlt.getAsInt());
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
		return pcap_breakloop.isNativeSymbolResolved();
	}

	/**
	 * Returns a string identifying the <em>libpcap</em> library, implementation
	 * information and version.
	 *
	 * @return a descriptive library string
	 */
	public static String libVersion() {
		return pcap_lib_version.invokeString();
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
	public static Pcap0_8 openDead(PcapDlt linktype, int snaplen) throws PcapException {
		return Pcap0_6.openDead(Pcap0_8::new, linktype, snaplen);
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
	public static Pcap0_8 openLive(String device,
			int snaplen,
			boolean promisc,
			long timeout,
			TimeUnit unit) throws PcapException {

		return Pcap0_4.openLive(Pcap0_8::new, device, snaplen, promisc, timeout, unit);
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
	public static Pcap0_8 openOffline(String fname) throws PcapException {
		return Pcap0_4.openOffline(Pcap0_8::new, fname);
	}

	/**
	 * Instantiates a new pcap 080.
	 *
	 * @param pcapHandle the pcap handle
	 * @param name       the handle name
	 * @param abi        the abi
	 */
	protected Pcap0_8(MemorySegment pcapHandle, String name, PcapHeaderABI abi) {
		super(pcapHandle, name, abi);
	}

	/**
	 * Breakloop.
	 *
	 * @see org.jnetpcap.Pcap#breakloop()
	 */
	@Override
	public final void breakloop() {
		pcap_breakloop.invokeVoid(getPcapHandle());
	}

	/**
	 * Get a file descriptor on which a select() can be done for a live capture.
	 * 
	 * <p>
	 * pcap_get_selectable_fd() returns, on UNIX, a file descriptor number for a
	 * file descriptor on which one can do a select(2), poll(2), epoll_wait(2),
	 * kevent(2), or other such call to wait for it to be possible to read packets
	 * without blocking, if such a descriptor exists, or -1, if no such descriptor
	 * exists. Some network devices opened with pcap_create(3PCAP) and
	 * pcap_activate(3PCAP), or with pcap_open_live(3PCAP), do not support those
	 * calls (for example, regular network devices on FreeBSD 4.3 and 4.4, and
	 * Endace DAG devices), so -1 is returned for those devices. In that case, those
	 * calls must be given a timeout less than or equal to the timeout returned by
	 * pcap_get_required_select_timeout(3PCAP) for the device for which
	 * pcap_get_selectable_fd() returned -1, the device must be put in non-blocking
	 * mode with a call to pcap_setnonblock(3PCAP), and an attempt must always be
	 * made to read packets from the device when the call returns. If
	 * pcap_get_required_select_timeout() returns NULL, it is not possible to wait
	 * for packets to arrive on the device in an event loop.
	 * </p>
	 * <p>
	 * Note that a device on which a read can be done without blocking may, on some
	 * platforms, not have any packets to read if the packet buffer timeout has
	 * expired. A call to pcap_dispatch(3PCAP) or pcap_next_ex(3PCAP) will return 0
	 * in this case, but will not block.
	 * <dl>
	 * <dt>Note that in:</dt>
	 * 
	 * <dd>FreeBSD prior to FreeBSD 4.6;</dd>
	 * <dd>NetBSD prior to NetBSD 3.0;</dd>
	 * <dd>OpenBSD prior to OpenBSD 2.4;</dd>
	 * <dd>Mac OS X prior to Mac OS X 10.7;</dd>
	 * </dl>
	 * <p>
	 * select(), poll(), and kevent() do not work correctly on BPF devices;
	 * pcap_get_selectable_fd() will return a file descriptor on most of those
	 * versions (the exceptions being FreeBSD 4.3 and 4.4), but a simple select(),
	 * poll(), or kevent() call will not indicate that the descriptor is readable
	 * until a full buffer's worth of packets is received, even if the packet
	 * timeout expires before then. To work around this, full that uses those calls
	 * to wait for packets to arrive must put the pcap_t in non-blocking mode, and
	 * must arrange that the call have a timeout less than or equal to the packet
	 * buffer timeout, and must try to read packets after that timeout expires,
	 * regardless of whether the call indicated that the file descriptor for the
	 * pcap_t is ready to be read or not. (That workaround will not work in FreeBSD
	 * 4.3 and later; however, in FreeBSD 4.6 and later, those calls work correctly
	 * on BPF devices, so the workaround isn't necessary, although it does no harm.)
	 * </p>
	 * <p>
	 * Note also that poll() and kevent() doesn't work on character special files,
	 * including BPF devices, in Mac OS X 10.4 and 10.5, so, while select() can be
	 * used on the descriptor returned by pcap_get_selectable_fd(), poll() and
	 * kevent() cannot be used on it those versions of Mac OS X. poll(), but not
	 * kevent(), works on that descriptor in Mac OS X releases prior to 10.4; poll()
	 * and kevent() work on that descriptor in Mac OS X 10.6 and later.
	 * </p>
	 * <p>
	 * pcap_get_selectable_fd() is not available on Windows.
	 * </p>
	 *
	 * @return the selectable fd
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.8 (Unix only)
	 */
	protected int getSelectableFd() throws PcapException {
		return Unix0_8.pcap_get_selectable_fd.invokeInt(this::getErrorString, getPcapHandle());
	}

	/**
	 * List data links.
	 *
	 * @return the list
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#listDataLinks()
	 */
	@Override
	public final List<PcapDlt> listDataLinks() throws PcapException {

		try (var arena = newArena()) {

			/* int pcap_list_datalinks(pcap_t *p, int **dlt_buf) */
			int count = pcap_list_datalinks.invokeInt(this::getErrorString, getPcapHandle(), super.POINTER_TO_POINTER1);
			MemorySegment dltBuf = POINTER_TO_POINTER1.getAtIndex(ADDRESS, 0)
					.reinterpret(JAVA_INT.byteAlignment() * count, arena, __ ->{});

			int[] dlts = dltBuf.toArray(JAVA_INT);

			/* void pcap_free_datalinks(int *dlt_list) */
			pcap_free_datalinks.invokeVoid(dltBuf);

			// Convert to Integer[] from int[] and collect as List<Integer>
			var list = IntStream.of(dlts)
					.mapToObj(PcapDlt::valueOf)
					.filter(d -> d != null)
					.toList();

			return Collections.unmodifiableList(list);
		}
	}

	/**
	 * Next ex.
	 *
	 * @return the pcap packet ref
	 * @throws PcapException    the pcap exception
	 * @throws TimeoutException the timeout exception
	 * @see org.jnetpcap.Pcap#nextEx()
	 */
	@Override
	public PcapPacketRef nextEx() throws PcapException, TimeoutException {
		return dispatcher.nextEx();
	}

	/**
	 * Send packet.
	 *
	 * @param packet the packet
	 * @param length the length
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#sendPacket(java.lang.foreign.MemorySegment, int)
	 */
	@Override
	public void sendPacket(MemorySegment packet, int length) throws PcapException {
		pcap_sendpacket.invokeInt(this::getErrorString, getPcapHandle(), packet, length);
	}

	/**
	 * Sets the datalink.
	 *
	 * @param dlt the dlt
	 * @return the pcap 0 8
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap0_4#setDatalink(int)
	 */
	@Override
	public final Pcap0_8 setDatalink(int dlt) throws PcapException {
		pcap_set_datalink.invokeInt(this::getErrorString, getPcapHandle(), dlt);

		return this;
	}

}
