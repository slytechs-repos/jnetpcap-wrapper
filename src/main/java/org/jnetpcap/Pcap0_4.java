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

import static java.util.Objects.*;
import static org.jnetpcap.constant.PcapConstants.*;
import static org.jnetpcap.internal.UnsafePcapHandle.*;

import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import org.jnetpcap.PcapHandler.OfMemorySegment;
import org.jnetpcap.constant.PcapCode;
import org.jnetpcap.constant.PcapConstants;
import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.internal.ForeignUtils;
import org.jnetpcap.internal.PcapDispatcher;
import org.jnetpcap.internal.PcapForeignDowncall;
import org.jnetpcap.internal.PcapForeignInitializer;
import org.jnetpcap.internal.PcapHeaderABI;
import org.jnetpcap.internal.PcapStatRecord;
import org.jnetpcap.internal.StandardPcapDispatcher;
import org.jnetpcap.util.NetIp4Address;
import org.jnetpcap.util.PcapPacketRef;

import static java.lang.foreign.MemorySegment.*;
import static java.lang.foreign.ValueLayout.*;

/**
 * Provides Pcap API method calls for up to libpcap version 0.4
 * 
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
public sealed class Pcap0_4 extends Pcap permits Pcap0_5 {

	/**
	 * The Interface PcapSupplier.
	 *
	 * @param <T> the generic type
	 */
	protected interface PcapSupplier<T extends Pcap> {

		/**
		 * Supplier of specific versioned Pcap subclasses and instantiations.
		 *
		 * @param handle the pcap handle
		 * @param name   the device name name
		 * @param abi    the native header abi
		 * @return the instance of specific Pcap subclass
		 */
		T newPcap(MemorySegment handle, String name, PcapHeaderABI abi);

	}

	/**
	 * The Constant pcap_open_live.
	 *
	 * @see {@code pcap_t *pcap_open_live (const char *device, int snaplen, int
	 *      promisc, int to_ms, char *errbuf)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_open_live;

	/**
	 * The Constant pcap_open_offline.
	 *
	 * @see {@code pcap_t *pcap_open_offline(const char *fname, char *errbuf)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_open_offline;

	/**
	 * The Constant pcap_close.
	 *
	 * @see {@code void pcap_close(pcap_t *p)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_close;

	/**
	 * The Constant pcap_datalink.
	 *
	 * @see {@code int pcap_datalink(pcap_t *p)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_datalink;

	/**
	 * The Constant pcap_geterr.
	 *
	 * @see {@code char *pcap_geterr(pcap_t *p)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_geterr;

	/**
	 * The Constant pcap_compile.
	 *
	 * @see {@code int pcap_compile (pcap_t *p, struct bpf_program *fp, const char
	 *      *str, int optimize, bpf_u_int32 netmask)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_compile;

	/**
	 * The Constant pcap_setfilter.
	 *
	 * @see {@code int pcap_setfilter(pcap_t *p, struct bpf_program *fp)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_setfilter;

	/**
	 * The Constant pcap_is_swapped.
	 *
	 * @see {@code int pcap_is_swapped(pcap_t *p)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_is_swapped;

	/**
	 * The Constant pcap_stats.
	 *
	 * @see {@code int pcap_stats(pcap_t *, struct pcap_stat *)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_stats;

	/**
	 * The Constant pcap_next.
	 *
	 * @see {@code const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_next;

	/**
	 * The Constant pcap_perror.
	 *
	 * @see {@code void pcap_perror(pcap_t *, const char *)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_perror;

	/**
	 * The Constant pcap_lookupnet.
	 *
	 * @see {@code int pcap_lookupnet(const char *device, bpf_u_int32 *netp,
	 *      bpf_u_int32 *maskp, char *errbuf)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_lookupnet;

	/**
	 * The Constant pcap_snapshot.
	 *
	 * @see {@code int pcap_snapshot(pcap_t *p)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_snapshot;

	/**
	 * The Constant pcap_major_version.
	 *
	 * @see {@code int pcap_major_version(pcap_t *p)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_major_version;

	/**
	 * The Constant pcap_minor_version.
	 *
	 * @see {@code int pcap_major_version(pcap_t *p)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_minor_version;

	/**
	 * The Constant pcap_file.
	 *
	 * @see {@code FILE *pcap_file(pcap_t *p)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_file;

	/**
	 * The Constant pcap_fileno.
	 *
	 * @see {@code int pcap_fileno(pcap_t *p)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_fileno;

	/**
	 * The Constant pcap_dump_open.
	 *
	 * @see {@code pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_dump_open;

	/**
	 * The Constant pcap_lookupdev.
	 *
	 * @see {@code [DEPRECATED] char *pcap_lookupdev(char *errbuf)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_lookupdev;

	/**
	 * The Constant pcap_strerror.
	 *
	 * @see {@code const char *pcap_strerror(int)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_strerror;

	static {

		try (var foreign = new PcapForeignInitializer(Pcap0_4.class)) {

			// @formatter:off
			pcap_open_live     = foreign.downcall("pcap_open_live(AIIIA)A"); //$NON-NLS-1$
			pcap_open_offline  = foreign.downcall("pcap_open_offline(AA)A"); //$NON-NLS-1$
			pcap_close         = foreign.downcall("pcap_close(A)V"); //$NON-NLS-1$
			pcap_datalink      = foreign.downcall("pcap_datalink(A)I"); //$NON-NLS-1$
			pcap_geterr        = foreign.downcall("pcap_geterr(A)A"); //$NON-NLS-1$
			pcap_compile       = foreign.downcall("pcap_compile(AAAII)I"); //$NON-NLS-1$
			pcap_setfilter     = foreign.downcall("pcap_setfilter(AA)I"); //$NON-NLS-1$
			pcap_is_swapped    = foreign.downcall("pcap_is_swapped(A)I"); //$NON-NLS-1$
			pcap_stats         = foreign.downcall("pcap_stats(AA)I"); //$NON-NLS-1$
			pcap_next          = foreign.downcall("pcap_next(AA)A"); //$NON-NLS-1$
			pcap_perror        = foreign.downcall("pcap_perror(AA)V"); //$NON-NLS-1$
			pcap_lookupnet     = foreign.downcall("pcap_lookupnet(AAAA)I"); //$NON-NLS-1$
			pcap_snapshot      = foreign.downcall("pcap_snapshot(A)I"); //$NON-NLS-1$
			pcap_major_version = foreign.downcall("pcap_major_version(A)I"); //$NON-NLS-1$
			pcap_minor_version = foreign.downcall("pcap_minor_version(A)I"); //$NON-NLS-1$
			pcap_file          = foreign.downcall("pcap_file(A)I"); //$NON-NLS-1$
			pcap_fileno        = foreign.downcall("pcap_fileno(A)I"); //$NON-NLS-1$
			pcap_dump_open     = foreign.downcall("pcap_dump_open(AA)A"); //$NON-NLS-1$
			pcap_lookupdev     = foreign.downcall("pcap_lookupdev(A)A"); //$NON-NLS-1$
			pcap_strerror      = foreign.downcall("pcap_strerror(I)A"); //$NON-NLS-1$
			// @formatter:on

		}

	}

	/**
	 * Checks if this is a Windows based platform.
	 *
	 * @return true, if is runtime is on windows
	 */
	public static boolean isInitialized() {
		return pcap_open_live.isNativeSymbolResolved();
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
		return pcap_open_live.isNativeSymbolResolved();
	}

	/**
	 * Find the default device on which to capture.
	 *
	 * @return the string
	 * @throws PcapException the pcap exception
	 */
	public static String lookupDev() throws PcapException {
		try (var arena = newArena()) {
			MemorySegment errbuf = arena.allocate(PCAP_ERRBUF_SIZE);

			String dev = pcap_lookupdev.invokeString(errbuf);
			if (dev == null)
				throw new PcapException(errbuf.getString(0, java.nio.charset.StandardCharsets.UTF_8));

			return dev;
		}
	}

	/**
	 * Find the IPv4 network number and netmask for a device.
	 * 
	 * pcap_lookupnet() is used to determine the IPv4 network number and mask
	 * associated with the network device device. Both netp and maskp are
	 * bpf_u_int32 pointers.
	 *
	 * @param device the network device name
	 * @return A netmasked IPv4 address
	 * @throws PcapException any LibpcapApi errors
	 * @since libpcap 0.4
	 */
	public static NetIp4Address lookupNet(String device) throws PcapException {
		try (var arena = newArena()) {
			MemorySegment pTop1 = arena.allocate(ADDRESS);
			MemorySegment pTop2 = arena.allocate(ADDRESS);
			MemorySegment errbuf = arena.allocate(PCAP_ERRBUF_SIZE);
			MemorySegment dev = arena.allocateFrom(device, java.nio.charset.StandardCharsets.UTF_8);

			int code = pcap_lookupnet.invokeInt(dev, pTop1, pTop2, errbuf);
			PcapException.throwIfNotOk(code, () -> errbuf.getString(0, java.nio.charset.StandardCharsets.UTF_8));

			int address = pTop1.get(ValueLayout.JAVA_INT, 0);
			int netmask = pTop2.get(ValueLayout.JAVA_INT, 0);

			return new NetIp4Address(address, netmask);
		}

	}

	/**
	 * Open live.
	 *
	 * @param <T>          the generic type
	 * @param pcapSupplier the pcap supplier
	 * @param device       the device
	 * @param snaplen      the snaplen
	 * @param promisc      the promisc
	 * @param timeout      the timeout
	 * @param unit         the unit
	 * @return the t
	 * @throws PcapException the pcap exception
	 */
	protected static <T extends Pcap> T openLive(PcapSupplier<T> pcapSupplier, String device,
			int snaplen,
			boolean promisc, long timeout, TimeUnit unit)
			throws PcapException {

		try (var arena = newArena()) {
			MemorySegment c_device = arena.allocateFrom(requireNonNull(device, "device"), java.nio.charset.StandardCharsets.UTF_8);
			MemorySegment errbuf = arena.allocate(PCAP_ERRBUF_SIZE);

			int c_snaplen = snaplen;
			int c_promisc = promisc ? 1 : 0;
			int c_to_ms = (unit == null) ? (int) timeout : (int) unit.toMillis(timeout);

			MemorySegment pcapPointer = pcap_open_live.invokeObj(c_device, c_snaplen, c_promisc, c_to_ms,
					errbuf);

			if (ForeignUtils.isNullAddress(pcapPointer))
				throw new PcapException(PcapCode.PCAP_ERROR, errbuf.getString(0, java.nio.charset.StandardCharsets.UTF_8));

			var abi = PcapHeaderABI.selectLiveAbi();

			return pcapSupplier.newPcap(pcapPointer, makeLiveHandleName(device), abi);
		}
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
	public static Pcap0_4 openLive(String device,
			int snaplen,
			boolean promisc,
			long timeout,
			TimeUnit unit) throws PcapException {

		return Pcap0_4.openLive(Pcap0_4::new, device, snaplen, promisc, timeout, unit);
	}

	/**
	 * open a saved capture file for reading.
	 * 
	 * <p>
	 * pcap_open_offline() and pcap_open_offline_with_tstamp_precision() are called
	 * to open a ``savefile'' for reading.
	 * </p>
	 *
	 * @param <T>          the generic type
	 * @param pcapSupplier the pcap supplier
	 * @param fname        specifies the name of the file to open. The file can have
	 *                     the pcap file format as described in pcap-savefile(5),
	 *                     which is the file format used by, among other programs,
	 *                     tcpdump(1) and tcpslice(1), or can have the pcapng file
	 *                     format, although not all pcapng files can be read
	 * @return the pcap handle
	 * @throws PcapException any errors
	 * @since Pcap 0.4
	 */
	protected static <T extends Pcap> T openOffline(PcapSupplier<T> pcapSupplier, String fname)
			throws PcapException {

		Objects.requireNonNull(fname, "fname"); //$NON-NLS-1$

		try (var arena = newArena()) {
			MemorySegment c_fname = arena.allocateFrom(fname, java.nio.charset.StandardCharsets.UTF_8);
			MemorySegment errbuf = arena.allocate(PCAP_ERRBUF_SIZE);

			MemorySegment pcapPointer = pcap_open_offline.invokeObj(c_fname, errbuf);

			if (ForeignUtils.isNullAddress(pcapPointer))
				throw new PcapException(PcapCode.PCAP_ERROR, errbuf.getString(0, java.nio.charset.StandardCharsets.UTF_8));

			boolean isSwapped = pcap_is_swapped
					.invokeInt(pcapPointer) == 1;

			var abi = PcapHeaderABI.selectOfflineAbi(isSwapped);

			return pcapSupplier.newPcap(pcapPointer, makeOfflineHandleName(fname), abi);
		}
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
	public static Pcap0_4 openOffline(String fname) throws PcapException {
		return Pcap0_4.openOffline(Pcap0_4::new, fname);
	}

	/**
	 * Convert an error full value to a string.
	 *
	 * @param code the code
	 * @return the error string for the given full
	 */
	public static String strerror(int code) {
		MemorySegment c_str = pcap_strerror.invokeObj(code);

		return ForeignUtils.toJavaString(c_str);
	}

	/**
	 * The pcap header buffer for use with next() call. Header and packet references
	 * are valid only from call to call and then out of pcap arena.
	 */
	private final MemorySegment PCAP0_4_HEADER_BUFFER = Arena.ofAuto()
			.allocate(PcapHeaderABI.nativeAbi().headerLength());

	/**
	 * Packet dispatcher implementation. The standard dispatcher just calls
	 * pcap_loop and pcap_dispatch native calls. Other dispatchers may perform
	 * additional processing on packets before dispatching to callback handlers.
	 */
	protected PcapDispatcher dispatcher;

	/**
	 * Instantiates a new pcap 0 4.
	 *
	 * @param pcapHandle the pcap handle
	 * @param name       the name
	 * @param abi        the abi
	 */
	protected Pcap0_4(MemorySegment pcapHandle, String name, PcapHeaderABI abi) {
		super(pcapHandle, name, abi);
		this.dispatcher = new StandardPcapDispatcher(getPcapHandle(), abi, this::breakloop);
	}

	/**
	 * Sets the packet dispatcher implementation.
	 *
	 * @param newDispatcher the new packet dispatcher implementation
	 */
	protected void setDispatcher(PcapDispatcher newDispatcher) {
		this.dispatcher.close(); // Close old dispatcher
		this.dispatcher = Objects.requireNonNull(newDispatcher, "dispatcher");
	}

	/**
	 * Gets the packet dispatcher implementation.
	 *
	 * @return the packet dispatcher implementation
	 */
	protected PcapDispatcher getDispatcher() {
		return dispatcher;
	}

	/**
	 * Close.
	 *
	 * @see org.jnetpcap.Pcap#close()
	 */
	@Override
	public void close() {
		pcap_close.invokeVoid(getPcapHandle());
		dispatcher.close();

		closed = true;
	}

	/**
	 * Compile.
	 *
	 * @param str      the str
	 * @param optimize the optimize
	 * @param netmask  the netmask
	 * @return the bp filter
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#compile(java.lang.String, boolean, int)
	 */
	@Override
	public final BpFilter compile(String str, boolean optimize, int netmask) throws PcapException {
		int opt = optimize ? 1 : 0;

		try (var arena = newArena()) {
			BpFilter bpFilter = new BpFilter(str);

			MemorySegment c_filter = arena.allocateFrom(str, java.nio.charset.StandardCharsets.UTF_8);

			pcap_compile.invokeInt(this::getErrorString, getPcapHandle(), bpFilter.address(), c_filter, opt, netmask);

			return bpFilter;
		}
	}

	/**
	 * Datalink.
	 *
	 * @return the pcap dlt
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#datalink()
	 */
	@Override
	public final PcapDlt datalink() throws PcapException {
		return PcapDlt.valueOf(datalinkGetAsInt());
	}

	/**
	 * Get the link-layer header type.
	 * 
	 * <p>
	 * It must not be called on a pcap descriptor created by pcap_create(3PCAP) that
	 * has not yet been activated by pcap_activate.
	 * </p>
	 * <p>
	 * https://www.tcpdump.org/linktypes.html lists the values pcap_datalink() can
	 * return and describes the packet formats that correspond to those values.
	 * </p>
	 * <p>
	 * Do NOT assume that the packets for a given capture or ``savefile`` will have
	 * any given link-layer header type, such as DLT_EN10MB for Ethernet. For
	 * example, the "any" device on Linux will have a link-layer header type of
	 * DLT_LINUX_SLL or DLT_LINUX_SLL2 even if all devices on the system at the time
	 * the "any" device is opened have some other data link type, such as DLT_EN10MB
	 * for Ethernet.
	 * </p>
	 *
	 * @return link-layer header type
	 * @throws PcapException any pcap errors
	 * @since libpcap 0.4
	 */
	public final int datalinkGetAsInt() throws PcapException {
		return pcap_datalink.invokeInt(this::getErrorString, getPcapHandle());
	}

	/**
	 * Dispatch.
	 *
	 * @param <U>     the generic type
	 * @param count   the count
	 * @param handler the handler
	 * @param user    the user
	 * @return the int
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#dispatch(int,
	 *      org.jnetpcap.PcapHandler.OfMemorySegment, java.lang.Object)
	 */
	@Override
	public <U> int dispatch(int count, OfMemorySegment<U> handler, U user) throws PcapException {

		MemorySegment aUser = (user instanceof MemorySegment addr) ? addr : NULL;

		return dispatcher.dispatchNative(count, (u, h, p) -> {
			int caplen = dispatcher.captureLength(h);
			int hdrlen = dispatcher.headerLength(h);

			/* Only valid for duration of this callback */
			try (var arena = newArena()) {

				MemorySegment mHdr = h.reinterpret(hdrlen, arena, __ ->{});
				MemorySegment mPkt = p.reinterpret(caplen, arena, __ ->{});

				/*
				 * If user value is address we forward the upcall user address.
				 * 
				 * Although with default dispatcher, the loop(user) value will always be the
				 * same as dispatched, but we override implementations which may provide a
				 * different user value between downcall and upcall.
				 */
				@SuppressWarnings("unchecked")
				U usr = (aUser == NULL) ? user : (U) u;

				handler.handleSegment(usr, mHdr, mPkt);
			}
		}, aUser);
	}

	/**
	 * Dispatch.
	 *
	 * @param count      the count
	 * @param pcapDumper the pcap dumper
	 * @return the int
	 * @see org.jnetpcap.Pcap#dispatch(int, org.jnetpcap.PcapDumper)
	 */
	@Override
	public final int dispatch(int count, PcapDumper pcapDumper) {

		/* Make sure no one can close the dumper while we're using it */
		synchronized (pcapDumper) {
			MemorySegment pcap_dump_func = pcapDumper.addressOfDumpFunction();
			MemorySegment pcap_dumper = pcapDumper.address();

			return dispatcher.dispatchRaw(count, pcap_dump_func, pcap_dumper);
		}
	}

	/**
	 * @see org.jnetpcap.Pcap#dispatch(int, org.jnetpcap.PcapHandler.NativeCallback, java.lang.foreign.MemorySegment)
	 */
	@Override
	public int dispatch(int count, PcapHandler.NativeCallback handler, MemorySegment user) {
		return dispatcher.dispatchNative(count, handler, user);
	}

	/**
	 * Dispatch.
	 *
	 * @param <U>     the generic type
	 * @param count   the count
	 * @param handler the handler
	 * @param user    the user
	 * @return the int
	 * @see org.jnetpcap.Pcap#dispatch(int, org.jnetpcap.PcapHandler.OfArray,
	 *      java.lang.Object)
	 */
	@Override
	public final <U> int dispatch(int count, PcapHandler.OfArray<U> handler, U user) {
		MemorySegment aUser = (user instanceof MemorySegment addr) ? addr : NULL;

		return dispatcher.dispatchNative(count, (u, header, bytes) -> {
			try (var arena = newArena()) {
				PcapHeader hdr = new PcapHeader(super.pcapHeaderABI, header, arena);

				int caplen = hdr.captureLength();
				assert caplen < PcapConstants.MAX_SNAPLEN : "caplen/wirelen out of range " + caplen;

				byte[] packet = bytes.reinterpret(caplen)
						.toArray(ValueLayout.JAVA_BYTE);

				handler.handleArray(user, hdr, packet);
			}
		}, aUser);
	}

	/**
	 * Dump open.
	 *
	 * @param fname the fname
	 * @return the pcap dumper
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#dumpOpen(java.lang.String)
	 */
	@Override
	public final PcapDumper dumpOpen(String fname) throws PcapException {
		try (var arena = newArena()) {
			MemorySegment c_file = arena.allocateFrom(fname, java.nio.charset.StandardCharsets.UTF_8);

			MemorySegment pcap_dumper_ptr = pcap_dump_open.invokeObj(this::geterr, getPcapHandle(), c_file);

			return new PcapDumper(pcap_dumper_ptr, fname);
		}
	}

	/**
	 * Get the OS standard I/O stream for a savefile being read.
	 * 
	 * <p>
	 * Returns the OS's standard I/O stream of the ``savefile,'' if a ``savefile''
	 * was opened with {@link Pcap#openOffline(String)}, or NULL, if a network
	 * device was opened with {@link Pcap#create(String)} and
	 * {@link Pcap#activate()}, or with
	 * {@link Pcap#openLive(String, int, boolean, long, TimeUnit)}. Note that the
	 * Packet Capture library is usually built with large file support, so the
	 * standard I/O stream of the ``savefile'' might refer to a file larger than 2
	 * gigabytes; applications that use {@link Pcap0_4#file()} should, if possible,
	 * use calls that support large files on the return value of
	 * {@link Pcap0_4#file()} or the value returned by {@link Pcap0_4#file()} when
	 * passed the return value of {@link Pcap0_4#file()}.
	 * </p>
	 *
	 * @return the OS standard I/O stream, only suitable with OS calls
	 * @throws PcapException the pcap exception
	 */
	public final MemorySegment file() throws PcapException {
		return pcap_file.invokeObj(this::geterr, getPcapHandle());
	}

	/**
	 * Get the file descriptor for a live capture.
	 * 
	 * <p>
	 * If {@code Pcap} refers to a network device that was opened for a live capture
	 * using a combination of {@link Pcap#create(String)} and
	 * {@link Pcap#activate()}, or using
	 * {@link Pcap#openLive(String, int, boolean, long, TimeUnit)} returns the OS
	 * file descriptor from which captured packets are read.
	 * </p>
	 *
	 * @return the OS file descriptor, only suitable with OS calls
	 * @throws PcapException the pcap exception
	 */
	public final int fileno() throws PcapException {
		return pcap_fileno.invokeInt(this::getErrorString, getPcapHandle());
	}

	/**
	 * Gets the err.
	 *
	 * @return the err
	 * @see org.jnetpcap.Pcap#geterr()
	 */
	@Override
	public final String geterr() {
		return pcap_geterr.invokeString(getPcapHandle());
	}

	/**
	 * Checks if is swapped.
	 *
	 * @return true, if is swapped
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#isSwapped()
	 */
	@Override
	public final boolean isSwapped() throws PcapException {
		int result = pcap_is_swapped.invokeInt(this::getErrorString, getPcapHandle());

		return (result == 1);
	}

	/**
	 * Loop.
	 *
	 * @param count      the count
	 * @param pcapDumper the pcap dumper
	 * @return the int
	 * @see org.jnetpcap.Pcap#loop(int, org.jnetpcap.PcapDumper)
	 */
	@Override
	public final int loop(int count, PcapDumper pcapDumper) {

		/* Make sure no one can close the dumper while we're using it */
		synchronized (pcapDumper) {
			MemorySegment pcap_dump_func = pcapDumper.addressOfDumpFunction();
			MemorySegment pcap_dumper = pcapDumper.address();

			return dispatcher.loopRaw(count, pcap_dump_func, pcap_dumper);
		}
	}

	/**
	 * @see org.jnetpcap.Pcap#loop(int, org.jnetpcap.PcapHandler.NativeCallback, java.lang.foreign.MemorySegment)
	 */
	@Override
	public int loop(int count, PcapHandler.NativeCallback handler, MemorySegment user) {
		return dispatcher.loopNative(count, handler, user);
	}

	/**
	 * Loop.
	 *
	 * @param <U>     the generic type
	 * @param count   the count
	 * @param handler the handler
	 * @param user    the user
	 * @return the int
	 * @see org.jnetpcap.Pcap#loop(int, org.jnetpcap.PcapHandler.OfArray,
	 *      java.lang.Object)
	 */
	@Override
	public <U> int loop(int count, PcapHandler.OfArray<U> handler, U user) {
		MemorySegment aUser = (user instanceof MemorySegment addr) ? addr : NULL;

		return dispatcher.loopNative(count, (u, header, bytes) -> {
			try (var arena = newArena()) {
				PcapHeader hdr = new PcapHeader(super.pcapHeaderABI, header, arena);

				int caplen = hdr.captureLength();
				assert caplen < PcapConstants.MAX_SNAPLEN : "caplen/wirelen out of range " + caplen;

				byte[] packet = bytes.reinterpret(caplen)
						.toArray(ValueLayout.JAVA_BYTE);

				handler.handleArray(user, hdr, packet);
			}
		}, aUser);
	}

	/**
	 * @see org.jnetpcap.Pcap#loop(int, org.jnetpcap.PcapHandler.OfMemorySegment, java.lang.Object)
	 */
	@Override
	public <U> int loop(int count, PcapHandler.OfMemorySegment<U> handler, U user) {
		MemorySegment aUser = (user instanceof MemorySegment addr) ? addr : NULL;

		return dispatcher.loopNative(count, (u, h, p) -> {
			int caplen = dispatcher.captureLength(h);
			int hdrlen = dispatcher.headerLength(h);

			/* Only valid for duration of this callback */
			try (var arena = newArena()) {

				MemorySegment mHdr = h.reinterpret(hdrlen, arena, __ ->{});
				MemorySegment mPkt = p.reinterpret(caplen, arena, __ ->{});

				/*
				 * If user value is address we forward the upcall user address.
				 * 
				 * Although with default dispatcher, the loop(user) value will always be the
				 * same as dispatched, but we override implementations which may provide a
				 * different user value between downcall and upcall.
				 */
				@SuppressWarnings("unchecked")
				U usr = (aUser == NULL) ? user : (U) u;

				handler.handleSegment(usr, mHdr, mPkt);
			}
		}, aUser);
	}

	/**
	 * Major version.
	 *
	 * @return the int
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#majorVersion()
	 */
	@Override
	public final int majorVersion() throws PcapException {
		return pcap_major_version.invokeInt(this::getErrorString, getPcapHandle());
	}

	/**
	 * Minor version.
	 *
	 * @return the int
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#minorVersion()
	 */
	@Override
	public final int minorVersion() throws PcapException {
		return pcap_minor_version.invokeInt(this::getErrorString, getPcapHandle());
	}

	/**
	 * Next.
	 *
	 * @return the pcap packet ref
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#next()
	 */
	@Override
	public PcapPacketRef next() throws PcapException {
		return dispatcher.next();
	}

	/**
	 * Perror.
	 *
	 * @param prefix the prefix
	 * @return the pcap 0 4
	 * @see org.jnetpcap.Pcap#perror(java.lang.String)
	 */
	@Override
	public final Pcap0_4 perror(String prefix) {
		try (var arena = newArena()) {
			pcap_perror.invokeVoid(getPcapHandle(), arena.allocateFrom(prefix), java.nio.charset.StandardCharsets.UTF_8);

			return this;
		}
	}

	/**
	 * Sets the filter.
	 *
	 * @param bpfProgram the bpf program
	 * @return the pcap 0 4
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#setFilter(org.jnetpcap.BpFilter)
	 */
	@Override
	public final Pcap0_4 setFilter(BpFilter bpfProgram) throws PcapException {
		pcap_setfilter.invokeInt(this::getErrorString, getPcapHandle(), bpfProgram.address());

		return this;
	}

	/**
	 * Snapshot.
	 *
	 * @return the int
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#snapshot()
	 */
	@Override
	public final int snapshot() throws PcapException {
		return pcap_snapshot.invokeInt(this::getErrorString, getPcapHandle());
	}

	/**
	 * Stats.
	 *
	 * @return the pcap stat
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#stats()
	 */
	@Override
	public final PcapStat stats() throws PcapException {
		try (var arena = newArena()) {
			MemorySegment mseg = arena.allocate(PcapConstants.PCAP_STAT_SIZE);

			pcap_stats.invokeInt(this::getErrorString, getPcapHandle(), mseg);

			return PcapStatRecord.ofMemoryPlatformDependent(mseg);
		}
	}

	/**
	 * Sets the uncaught exception handler for {@link #loop} and {@link #dispatch}
	 * methods. Any exception thrown within the user callback methods, will be
	 * caught and sent to the specified user exception handler.
	 *
	 * @param exceptionHandler the exception handler
	 * @return this pcap
	 */
	@Override
	public Pcap setUncaughtExceptionHandler(UncaughtExceptionHandler exceptionHandler) {
		dispatcher.setUncaughtExceptionHandler(exceptionHandler);

		return this;
	}
}
