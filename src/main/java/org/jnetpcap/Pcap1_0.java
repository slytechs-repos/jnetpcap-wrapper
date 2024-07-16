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

import org.jnetpcap.constant.PcapCode;
import org.jnetpcap.constant.PcapConstants;
import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.internal.ForeignUtils;
import org.jnetpcap.internal.PcapForeignDowncall;
import org.jnetpcap.internal.PcapForeignInitializer;
import org.jnetpcap.internal.PcapHeaderABI;

/**
 * Provides Pcap API method calls for up to libpcap version 1.0
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public sealed class Pcap1_0 extends Pcap0_9 permits Pcap1_2 {

	/**
	 * The Constant pcap_create.
	 *
	 * @see {@code pcap_t *pcap_create(const char *source, char *errbuf)}
	 * @since libpcap 1.0
	 */
	private static final PcapForeignDowncall pcap_create;

	/**
	 * The Constant pcap_activate.
	 *
	 * @see {@code int pcap_activate(pcap_t *p)}
	 * @since libpcap 1.0
	 */
	private static final PcapForeignDowncall pcap_activate;

	/**
	 * The Constant pcap_offline_filter.
	 *
	 * @see {@code int pcap_offline_filter(const struct bpf_program *fp, const
	 *      struct pcap_pkthdr *h, const u_char *pkt)}
	 * @since libpcap 1.0
	 */
	private static final PcapForeignDowncall pcap_offline_filter;

	/**
	 * The Constant pcap_set_buffer_size.
	 *
	 * @see {@code int pcap_set_buffer_size(pcap_t *p, int buffer_size)}
	 * @since libpcap 1.0
	 */
	private static final PcapForeignDowncall pcap_set_buffer_size;

	/**
	 * The Constant pcap_can_set_rfmon.
	 *
	 * @see {@code int pcap_can_set_rfmon(pcap_t *p)}
	 * @since libpcap 1.0
	 */
	private static final PcapForeignDowncall pcap_can_set_rfmon;

	/**
	 * The Constant pcap_set_rfmon.
	 *
	 * @see {@code int pcap_set_rfmon(pcap_t *, int)}
	 * @since libpcap 1.0
	 */
	private static final PcapForeignDowncall pcap_set_rfmon;

	/**
	 * The Constant pcap_set_promisc.
	 *
	 * @see {@code int pcap_set_promisc(pcap_t *, int)}
	 * @since libpcap 1.0
	 */
	private static final PcapForeignDowncall pcap_set_promisc;

	/**
	 * The Constant pcap_set_snaplen.
	 *
	 * @see {@code int pcap_set_snaplen(pcap_t *, int)}
	 * @since libpcap 1.0
	 */
	private static final PcapForeignDowncall pcap_set_snaplen;

	/**
	 * The Constant pcap_statustostr.
	 *
	 * @see {@code const char * pcap_statustostr(int)}
	 * @since libpcap 1.0
	 */
	private static final PcapForeignDowncall pcap_statustostr;

	/**
	 * The Constant pcap_set_timeout.
	 *
	 * @see {@code int pcap_set_timeout(pcap_t *, int)}
	 * @since libpcap 1.0
	 */
	private static final PcapForeignDowncall pcap_set_timeout;

	/**
	 * The Constant pcap_datalink_ext.
	 *
	 * @see {@code int pcap_datalink_ext(pcap_t *)}
	 * @since libpcap 1.0
	 */
	private static final PcapForeignDowncall pcap_datalink_ext;

	/**
	 * The Constant pcap_init.
	 *
	 * @see {@code int pcap_init(unsigned int opts, char *errbuf)}
	 * @since libpcap 1.0
	 */
	private static final PcapForeignDowncall pcap_init;

	static {
		try (var foreign = new PcapForeignInitializer(Pcap1_0.class)) {

			// @formatter:off
			pcap_create          = foreign.downcall("pcap_create(AA)A");
			pcap_activate        = foreign.downcall("pcap_activate(A)I");
			pcap_offline_filter  = foreign.downcall("pcap_offline_filter(AAA)I");
			pcap_set_buffer_size = foreign.downcall("pcap_set_buffer_size(AI)I");
			pcap_can_set_rfmon   = foreign.downcall("pcap_can_set_rfmon(A)I");
			pcap_set_promisc     = foreign.downcall("pcap_set_promisc(AI)I");
			pcap_set_rfmon       = foreign.downcall("pcap_set_rfmon(AI)I");
			pcap_set_snaplen     = foreign.downcall("pcap_set_snaplen(AI)I");
			pcap_set_timeout     = foreign.downcall("pcap_set_timeout(AI)I");
			pcap_statustostr     = foreign.downcall("pcap_statustostr(I)A");
			pcap_datalink_ext    = foreign.downcall("pcap_datalink_ext(A)I");
			pcap_init            = foreign.downcall("pcap_init(IA)I");
			// @formatter:on

		}
	}

	/**
	 * Creates the.
	 *
	 * @param <T>     the generic type
	 * @param factory the pcap supplier
	 * @param device  the device
	 * @return the version specific Pcap instance
	 * @throws PcapException the pcap exception
	 */
	protected static <T extends Pcap> T create(PcapSupplier<T> factory, String device)
			throws PcapException {
		try (var arena = newArena()) {
			MemorySegment c_errbuf = arena.allocate(PcapConstants.PCAP_ERRBUF_SIZE);
			MemorySegment c_device = arena.allocate(device.length() + 1);

			c_device.setString(0, device, java.nio.charset.StandardCharsets.UTF_8);

			MemorySegment pcapPointer = (MemorySegment) pcap_create.handle().invokeExact(c_device,
					c_errbuf);

			if (ForeignUtils.isNullAddress(pcapPointer))
				throw new PcapException(PcapCode.PCAP_ERROR, c_errbuf.getString(0, java.nio.charset.StandardCharsets.UTF_8));

			var abi = PcapHeaderABI.selectLiveAbi();

			return factory.newPcap(pcapPointer, device, abi);

		} catch (PcapException e) {
			throw e;
		} catch (Throwable e) {
			throw new RuntimeException(e);
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
	public static Pcap1_0 create(String device) throws PcapException {
		return Pcap1_0.create(Pcap1_0::new, device);
	}

	/**
	 * Initialize the native <em>libpcap</em> library.
	 * 
	 * <p>
	 * Used to initialize the Packet Capture library. opts specifies options for the
	 * library; currently, the options are:
	 * </p>
	 * <dl>
	 * <dt>{@link PcapConstants#PCAP_CHAR_ENC_LOCAL}</dt>
	 * <dd>Treat all strings supplied as arguments, and return all strings to the
	 * caller, as being in the local character encoding.</dd>
	 * <dt>{@link PcapConstants#PCAP_CHAR_ENC_UTF_8}</dt>
	 * <dd>Treat all strings supplied as arguments, and return all strings to the
	 * caller, as being in UTF-8.</dd>
	 * </dl>
	 * 
	 * <p>
	 * On UNIX-like systems, the local character encoding is assumed to be UTF-8, so
	 * no character encoding transformations are done.
	 * </p>
	 * 
	 * <p>
	 * On Windows, the local character encoding is the local ANSI full page.
	 * </p>
	 * 
	 * <p>
	 * If {@link #init(int)} is not called, strings are treated as being in the
	 * local ANSI full page on Windows, {@link #lookupDev()} will succeed if there
	 * is a device on which to capture, and {@link #create(String)} makes an attempt
	 * to check whether the string passed as an argument is a UTF-16LE string - note
	 * that this attempt is unsafe, as it may run past the end of the string - to
	 * handle pcap_lookupdev() returning a UTF-16LE string. Programs that don't call
	 * {@link #init(int)} should, on Windows, call native {@code pcap_wsockinit()}
	 * to initialize Winsock; this is not necessary if {@link #init} is called, as
	 * {@link #init} will initialize Winsock itself on Windows.
	 * </p>
	 *
	 * @param opts Pcap initialization option flags
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.9
	 */
	public static void init(int opts) throws PcapException {
		try (var arena = newArena()) {
			MemorySegment errbuf = arena.allocate(PcapConstants.PCAP_ERRBUF_SIZE);

			int result = pcap_init.invokeInt(opts, errbuf);
			if (result != PcapCode.PCAP_OK)
				PcapException.throwIfNotOk(opts, () -> errbuf.getString(0, java.nio.charset.StandardCharsets.UTF_8));
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
		return pcap_create.isNativeSymbolResolved();
	}

	/**
	 * Check whether a filter matches a packet.
	 * 
	 * <p>
	 * checks whether a filter matches a packet. fp is a pointer to a bpf_program
	 * struct, usually the result of a call to pcap_compile(3PCAP). h points to the
	 * pcap_pkthdr structure for the packet, and pkt points to the data in the
	 * packet.
	 * </p>
	 *
	 * @param bpFilter the BPF program or filter program
	 * @param pktHdr   the packet header
	 * @param pktData  the packet data
	 * @return true, if filter matched packet otherwise false
	 * @since libpcap 1.0
	 */
	public static boolean offlineFilter(BpFilter bpFilter, MemorySegment pktHdr, MemorySegment pktData) {
		MemorySegment c_bpf = bpFilter.address();

		int result = pcap_offline_filter.invokeInt(c_bpf, pktHdr, pktData);

		return (result != 0);
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
	public static Pcap1_0 openDead(PcapDlt linktype, int snaplen) throws PcapException {
		return Pcap0_6.openDead(Pcap1_0::new, linktype, snaplen);
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
	public static Pcap1_0 openLive(String device,
			int snaplen,
			boolean promisc,
			long timeout,
			TimeUnit unit) throws PcapException {

		return Pcap0_4.openLive(Pcap1_0::new, device, snaplen, promisc, timeout, unit);
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
	public static Pcap1_0 openOffline(String fname) throws PcapException {
		return Pcap0_4.openOffline(Pcap1_0::new, fname);
	}

	/**
	 * Convert an error full value to a string.
	 *
	 * @param error the error
	 * @return the error string for the given full
	 * @since libpcap 1.0
	 */
	public static String statusToStr(int error) {
		return pcap_statustostr.invokeString(error);
	}

	/**
	 * Instantiates a new pcap 100.
	 *
	 * @param pcapHandle the pcap handle
	 * @param name       the handle name
	 * @param abi        the abi
	 */
	protected Pcap1_0(MemorySegment pcapHandle, String name, PcapHeaderABI abi) {
		super(pcapHandle, name, abi);
	}

	/**
	 * Activate.
	 *
	 * @throws PcapActivatedException the pcap activated exception
	 * @throws PcapException          the pcap exception
	 * @see org.jnetpcap.Pcap#activate()
	 */
	@Override
	public void activate() throws PcapActivatedException, PcapException {
		int code = pcap_activate.invokeInt(getPcapHandle());
		if (code == PcapCode.PCAP_ERROR_ACTIVATED)
			throw new PcapActivatedException(code, "can not activate, already active");

		PcapException.throwIfNotOk(code);
	}

	/**
	 * Can set rfmon.
	 *
	 * @return true, if successful
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#canSetRfmon()
	 */
	@Override
	public final boolean canSetRfmon() throws PcapException {
		return (pcap_can_set_rfmon.invokeInt(this::getErrorString, getPcapHandle()) == 1);
	}

	/**
	 * Data link ext.
	 *
	 * @return the pcap dlt
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#dataLinkExt()
	 */
	@Override
	public final PcapDlt dataLinkExt() throws PcapException {
		return PcapDlt.valueOf(pcap_datalink_ext.invokeInt(this::getErrorString, getPcapHandle()));
	}

	/**
	 * @see org.jnetpcap.Pcap#setBufferSize(int)
	 */
	@Override
	public final Pcap1_0 setBufferSize(int bufferSize) throws PcapException {
		pcap_set_buffer_size.invokeInt(this::getErrorString, getPcapHandle(), bufferSize);

		return this;
	}

	/**
	 * Sets the promisc.
	 *
	 * @param b the b
	 * @return the pcap 1 0
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#setPromisc(boolean)
	 */
	@Override
	public final Pcap1_0 setPromisc(boolean b) throws PcapException {
		return setPromisc(b ? 1 : 0);
	}

	/**
	 * Set promiscuous mode for a not-yet-activated capture handle.
	 * <p>
	 * pcap_set_promisc() sets whether promiscuous mode should be set on a capture
	 * handle when the handle is activated. If promisc is non-zero, promiscuous mode
	 * will be set, otherwise it will not be set.
	 * </p>
	 *
	 * @param enable if true enable promiscous mode, otherwise disable it
	 * @return this pcap handle
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.0
	 */
	public final Pcap1_0 setPromisc(int enable) throws PcapException {
		pcap_set_promisc.invokeInt(this::getErrorString, getPcapHandle(), enable);

		return this;
	}

	/**
	 * Sets the rfmon.
	 *
	 * @param enableRfmon the enable rfmon
	 * @return the pcap 1 0
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#setRfmon(boolean)
	 */
	@Override
	public final Pcap1_0 setRfmon(boolean enableRfmon) throws PcapException {
		return setRfmon(enableRfmon ? 1 : 0);
	}

	/**
	 * Set monitor mode for a not-yet-activated capture handle.
	 * 
	 * <p>
	 * Sets whether monitor mode should be set on a capture handle when the handle
	 * is activated. If rfmon is {@code true}, monitor mode will be set, otherwise
	 * it will not be set.
	 * </p>
	 *
	 * @param enableRfmon the enable rfmon
	 * @return this pcap handle
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.0
	 */
	public final Pcap1_0 setRfmon(int enableRfmon) throws PcapException {
		pcap_set_rfmon.invokeInt(this::getErrorString, getPcapHandle(), enableRfmon);

		return this;
	}

	/**
	 * Sets the snaplen.
	 *
	 * @param snaplen the snaplen
	 * @return the pcap 1 0
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#setSnaplen(int)
	 */
	@Override
	public final Pcap1_0 setSnaplen(int snaplen) throws PcapException {
		pcap_set_snaplen.invokeInt(this::getErrorString, getPcapHandle(), snaplen);

		return this;
	}

	/**
	 * Sets the timeout.
	 *
	 * @param timeout the timeout
	 * @return the pcap 1 0
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap#setTimeout(int)
	 */
	@Override
	public final Pcap1_0 setTimeout(int timeout) throws PcapException {
		pcap_set_timeout.invokeInt(this::getErrorString, getPcapHandle(), timeout);

		return this;
	}

}
