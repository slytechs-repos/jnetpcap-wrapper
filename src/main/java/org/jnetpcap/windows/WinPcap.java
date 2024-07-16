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
package org.jnetpcap.windows;

import static org.jnetpcap.constant.PcapConstants.*;
import static org.jnetpcap.windows.PcapStatEx.*;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import org.jnetpcap.Pcap;
import org.jnetpcap.Pcap0_4;
import org.jnetpcap.Pcap0_6;
import org.jnetpcap.Pcap1_0;
import org.jnetpcap.Pcap1_10;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapIf;
import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.constant.PcapSrc;
import org.jnetpcap.constant.WinPcapMode;
import org.jnetpcap.internal.PcapForeignDowncall;
import org.jnetpcap.internal.PcapForeignInitializer;
import org.jnetpcap.internal.PcapHeaderABI;
import org.jnetpcap.internal.PcapStatExRecord;

import static java.lang.foreign.MemorySegment.*;
import static java.lang.foreign.ValueLayout.*;

/**
 * WinPcap is a wrapper around, windows packet capture library.
 * 
 * <h2>News - 15 September 2018</h2>
 * 
 * <blockquote> Native WinPcap, though still available for download (v4.1.3),
 * has not seen an upgrade in many years and there are no road map/future plans
 * to update the technology. While community support may persist, technical
 * oversight by Riverbed staff, responses to questions posed by Riverbed
 * resources, and bug reporting are no longer available. </blockquote>
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author http://winpcap.org
 * @author Mark Bednarczyk
 */
public sealed class WinPcap extends Pcap1_10 permits Npcap {

	/** The Constant WINPCAP_MODE_CAPT. */
	public static final int WINPCAP_MODE_CAPT = 0;

	/** The Constant WINPCAP_MODE_STAT. */
	public static final int WINPCAP_MODE_STAT = 1;

	/** The Constant WINPCAP_MODE_MON. */
	public static final int WINPCAP_MODE_MON = 2;

	/**
	 * The Constant pcap_wsockinit.
	 *
	 * @see {@code int pcap_wsockinit(void)}
	 * @since libpcap 0.4 (Windows only)
	 */
	private static final PcapForeignDowncall pcap_wsockinit;

	/**
	 * The Constant pcap_stat_ex.
	 *
	 * @see {@code struct pcap_stat* pcap_stats_ex(pcap_t * p, int *pcap_stat_size)}
	 * @since libpcap 0.4 (Windows only)
	 */
	private static final PcapForeignDowncall pcap_stat_ex;

	/**
	 * The Constant pcap_live_dump.
	 *
	 * @see {@code int pcap_live_dump (pcap_t *p, char *filename, int maxsize, int
	 *      maxpacks)}
	 * @since Microsoft Windows only
	 */
	private static final PcapForeignDowncall pcap_live_dump;

	/**
	 * The Constant pcap_live_dump_ended.
	 *
	 * @see {@code int pcap_live_dump (pcap_t *p, char *filename, int maxsize, int
	 *      maxpacks)}
	 * @since Microsoft Windows only
	 */
	private static final PcapForeignDowncall pcap_live_dump_ended;

	/**
	 * The Constant pcap_setbuff.
	 *
	 * @see {@code int pcap_setbuff (pcap_t *p, int dim)}
	 * @since Microsoft Windows only
	 */
	private static final PcapForeignDowncall pcap_setbuff;

	/**
	 * The Constant pcap_setmode.
	 *
	 * @see {@code int pcap_setmode(pcap_t *p, int mode)}
	 * @since Microsoft Windows only
	 */
	private static final PcapForeignDowncall pcap_setmode;

	/**
	 * The Constant pcap_setmintocopy.
	 *
	 * @see {@code int pcap_setmode(pcap_t *p, int mode)}
	 * @since Microsoft Windows only
	 */
	private static final PcapForeignDowncall pcap_setmintocopy;

	/**
	 * The Constant pcap_getevent.
	 *
	 * @see {@code HANDLE pcap_getevent(pcap_t *p)}
	 * @since Microsoft Windows only
	 */
	private static final PcapForeignDowncall pcap_getevent;

	/**
	 * The Constant pcap_findalldevs_ex.
	 *
	 * @see {@code int pcap_findalldevs_ex(const char *source, struct pcap_rmtauth
	 *      *auth, pcap_if_t **alldevs, char *errbuf)}
	 * @since libpcap 1.9
	 */
	private static final PcapForeignDowncall pcap_findalldevs_ex;

	/**
	 * The Constant pcap_createsrcstr.
	 *
	 * @see {@code int pcap_createsrcstr(char *source, int type, const char *host,
	 *      const char *port, const char *name, char *errbuf)}
	 * @since libpcap 1.9
	 */
	private static final PcapForeignDowncall pcap_createsrcstr;

	/**
	 * The Constant pcap_parsesrcstr.
	 *
	 * @see {@code int pcap_parsesrcstr(const char *source, int *type, char *host,
	 *      char *port, char *name, char *errbuf}
	 * @since libpcap 1.9
	 */
	private static final PcapForeignDowncall pcap_parsesrcstr;

	/**
	 * The Constant pcap_remoteact_accept_ex.
	 *
	 * @see {@code SOCKET pcap_remoteact_accept_ex(const char *address, const char
	 *      *port, const char *hostlist, char *connectinghost, struct pcap_rmtauth
	 *      *auth, int uses_ssl, char *errbuf)}
	 * @since libpcap 1.10
	 */
	@SuppressWarnings("unused")
	private static final PcapForeignDowncall pcap_remoteact_accept_ex;

	static {
		try (var foreign = new PcapForeignInitializer(WinPcap.class)) {

			// @formatter:off
			pcap_wsockinit           = foreign.downcall("pcap_wsockinit()I");
			pcap_stat_ex             = foreign.downcall("pcap_stat_ex(AA)A");
			pcap_live_dump           = foreign.downcall("pcap_live_dump(AAII)I");
			pcap_live_dump_ended     = foreign.downcall("pcap_live_dump_ended()I");
			pcap_setbuff             = foreign.downcall("pcap_setbuff(AI)I");
			pcap_setmode             = foreign.downcall("pcap_setmode(AI)I");
			pcap_setmintocopy        = foreign.downcall("pcap_setmintocopy(AI)I");
			pcap_getevent            = foreign.downcall("pcap_getevent(A)A");
			pcap_findalldevs_ex      = foreign.downcall("pcap_findalldevs_ex(AAAA)I");
			pcap_createsrcstr        = foreign.downcall("pcap_createsrcstr(AIAAAA)I");
			pcap_parsesrcstr         = foreign.downcall("pcap_parsesrcstr(AAAAAA)I");
			pcap_remoteact_accept_ex = foreign.downcall("pcap_remoteact_accept_ex(AAAAAIA)I");
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
	public static WinPcap create(String device) throws PcapException {
		return Pcap1_0.create(WinPcap::new, device);
	}

	/**
	 * Accept a set of strings (host name, port, ...), and it returns the complete
	 * source string according to the new format (e.g. 'rpcap://1.2.3.4/eth0').
	 * 
	 * <p>
	 * This function is provided in order to help the user creating the source
	 * string according to the new format. An unique source string is used in order
	 * to make easy for old applications to use the remote facilities. Think about
	 * tcpdump, for example, which has only one way to specify the interface on
	 * which the capture has to be started. However, GUI-based programs can find
	 * more useful to specify hostname, port and interface name separately. In that
	 * case, they can use this function to create the source string before passing
	 * it to the pcap_open() function.
	 * </p>
	 *
	 * @param type its value tells the type of the source we want to create
	 * @param host the host (e.g. "foo.bar.com") we want to connect to. It can be
	 *             NULL in case we want to open an interface on a local host
	 * @param port the network port (e.g. "2002") we want to use for the RPCAP
	 *             protocol. It can be NULL in case we want to open an interface on
	 *             a local host
	 * @param name the interface name we want to use (e.g. "eth0"). It can be NULL
	 *             in case the return string (i.e. 'source') has to be used with the
	 *             pcap_findalldevs_ex(), which does not require the interface name.
	 * @return contain the complete source string
	 * @throws PcapException the pcap exception
	 */
	public static String createSrcStr(PcapSrc type, String host, String port, String name) throws PcapException {
		try (var arena = newArena()) {
			MemorySegment c_source = arena.allocate(PCAP_BUF_SIZE);
			MemorySegment errbuf = arena.allocate(PCAP_ERRBUF_SIZE);

			MemorySegment c_host = (host != null) ? arena.allocateFrom(host, java.nio.charset.StandardCharsets.UTF_8) : NULL;
			MemorySegment c_port = (port != null) ? arena.allocateFrom(port, java.nio.charset.StandardCharsets.UTF_8) : NULL;
			MemorySegment c_name = (name != null) ? arena.allocateFrom(name, java.nio.charset.StandardCharsets.UTF_8) : NULL;

			int result = pcap_createsrcstr.invokeInt(c_source, type.getAsInt(), c_host, c_port, c_name, errbuf);
			PcapException.throwIfNotOk(result, () -> errbuf.getString(0, java.nio.charset.StandardCharsets.UTF_8));

			return c_source.getString(0, java.nio.charset.StandardCharsets.UTF_8);
		}
	}

	/**
	 * Create a list of network devices that can be opened with {@code #openopen}.
	 * <p>
	 * This routine can scan a directory for savefiles, list local capture devices,
	 * or list capture devices on a remote machine running an RPCAP server.
	 * </p>
	 * <p>
	 * For scanning for savefiles, it can be used on both UN*X systems and Windows
	 * systems; for each directory entry it sees, it tries to open the file as a
	 * savefile using pcap_open_offline(), and only includes it in the list of files
	 * if the open succeeds, so it filters out files for which the user doesn't have
	 * read permission, as well as files that aren't valid savefiles readable by
	 * libpcap.
	 * </p>
	 * <p>
	 * For listing local capture devices, it's just a wrapper around
	 * pcap_findalldevs(); full using pcap_findalldevs() will work on more platforms
	 * than full using pcap_findalldevs_ex().
	 * </p>
	 * <p>
	 * For listing remote capture devices, pcap_findalldevs_ex() is currently the
	 * only API available.
	 * </p>
	 * 
	 * <dl>
	 * <dt>Warning!</dt>
	 * <dd>There may be network devices that cannot be opened with pcap_open() by
	 * the process calling pcap_findalldevs(), because, for example, that process
	 * might not have sufficient privileges to open them for capturing; if so, those
	 * devices will not appear on the list.</dd>
	 * </dl>
	 * 
	 * @param source   This source will be examined looking for adapters (local or
	 *                 remote) (e.g. source can be 'rpcap://' for local adapters or
	 *                 'rpcap://host:port' for adapters on a remote host) or pcap
	 *                 files (e.g. source can be 'file://c:/myfolder/').
	 * @param type     Type of the authentication required
	 * @param username The username that has to be used on the remote machine for
	 *                 authentication
	 * @param password The password that has to be used on the remote machine for
	 *                 authentication
	 * @return The list of the devices
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.9
	 * @since early days of WinPcap
	 */
	public static List<PcapIf> findAllDevsEx(String source, PcapSrc type, String username, String password)
			throws PcapException {

		Objects.requireNonNull(type, "type");
		username = username == null ? "" : username;
		password = password == null ? "" : password;

		try (var arena = newArena()) {
			MemorySegment c_source = arena.allocateFrom(source, java.nio.charset.StandardCharsets.UTF_8);
			MemorySegment c_alldevsp = arena.allocate(ADDRESS);
			MemorySegment c_rmtauth = new PcapRmt.Auth(type, username, password).allocateNative(arena);
			MemorySegment errbuf = arena.allocate(PCAP_ERRBUF_SIZE);

			int result = pcap_findalldevs_ex.invokeInt(c_source, c_rmtauth, c_alldevsp, errbuf);
			PcapException.throwIfNotOk(result, () -> errbuf.getString(0, java.nio.charset.StandardCharsets.UTF_8));

			return listAllPcapIf(c_alldevsp.get(ADDRESS, 0), arena);
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
		return pcap_wsockinit.isNativeSymbolResolved();
	}

	/**
	 * New arena.
	 *
	 * @return the memory session
	 */
	protected static Arena newArena() {
		return Pcap.newArena();
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
	public static WinPcap openLive(String device,
			int snaplen,
			boolean promisc,
			long timeout,
			TimeUnit unit) throws PcapException {

		return Pcap0_4.openLive(WinPcap::new, device, snaplen, promisc, timeout, unit);
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
	public static WinPcap openDead(PcapDlt linktype, int snaplen) throws PcapException {
		return Pcap0_6.openDead(WinPcap::new, linktype, snaplen);
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
	public static WinPcap openOffline(String fname) throws PcapException {
		return Pcap0_4.openOffline(WinPcap::new, fname);
	}

	/**
	 * Parse the source string and returns the pieces in which the source can be
	 * split.
	 * <p>
	 * This call is the other way round of pcap_createsrcstr(). It accepts a
	 * null-terminated string and it returns the parameters related to the source.
	 * This includes:
	 * </p>
	 * <ul>
	 * <li>the type of the source (file, winpcap on a remote adapter, winpcap on
	 * local adapter), which is determined by the source prefix (PCAP_SRC_IF_STRING
	 * and so on)</li>
	 * <li>the host on which the capture has to be started (only for remote
	 * captures)</li>
	 * <li>the 'raw' name of the source (file name, name of the remote adapter, name
	 * of the local adapter), without the source prefix. The string returned does
	 * not include the type of the source itself (i.e. the string returned does not
	 * include "file://" or rpcap:// or such).</li>
	 * </ul>
	 * 
	 * @param source This source in the format (local or remote) (e.g. source can be
	 *               'rpcap://' for local adapters or 'rpcap://host:port' for
	 *               adapters on a remote host) or pcap files (e.g. source can be
	 *               'file://c:/myfolder/').
	 * @return parsed source string
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.9
	 * @since early days of WinPcap
	 */
	public static PcapRmt.Source parseSrcStr(String source) throws PcapException {
		try (var arena = newArena()) {
			MemorySegment errbuf = arena.allocate(PCAP_ERRBUF_SIZE);

			MemorySegment c_source = arena.allocateFrom(source, java.nio.charset.StandardCharsets.UTF_8);
			MemorySegment c_type = arena.allocate(JAVA_INT);
			MemorySegment c_host = arena.allocate( PCAP_BUF_SIZE);
			MemorySegment c_port = arena.allocate(PCAP_BUF_SIZE);
			MemorySegment c_name = arena.allocate(PCAP_BUF_SIZE);

			int result = pcap_parsesrcstr.invokeInt(c_source, c_type, c_host, c_port, c_name, errbuf);
			PcapException.throwIfNotOk(result, () -> errbuf.getString(0, java.nio.charset.StandardCharsets.UTF_8));

			int type = c_type.get(JAVA_INT, 0);
			String host = c_host.getString(0, java.nio.charset.StandardCharsets.UTF_8);
			String port = c_port.getString(0, java.nio.charset.StandardCharsets.UTF_8);
			String name = c_name.getString(0, java.nio.charset.StandardCharsets.UTF_8);

			PcapRmt.Source srcString = new PcapRmt.Source(type, host, port, name);

			return srcString;
		}
	}

	/**
	 * Initializes Winsock. on windows platforms (Windows only).
	 * 
	 * <p>
	 * Programs that don't call pcap_init() should, on Windows, call
	 * pcap_wsockinit() to initialize Winsock; this is not necessary if pcap_init()
	 * is called, as pcap_init() will initialize Winsock itself on Windows
	 * </p>
	 *
	 * @return status full
	 */
	public static int wsockInit() {
		return pcap_wsockinit.invokeInt();
	}

	/**
	 * Instantiates a new win pcap.
	 *
	 * @param pcapHandle the pcap handle
	 * @param name       the name
	 * @param abi        the abi
	 */
	WinPcap(MemorySegment pcapHandle, String name, PcapHeaderABI abi) {
		super(pcapHandle, name, abi);
	}

	/**
	 * Return the handle of the event associated with the interface {@code Pcap}.
	 * <p>
	 * This event can be passed to functions like WaitForSingleObject() or
	 * WaitForMultipleObjects() to wait until the driver's buffer contains some data
	 * without performing a read.
	 * </p>
	 * <p>
	 * We disourage the use of this function because it is not portable.
	 * </p>
	 * 
	 * @return the handle of the Windows event associated
	 * @throws PcapException the pcap exception
	 * @since Microsoft Windows only
	 */
	public MemorySegment getEvent() throws PcapException {
		return pcap_getevent.invokeObj(this::geterr, getPcapHandle());
	}

	/**
	 * Save a capture to file.
	 * <p>
	 * pcap_live_dump() dumps the network traffic from an interface to a file. Using
	 * this function the dump is performed at kernel level, therefore it is more
	 * efficient than using pcap_dump().
	 * </p>
	 * <p>
	 * The parameters of this function are an interface descriptor (obtained with
	 * pcap_open_live()), a string with the name of the dump file, the maximum size
	 * of the file (in bytes) and the maximum number of packets that the file will
	 * contain. Setting maxsize or maxpacks to 0 means no limit. When maxsize or
	 * maxpacks are reached, the dump ends.
	 * </p>
	 * <p>
	 * pcap_live_dump() is non-blocking, threfore Return immediately.
	 * pcap_live_dump_ended() can be used to check the status of the dump process or
	 * to wait until it is finished. pcap_close() can instead be used to end the
	 * dump process.
	 * </p>
	 * <p>
	 * Note that when one of the two limits is reached, the dump is stopped, but the
	 * file remains opened. In order to correctly flush the data and put the file in
	 * a consistent state, the adapter must be closed with pcap_close().
	 * </p>
	 *
	 * @param filename the filename where to write the file
	 * @param maxsize  maximum size of the file (in bytes)
	 * @param maxpacks maximum number of packets that the file will contain
	 * @throws PcapException the pcap exception
	 * @since Microsoft Windows only
	 */
	public void liveDump(String filename, int maxsize, int maxpacks) throws PcapException {
		try (var arena = newArena()) {
			MemorySegment c_filename = arena.allocateFrom(filename, java.nio.charset.StandardCharsets.UTF_8);
			pcap_live_dump.invokeInt(this::geterr,  getPcapHandle(), c_filename, maxsize, maxpacks);
		}
	}

	/**
	 * Return the status of the kernel dump process, i.e. tells if one of the limits
	 * defined with pcap_live_dump() has been reached.
	 * 
	 * pcap_live_dump_ended() informs the user about the limits that were set with a
	 * previous call to pcap_live_dump() on the interface pointed by p: if the
	 * return value is nonzero, one of the limits has been reched and the dump
	 * process is currently stopped.
	 * 
	 * If sync is nonzero, the function blocks until the dump is finished, otherwise
	 * Return immediately.
	 * 
	 * <dl>
	 * <dt>Warning!</dt>
	 * <dd>if the dump process has no limits (i.e. if the maxsize and maxpacks
	 * arguments of pcap_live_dump() were both 0), the dump process will never stop,
	 * therefore setting sync to TRUE will block the application on this call
	 * forever.</dd>
	 * </dl>
	 *
	 * @param sync the sync
	 * @return true, if successful
	 * @since Microsoft Windows only
	 */
	public boolean liveDumpEnded(boolean sync) {
		return pcap_live_dump_ended.invokeInt(getPcapHandle(), sync ? 1 : 0) != 0;
	}

	/**
	 * Transmit all packets in the send queue.
	 * <p>
	 * This function transmits the content of a queue to the wire. p is a pointer to
	 * the adapter on which the packets will be sent, queue points to a
	 * pcap_send_queue structure containing the packets to send (see
	 * pcap_sendqueue_alloc() and pcap_sendqueue_queue()), sync determines if the
	 * send operation must be synchronized: if it is non-zero, the packets are sent
	 * respecting the timestamps, otherwise they are sent as fast as possible.
	 * </p>
	 * <p>
	 * The return value is the amount of bytes actually sent. If it is smaller than
	 * the size parameter, an error occurred during the send. The error can be
	 * caused by a driver/adapter problem or by an inconsistent/bogus send queue.
	 * </p>
	 * <p>
	 * Note: Using this function is more efficient than issuing a series of
	 * pcap_sendpacket(), because the packets are buffered in the kernel driver, so
	 * the number of context switches is reduced. Therefore, expect a better
	 * throughput when using pcap_sendqueue_transmit. When Sync is set to TRUE, the
	 * packets are synchronized in the kernel with a high precision timestamp. This
	 * requires a non-negligible amount of CPU, but allows normally to send the
	 * packets with a precision of some microseconds (depending on the accuracy of
	 * the performance counter of the machine). Such a precision cannot be reached
	 * sending the packets with pcap_sendpacket().
	 * </p>
	 *
	 * @param queue the queue
	 * @param sync  if true, the packets are synchronized in the kernel with a high
	 *              precision timestamp
	 * @return number of packets transmitted
	 * @since Microsoft Windows only
	 */
	public int sendQueueTransmit(PcapSendQueue queue, boolean sync) {
		return queue.transmit(getPcapHandle(), sync);
	}

	/**
	 * Set the size of the kernel buffer associated with an adapter.
	 * <p>
	 * dim specifies the size of the buffer in bytes. The return value is 0 when the
	 * call succeeds, -1 otherwise. If an old buffer was already created with a
	 * previous call to pcap_setbuff(), it is deleted and its content is discarded.
	 * pcap_open_live() creates a 1 MByte buffer by default.
	 * </p>
	 *
	 * @param dim size of the buffer in bytes
	 * @throws PcapException the pcap exception
	 * @since Microsoft Windows only
	 */
	public void setBuff(int dim) throws PcapException {
		pcap_setbuff.invokeInt(this::getErrorString, getPcapHandle(), dim);
	}

	/**
	 * Set the minumum amount of data received by the kernel in a single call.
	 * <p>
	 * pcap_setmintocopy() changes the minimum amount of data in the kernel buffer
	 * that causes a read from the application to return (unless the timeout
	 * expires). If the value of size is large, the kernel is forced to wait the
	 * arrival of several packets before copying the data to the user. This
	 * guarantees a low number of system calls, i.e. low processor usage, and is a
	 * good setting for applications like packet-sniffers and protocol analyzers.
	 * Vice versa, in presence of a small value for this variable, the kernel will
	 * copy the packets as soon as the application is ready to receive them. This is
	 * useful for real time applications that need the best responsiveness from the
	 * kernel. pcap_open_live() sets a default mintocopy value of 16000 bytes.
	 * </p>
	 * 
	 * @param size minimum amount of data in the kernel buffer
	 * @throws PcapException the pcap exception
	 * @since Microsoft Windows only
	 */
	public void setMinToCopy(int size) throws PcapException {
		pcap_setmintocopy.invokeInt(this::getErrorString, getPcapHandle(), size);
	}

	/**
	 * Set the working mode of the interface p to mode.
	 * <p>
	 * Valid values for mode are MODE_CAPT (default capture mode) and MODE_STAT
	 * (statistical mode).
	 * </p>
	 * 
	 * @param mode the new mode
	 * @throws PcapException the pcap exception
	 */
	public void setMode(int mode) throws PcapException {
		pcap_setmode.invokeInt(this::getErrorString, getPcapHandle(), mode);
	}

	/**
	 * Set the working mode of the interface p to mode.
	 * <p>
	 * Valid values for mode are MODE_CAPT (default capture mode) and MODE_STAT
	 * (statistical mode).
	 * </p>
	 * 
	 * @param winPcapMode the new mode
	 * @throws PcapException the pcap exception
	 */
	public void setMode(WinPcapMode winPcapMode) throws PcapException {
		setMode(winPcapMode.getAsInt());
	}

	/**
	 * Return statistics on current capture.
	 * <p>
	 * pcap_stats_ex() extends the pcap_stats() allowing to return more statistical
	 * parameters than the old call. One of the advantages of this new call is that
	 * the pcap_stat structure is not allocated by the user; instead, it is returned
	 * back by the system. This allow to extend the pcap_stat structure without
	 * affecting backward compatibility on older applications. These will simply
	 * check at the values of the members at the beginning of the structure, while
	 * only newest applications are able to read new statistical values, which are
	 * appended in tail.
	 * </p>
	 * <p>
	 * To be sure not to read a piece of mamory which has not been allocated by the
	 * system, the variable pcap_stat_size will return back the size of the
	 * structure pcap_stat allocated by the system.
	 * </p>
	 * 
	 * @return the pcap stat ex
	 * @throws PcapException the pcap exception
	 * @since Microsoft Windows only
	 */
	public PcapStatEx statsEx() throws PcapException {

		try (var arena = newArena()) {
			MemorySegment sizeIntPtr = arena.allocate(JAVA_INT);
			MemorySegment pcap_stat_ex_ptr = pcap_stat_ex.invokeObj(this::geterr, getPcapHandle(), sizeIntPtr);

			MemorySegment mseg = pcap_stat_ex_ptr.reinterpret(PCAP_STAT_EX_LENGTH, arena, __ ->{});
			int statStructSize = sizeIntPtr.get(JAVA_INT, 0);

			return new PcapStatExRecord(statStructSize, mseg);
		}
	}

}