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

import java.io.File;
import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import org.jnetpcap.Pcap0_4.PcapSupplier;
import org.jnetpcap.constant.PcapCode;
import org.jnetpcap.constant.PcapConstants;
import org.jnetpcap.constant.PcapDirection;
import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.constant.PcapOption;
import org.jnetpcap.constant.PcapSrc;
import org.jnetpcap.constant.PcapTStampPrecision;
import org.jnetpcap.constant.PcapTstampType;
import org.jnetpcap.internal.PcapForeignInitializer;
import org.jnetpcap.internal.PcapHeaderABI;
import org.jnetpcap.util.NetIp4Address;
import org.jnetpcap.util.PcapPacketRef;
import org.jnetpcap.util.PcapVersionException;

import static java.lang.foreign.ValueLayout.*;

/**
 * Entry point and base class for all Pcap API methods provided by jNetPcap
 * library.
 *
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
public abstract sealed class Pcap implements AutoCloseable permits Pcap0_4 {

	/**
	 * An interface which provides a hook into Pcap initialization process. Any
	 * missing native library symbols during the low level initialization/static
	 * process are captured and reported to this policy which may log, report, or
	 * even halt the initialization process from continuing.
	 * 
	 * <h2>Logging and handling errors on missing native symbols</h2>
	 * <p>
	 * A policy also defines a logger output destination, a {@code Appendable},
	 * where logs by the default policy on initialization errors are sent. By
	 * default a {@code PrintWriter.nullWriter()} is used which discards all logging
	 * output. Any {@code Appendable} implementing output destination can be used
	 * such as {@code System.err}, {@code StringBuilder}, {@code CharBuffer},
	 * {@code Writer} and so on.
	 * </p>
	 * <p>
	 * For quick debugging, the default policy can be used by "turning on" the
	 * logging message consumer using code
	 * {@code LibraryPolicy.setLoggingOutput(System.err)} which will print to
	 * console any native library missing symbols. Again, this output is discarded
	 * by default settings. Can also install a {@code Logger} adapter as well
	 * instead of sending the output to console, while still using the default
	 * policy.
	 * </p>
	 * <p>
	 * For more sophisticated library handling, you can install a new policy, that
	 * does or does not rely on the {@link #getLogginOutput()} value. It may also
	 * throw an {@code IllegalStateException} to stop further intialization process
	 * from continuing, or try to attempt a different native loading path or method.
	 * By throwing an exception in the class static initializer, as this would do,
	 * you are preventing the class from loading and initializing the first time an
	 * error is encountered. This allows a second attempt with different native
	 * library loading algorithm. By providing your own policy which overrides the
	 * default native libpcap library loading method
	 * {@link #loadNativePcapLibrary(boolean)}, you load the library yourself. It
	 * calls on the default library initializer, which is a private instance of
	 * {@code ForeignInitializer} class.
	 * </p>
	 * <h3>Native Library Loading</h3>
	 * <p>
	 * You can define several system properties which control the behavior of how
	 * the native pcap library, or one of its derivatives are loaded. These
	 * properties, allow changing of the procedure how the library is located and
	 * how is actually loaded. The defaults for the native library loading
	 * procedure, define a list of possible pcap library undecorated names such as
	 * 'wpcap,npcap,pcap' and utilize the relative
	 * {@link System#loadLibrary(String)} to search for the shared object/native
	 * library.
	 * </p>
	 * <p>
	 * By specifying various system properties on the java command line, you can
	 * redefine how, where and what to look for when loading the native library.
	 * </p>
	 * The following properties are used in a search, in the following order:
	 * <dl>
	 * <dt>{@value LibraryPolicy#SYSTEM_PROPERTY_JAVA_LIBRARY_PATH}:</dt>
	 * <dd>Defines directories where the native library will searched for.</dd>
	 * <dt>{@value LibraryPolicy#SYSTEM_PROPERTY_LIBPCAP_FILE}:</dt>
	 * <dd>Defines an absolute directory and decorated filename path to load the
	 * native library using {@link System#load(String)} system call.</dd>
	 * <dt>{@value LibraryPolicy#SYSTEM_PROPERTY_LIBPCAP_FILENAME}:</dt>
	 * <dd>Defines a decorated filename only of the native library. The decorated
	 * filename will be appended to the
	 * {@value LibraryPolicy#SYSTEM_PROPERTY_JAVA_LIBRARY_PATH} and an absolute
	 * library load call will be attempted {@link System#load(String)}.</dd>
	 * <dt>{@value LibraryPolicy#SYSTEM_PROPERTY_LIBPCAP_NAMES}:</dt>
	 * <dd>A comma separated list of undecorated library names. Each of the
	 * undecorated names in the list will be attempted to load using
	 * {@link System#loadLibrary(String)} combined with the
	 * {@value LibraryPolicy#SYSTEM_PROPERTY_JAVA_LIBRARY_PATH} property value.</dd>
	 * <dt>{@value LibraryPolicy#SYSTEM_PROPERTY_SO_EXTENSIONS}:</dt>
	 * <dd>Lastly, as a long-shot attempt, a list of absolute files will be built by
	 * combining all the property values given, with fully decorated filenames which
	 * utilize the provided extensions, to try and locate the native library on the
	 * platform. The default extension list are defined as "so,dylib". Each one will
	 * be tried in turn.
	 * </dl>
	 *
	 * @see LibraryPolicy#SYSTEM_PROPERTY_JAVA_LIBRARY_PATH
	 * @see LibraryPolicy#SYSTEM_PROPERTY_LIBPCAP_FILE
	 * @see LibraryPolicy#SYSTEM_PROPERTY_LIBPCAP_FILENAME
	 * @see LibraryPolicy#SYSTEM_PROPERTY_LIBPCAP_NAMES
	 * @see LibraryPolicy#SYSTEM_PROPERTY_SO_EXTENSIONS
	 * @see LibraryPolicy#SYSTEM_PROPERTY_SO_IGNORE_LOAD_ERRORS
	 */
	@FunctionalInterface
	public interface LibraryPolicy {

		/** System property used to search for native libraries. */
		String SYSTEM_PROPERTY_JAVA_LIBRARY_PATH = "java.library.path";

		/**
		 * System property containing the absolute native file path to the pcap library.
		 * For example
		 * <code>-Dorg.jnetpcap.libpcap.file="/usr/lib/x86_64-linux-gnu/libpcap.so"</code>
		 */
		String SYSTEM_PROPERTY_LIBPCAP_FILE = "org.jnetpcap.libpcap.file";

		/**
		 * System property containing full native library filename, but no directory
		 * path. The value of the 'java.library.path' is prepended to the filename and
		 * an attempt to load the library is made. For example:
		 * <code>-Dorg.jnetpcap.libpcap.names="libpcap.so"</code>
		 */
		String SYSTEM_PROPERTY_LIBPCAP_FILENAME = "org.jnetpcap.libpcap.filename";

		/**
		 * A list of comma separated, undecorated library names. The default is to
		 * search for <code>npcap,wpcap,pcap</code> in the directories specified by
		 * 'java.library.path'
		 */
		String SYSTEM_PROPERTY_LIBPCAP_NAMES = "org.jnetpcap.libpcap.names";

		/**
		 * Platform dependent list of shared-object extensions to use while attempting
		 * to load the native library. This property, combined with the
		 * 'org.jnetpcap.libpcap.names' property and 'java.library.path' propeties are
		 * used to try and load native library by building absolute file path to each
		 * named library. The default is <code>so,dylib</code> extensions.
		 */
		String SYSTEM_PROPERTY_SO_EXTENSIONS = "org.jnetpcap.so.extensions";

		/**
		 * The system property which is used to define if load error messages should be
		 * ignored or not. If ignored, when shared library is not found, it will be
		 * silently ignored and no errors reported. If set to 'false', when native
		 * shared object is not found, and exception will be thrown by the default
		 * LibraryPolicy currently set. Default is 'true' or ignore errors and be
		 * silent.
		 * <p>
		 * Note: errors are always detectible by using the method
		 * {@link Pcap#isSupported()} call, which will return false if the pcap library
		 * was not loaded. Also invoking any of the native methods, will throw an
		 * <code>IllegalStateException</code>. This propery applies to the act of native
		 * library loading itself, and does not silence
		 * <code>IllegalStateExceptions</code> when native methods are invoked and
		 * corresponding native library has not been loaded at runtime.
		 */
		String SYSTEM_PROPERTY_SO_IGNORE_LOAD_ERRORS = "org.jnetpcap.so.ignoreLoadErrors";

		/**
		 * System property used to override the selection of the PcapHeaderABI. ABI
		 * stands for <em>Application Binary Interface</em>, a low level hardware
		 * architecture dependent description how native primitive data structures are
		 * encoded.
		 * <p>
		 * The main difference between "compact" and "padded" native C structures is how
		 * individual members within a give C structure an encoded. Specifically the
		 * <code>struct pcap_pkthdr</code> in <em>libpcap</em> is susceptible to such
		 * encoding differences. The timestamp field is defined as two int sub-fields
		 * (seconds and micro-seconds), each of which is typically 32-bits but on modern
		 * 64-bit machines. Therefore the sizeof(pcap_pkthdr) can be either 16 or 24
		 * bytes, depending on the architecture. Further more, even on 64-bit machines,
		 * when reading offline files, the header stored is byte encoded to the machine
		 * that wrote the offline file. Thus you can have a "compact" header on a 64-bit
		 * machine, and even with its bytes swapped for integer values. The ABI values
		 * determines the best ABI to utilize to read such binary headers.
		 * </p>
		 * <p>
		 * The applicable values are:
		 * </p>
		 * <dl>
		 * <dt>COMPACT_LE</dt>
		 * <dd>Native C structure is "compact" encoded with LITTLE endian byte encoding.
		 * The total length of pcap_pkthdr is 16 bytes.</dd>
		 * <dt>COMPACT_BE</dt>
		 * <dd>Native C structure is "compact" encoded with BIG endian byte encoding.
		 * The total length of pcap_pkthdr is 16 bytes.</dd>
		 * <dt>PADDED_LE</dt>
		 * <dd>Native C structure is "padded" encoded with LITTLE endian byte encoding.
		 * The total length of pcap_pkthdr is 24 bytes.</dd>
		 * <dt>PADDED_BE</dt>
		 * <dd>Native C structure is "padded" encoded with BIG endian byte encoding. The
		 * total length of pcap_pkthdr is 24 bytes.</dd>
		 * </dl>
		 */
		String SYSTEM_PROPERTY_ABI = "org.jnetpcap.abi";

		/**
		 * Default value ("true") for {@link #SYSTEM_PROPERTY_SO_IGNORE_LOAD_ERRORS}
		 * property if not specified in system properties.
		 * 
		 * @see #SYSTEM_PROPERTY_SO_IGNORE_LOAD_ERRORS
		 */
		String DEFAULT_SO_IGNORE_LOAD_ERRORS = "true";

		/**
		 * The default java library path made up of many common paths on different
		 * platforms where libpcap is typically installed.
		 */
		String DEFAULT_JAVA_LIBRARY_PATH = ""
				+ "C:\\Windows\\SysWOW64;"
				+ "C:\\Windows\\System32;"
				+ "C:\\Program Files;"
				+ "/usr/lib/x86_64-linux-gnu;"
				+ "/usr/lib/aarch64-linux-gnu/libpcap.so.0.8;" // Raspberry PI
				+ "/usr/local/Cellar/libpcap/1.10.4/lib;"
				+ "/usr/local/Cellar/libpcap/1.10.3/lib;"
				+ "/usr/local/Cellar/libpcap/1.10.2/lib;"
				+ "/usr/local/Cellar/libpcap/1.10.1/lib;"
				+ "/usr/local/Cellar/libpcap/1.10.0/lib;"
				+ "/usr/local/Cellar/libpcap/1.9.1/lib;"
				+ "/usr/local/Cellar/libpcap/1.9.0/lib;"
				+ "/usr/local/Cellar/libpcap/1.8.1/lib;"
				+ "/usr/local/Cellar/libpcap/1.8.0/lib;"
				+ "/usr/local/Cellar/libpcap/1.7.4/lib;"
				+ "/usr/local/Cellar/libpcap/1.7.3/lib;"
				+ "/usr/local/Cellar/libpcap/1.7.2/lib;"
				+ "/usr/local/Cellar/libpcap/1.6.2/lib;"
				+ "/usr/local/Cellar/libpcap/1.5.3/lib;"
				+ "/usr/local/Cellar/libpcap/1.4.0/lib;"
				+ "/usr/local/Cellar/libpcap/1.3.0/lib;"
				+ "/usr/local/Cellar/libpcap/1.2.0/lib;"
				+ "/usr/local/Cellar/libpcap/1.1.1/lib;"
				+ "/usr/local/Cellar/libpcap/1.0.0/lib;"
				+ "/usr/local/Cellar/libpcap/0.9.8/lib;"
				+ "/opt/local/lib;"
				+ "/opt/napatech3/lib;"
				+ "/lib;"
				+ "/usr/lib";

		/**
		 * The Constant which defines the default logging output which discards all of
		 * its input.
		 */
		public static final Appendable DEFAULT_LOGGING_OUTPUT = PcapForeignInitializer.DEFAULT_LOGGING_OUTPUT;

		/**
		 * Gets the default missing symbols policy.
		 *
		 * @return the default missing symbols policy
		 */
		static LibraryPolicy getDefault() {
			return PcapForeignInitializer.getPolicy();
		}

		/**
		 * Gets the current logging output produced by the default missing symbols
		 * policy receiver. By default the output is sent to
		 * {@code PrintWriter.nullWriter()} which discards all output. You can set
		 * another output consumer or override the policy using
		 * {@link #setDefault(LibraryPolicy)}.
		 *
		 * @return the loggin output receiver
		 */
		static Appendable getLogginOutput() {
			return PcapForeignInitializer.getLogginOutput();
		}

		/**
		 * Sets the default native Pcap library policy.
		 * <p>
		 * Native policy is executed during early/static initialization phase of Pcap
		 * library. The policy object receives a list of symbols both for 'downcall' and
		 * 'upcall' symbols which were not found during loading of the native pcap
		 * libarary. The {@code ForeignInitializer} creates stubs for each missing
		 * symbol, that when called at runtime will throw a safe exception. A missing
		 * symbols policy can intercept missing symbols during initialization phase and
		 * if so desired can throw an appropriate exception, halting any further
		 * initialization. A different policy might simply log an error using
		 * application's logger.
		 * </p>
		 *
		 * @param newPolicy the new default missing symbols policy
		 * @see #setLoggingOutput(Appendable)
		 */
		static void setDefault(LibraryPolicy newPolicy) {
			PcapForeignInitializer.setPolicy(newPolicy);
		}

		/**
		 * Sets the logging output produced by the default native library policy
		 * receiver. By default the output is sent to {@code PrintWriter.nullWriter()}
		 * which discards all output. You can set another output consumer or override
		 * the policy using {@link #setDefault(LibraryPolicy)}.
		 *
		 * @param out the new logging output
		 * @see #setDefault(LibraryPolicy)
		 */
		public static void setLoggingOutput(Appendable out) {
			PcapForeignInitializer.setLoggingOutput(out);
		}

		/**
		 * Calls on the private instanceof {@code ForeignInitializer} to load the native
		 * libpcap library.
		 *
		 * @param ignoreErrors when library loading error occures, the error will be
		 *                     ignore and no exception will be thrown
		 * @return true, if library was loaded successfully or false when
		 *         {@code ignoreErrors} parameter is true and library failed to load
		 */
		default boolean loadNativePcapLibrary(boolean ignoreErrors) {
			return PcapForeignInitializer.loadNativePcapLibrary(ignoreErrors);
		}

		/**
		 * Called when a {@code ForeignInitializer} finishes initializing a class with
		 * native functions.
		 *
		 * @param name                   the name of the {@code ForeignInitializer},
		 *                               usually the name of the class in which it was
		 *                               executed
		 * @param missingDowncallSymbols a list of all missing/unresolved downcall
		 *                               symbols
		 * @param missingUpcallMethods   a list of all missing/unresolved upcall methods
		 * @throws Throwable any exception deemed appropriate by the policy
		 *                   implementation. This method is called during static
		 *                   Initializer phase of class loading, so this exception will
		 *                   be wrapped in the JRE's {@code ExceptionInInitializerError}
		 *                   exception.
		 */
		void onMissingSymbols(String name, List<String> missingDowncallSymbols, List<String> missingUpcallMethods)
				throws Throwable;
	}

	/**
	 * Linux only/specific calls.
	 */
	public static final class Linux extends Pcap.Unix {

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
		public static Linux create(String device) throws PcapException {
			return Pcap1_0.create(Linux::new, device);
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
			return Linux0_9.isSupported();
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
		public static Linux openDead(PcapDlt linktype, int snaplen) throws PcapException {
			return Pcap0_6.openDead(Linux::new, linktype, snaplen);
		}

		/**
		 * Open a fake pcap_t for compiling filters or opening a capture for output.
		 * 
		 * <p>
		 * {@link #openDead(PcapDlt, int)} and
		 * {@link #openDeadWithTstampPrecision(PcapDlt, int, PcapTStampPrecision)} are
		 * used for creating a pcap_t structure to use when calling the other functions
		 * in libpcap. It is typically used when just using libpcap for compiling BPF
		 * full; it can also be used if using {@code #dumpOpen(String)},
		 * {@link PcapDumper#dump(MemorySegment, MemorySegment)}, and
		 * {@link PcapDumper#close()} to write a savefile if there is no pcap_t that
		 * supplies the packets to be written.
		 * </p>
		 * 
		 * <p>
		 * When {@link #openDeadWithTstampPrecision(PcapDlt, int, PcapTStampPrecision)},
		 * is used to create a {@code Pcap} handle for use with
		 * {@link #dumpOpen(String)}, precision specifies the time stamp precision for
		 * packets; PCAP_TSTAMP_PRECISION_MICRO should be specified if the packets to be
		 * written have time stamps in seconds and microseconds, and
		 * PCAP_TSTAMP_PRECISION_NANO should be specified if the packets to be written
		 * have time stamps in seconds and nanoseconds. Its value does not affect
		 * pcap_compile(3PCAP).
		 * </p>
		 *
		 * @param linktype  specifies the link-layer type for the pcap handle
		 * @param snaplen   specifies the snapshot length for the pcap handle
		 * @param precision the requested timestamp precision
		 * @return A dead pcap handle
		 * @throws PcapException any errors
		 * @since libpcap 1.5.1
		 */
		public static Linux openDeadWithTstampPrecision(PcapDlt linktype, int snaplen, PcapTStampPrecision precision)
				throws PcapException {
			return Pcap1_5.openDeadWithTstampPrecision(Linux::new, linktype, snaplen, precision);
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
		public static Linux openLive(String device,
				int snaplen,
				boolean promisc,
				long timeout,
				TimeUnit unit) throws PcapException {

			return Pcap0_4.openLive(Linux::new, device, snaplen, promisc, timeout, unit);
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
		public static Linux openOffline(String fname) throws PcapException {
			return Pcap0_4.openOffline(Linux::new, fname);
		}

		/**
		 * Instantiates a new linux.
		 *
		 * @param pcapHandle the pcap handle
		 * @param name       the name
		 * @param abi        the abi
		 */
		Linux(MemorySegment pcapHandle, String name, PcapHeaderABI abi) {
			super(pcapHandle, name, abi);
		}

		/**
		 * Set capture protocol for a not-yet-activated capture handle.
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
		@Override
		public int setProtocolLinux(int protocol) throws PcapException {
			return super.setProtocolLinux(protocol);
		}
	}

	/**
	 * Unix only/specific calls.
	 */
	public static sealed class Unix extends Pcap1_10 permits Pcap.Linux {

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
		public static Unix create(String device) throws PcapException {
			return Pcap1_0.create(Unix::new, device);
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
			return Unix0_8.isSupported();
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
		public static Unix openDead(PcapDlt linktype, int snaplen) throws PcapException {
			return Pcap0_6.openDead(Unix::new, linktype, snaplen);
		}

		/**
		 * Open a fake pcap_t for compiling filters or opening a capture for output.
		 * 
		 * <p>
		 * {@link #openDead(PcapDlt, int)} and
		 * {@link #openDeadWithTstampPrecision(PcapDlt, int, PcapTStampPrecision)} are
		 * used for creating a pcap_t structure to use when calling the other functions
		 * in libpcap. It is typically used when just using libpcap for compiling BPF
		 * full; it can also be used if using {@code #dumpOpen(String)},
		 * {@link PcapDumper#dump(MemorySegment, MemorySegment)}, and
		 * {@link PcapDumper#close()} to write a savefile if there is no pcap_t that
		 * supplies the packets to be written.
		 * </p>
		 * 
		 * <p>
		 * When {@link #openDeadWithTstampPrecision(PcapDlt, int, PcapTStampPrecision)},
		 * is used to create a {@code Pcap} handle for use with
		 * {@link #dumpOpen(String)}, precision specifies the time stamp precision for
		 * packets; PCAP_TSTAMP_PRECISION_MICRO should be specified if the packets to be
		 * written have time stamps in seconds and microseconds, and
		 * PCAP_TSTAMP_PRECISION_NANO should be specified if the packets to be written
		 * have time stamps in seconds and nanoseconds. Its value does not affect
		 * pcap_compile(3PCAP).
		 * </p>
		 *
		 * @param linktype  specifies the link-layer type for the pcap handle
		 * @param snaplen   specifies the snapshot length for the pcap handle
		 * @param precision the requested timestamp precision
		 * @return A dead pcap handle
		 * @throws PcapException any errors
		 * @since libpcap 1.5.1
		 */
		public static Unix openDeadWithTstampPrecision(PcapDlt linktype, int snaplen, PcapTStampPrecision precision)
				throws PcapException {
			return Pcap1_5.openDeadWithTstampPrecision(Unix::new, linktype, snaplen, precision);
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
		public static Unix openLive(String device,
				int snaplen,
				boolean promisc,
				long timeout,
				TimeUnit unit) throws PcapException {

			return Pcap0_4.openLive(Unix::new, device, snaplen, promisc, timeout, unit);
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
		public static Unix openOffline(String fname) throws PcapException {
			return Pcap0_4.openOffline(Unix::new, fname);
		}

		/**
		 * Instantiates a new unix.
		 *
		 * @param pcapHandle the pcap handle
		 * @param name       the name
		 * @param abi        the abi
		 */
		Unix(MemorySegment pcapHandle, String name, PcapHeaderABI abi) {
			super(pcapHandle, name, abi);
		}

		/**
		 * Gets the selectable fd.
		 *
		 * @return the selectable fd
		 * @throws PcapException the pcap exception
		 * @see org.jnetpcap.Pcap0_8#getSelectableFd()
		 */
		@Override
		public final int getSelectableFd() throws PcapException {
			return super.getSelectableFd();
		}

	}

	/** The jNetPcap API version. */
	public static final String VERSION = "2.3.0";

	static {
		LibraryPolicy policy = LibraryPolicy.getDefault();

		boolean ignoreErrors = Boolean.parseBoolean(System.getProperty(
				LibraryPolicy.SYSTEM_PROPERTY_SO_IGNORE_LOAD_ERRORS,
				LibraryPolicy.DEFAULT_SO_IGNORE_LOAD_ERRORS));

		policy.loadNativePcapLibrary(ignoreErrors);
	}

	/**
	 * Checks runtime version against application version of the java jNetPcap APIs.
	 * <p>
	 * For example {@code Pcap.checkPcapVersion(Pcap.VERSION)} when compiled, the
	 * {@code Pcap.VERSION} will be stored in the application full as a constant and
	 * then compared to the runtime {@code Pcap.VERSION}, also a constant. Both
	 * runtime and application constants will be different as they are compiled at
	 * different times and against, possibly, different versions of the pcap
	 * libarary.
	 * </p>
	 * <p>
	 * This does not perform version checks against the native libpcap library
	 * versions. Only the java jNetPcap API versions.
	 * </p>
	 * <p>
	 * To check for compatibility with specific native library versions, you can
	 * either use {@link Pcap#libVersion()} and do a compare, or try specific
	 * {@code PcapX_Y.isSupported()} calls to get a boolean weather a particular
	 * subclass is supported. Support in version specific classes is done by
	 * checking if a very specific to the version, native library symbol is found. A
	 * missing symbol indicates that the native library is of lower version, which
	 * does not have the symbol defined yet.
	 * </p>
	 *
	 * @param applicationVersion the application version
	 * @throws PcapVersionException the incompatible pcap runtime exception
	 */
	public static void checkPcapVersion(String applicationVersion) throws PcapVersionException {
		PcapVersionException.throwIfVersionMismatch(VERSION, applicationVersion);
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
	@Deprecated(since = "libpcap 1.11.0 API, jNetPcap 2.1.0")
	public static BpFilter compileNoPcap(
			int snaplen,
			PcapDlt pcapDlt,
			String str,
			boolean optimize,
			int netmask) throws PcapException {
		return Pcap0_5.compileNoPcap(snaplen, pcapDlt, str, optimize, netmask);
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
	 * @param device pcap network interface that specifies the network device to
	 *               open.
	 * @return a new pcap object that needs to be activated using
	 *         {@link #activate()} call
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.0
	 */
	public static Pcap create(PcapIf device) throws PcapException {
		return Pcap1_0.create(latest(), device.name());
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
	public static Pcap create(String device) throws PcapException {
		return Pcap1_0.create(latest(), device);
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
		return Pcap0_8.datalinkNameToVal(name);
	}

	/**
	 * link-layer header type. NULL is returned if the type value does not
	 * correspond to a known DLT_ value..
	 *
	 * @param pcapDlt link-layer header type
	 * @return short description of that link-layer header type
	 * @since libpcap 0.8
	 */
	public static String datalinkValToDescription(PcapDlt pcapDlt) {
		return Pcap0_8.dataLinkValToDescription(pcapDlt);
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
	public static String datalinkValToName(PcapDlt pcapDlt) {
		return Pcap0_8.dataLinkValToName(pcapDlt);
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
		return Pcap0_7.findAllDevs();
	}

	/**
	 * Create a list of network devices that can be opened with {@code Pcap#open}.
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
	 * <p>
	 * <em>Warning:</em>
	 * </p>
	 * 
	 * <blockquote>There may be network devices that cannot be opened with
	 * pcap_open() by the process calling pcap_findalldevs(), because, for example,
	 * that process might not have sufficient privileges to open them for capturing;
	 * if so, those devices will not appear on the list.</blockquote>
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
		return Pcap1_9.findAllDevsEx(source, type, username, password);
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
	 * @param opts the opts
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.9
	 */
	public static void init(int opts) throws PcapException {
		Pcap1_0.init(opts);
	}

	/**
	 * Initialize the native <em>libpcap</em> library.
	 * 
	 * <p>
	 * Used to initialize the Packet Capture library. opts specifies options for the
	 * library; currently, the options are:
	 * </p>
	 * 
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
	 * @param option a pcap init option
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.9
	 */
	public static void init(PcapOption option) throws PcapException {
		Pcap1_0.init(option.getAsInt());
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
		return Pcap0_4.isSupported();
	}

	/**
	 * Latest.
	 *
	 * @param <T> the generic type
	 * @return the bi function
	 */
	@SuppressWarnings("unchecked")
	private static <T extends Pcap> PcapSupplier<T> latest() {
		return (pcap, name, abi) -> (T) new Pcap1_10(pcap, name, abi);
	}

	/**
	 * Get the version information for libpcap.
	 *
	 * @return a string giving information about the version of the libpcap library
	 *         being used; note that it contains more information than just a
	 *         version number
	 * @since libpcap 0.8
	 */
	public static String libVersion() {
		return Pcap0_8.libVersion();
	}

	/**
	 * List all pcap if.
	 *
	 * @param next  the next
	 * @param scope the scope
	 * @return the list
	 */
	protected static List<PcapIf> listAllPcapIf(MemorySegment next, Arena scope) {
		return PcapIf.listAll(next, scope);
	}

	/**
	 * Checks if native libpcap library is loaded, and if its not,it will attempt to
	 * load it. If library loading fails, no error messages are reported but
	 * {@code false} will be returned.
	 *
	 * @return true, if is native library was successfully loaded, otherwise false
	 * @see PcapForeignInitializer#loadNativePcapLibrary(boolean)
	 */
	public static boolean loadNativePcapLibrary() {
		return PcapForeignInitializer.loadNativePcapLibrary(true);
	}

	/**
	 * Find the default device on which to capture.
	 * 
	 * <p>
	 * Note: We're deprecating pcap_lookupdev() for various reasons (not
	 * thread-safe, can behave weirdly with WinPcap). Callers should use
	 * pcap_findalldevs() and use the first device.
	 * </p>
	 *
	 * @return a device name
	 * @throws PcapException the pcap exception
	 * @since libpcap 0.4
	 * @deprecated use {@link #findAllDevs()} and use the first device
	 */
	@Deprecated
	public static String lookupDev() throws PcapException {
		return Pcap0_4.lookupDev();
	}

	/**
	 * Static non-pcap utility method to convert libpcap error code to a string, by
	 * various fallback methods with no pcap handle.
	 *
	 * @param error the error
	 * @return the string
	 */
	protected static String lookupErrorString(int error) {
		String msg = statusToStr(error);

		if ((msg == null) || msg.isBlank())
			msg = "code: " + error;

		return msg;
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
	public static NetIp4Address lookupNet(PcapIf device) throws PcapException {
		return Pcap0_4.lookupNet(device.name());
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
		return Pcap0_4.lookupNet(device);
	}

	/**
	 * Min api.
	 *
	 * @param pcapVersion    the pcap version
	 * @param libpcapVersion the libpcap version
	 * @return the string
	 */
	private static String minApi(String pcapVersion, String libpcapVersion) {
		return PcapErrorHandler.getString("pcap.api.min.1").formatted(pcapVersion, libpcapVersion); //$NON-NLS-1$
	}

	/**
	 * New scope.
	 *
	 * @return the memory session
	 */
	protected static Arena newArena() {
		return Arena.ofShared();
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
	 * @since Pcap 1.0
	 */
	public static boolean offlineFilter(BpFilter bpFilter, MemorySegment pktHdr, MemorySegment pktData) {
		return Pcap1_0.offlineFilter(bpFilter, pktHdr, pktData);
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
	public static Pcap openDead(PcapDlt linktype, int snaplen) throws PcapException {
		return Pcap0_6.openDead(latest(), linktype, snaplen);
	}

	/**
	 * Open a fake pcap_t for compiling filters or opening a capture for output.
	 * 
	 * <p>
	 * {@link #openDead(PcapDlt, int)} and
	 * {@link #openDeadWithTstampPrecision(PcapDlt, int, PcapTStampPrecision)} are
	 * used for creating a pcap_t structure to use when calling the other functions
	 * in libpcap. It is typically used when just using libpcap for compiling BPF
	 * full; it can also be used if using {@code #dumpOpen(String)},
	 * {@link PcapDumper#dump(MemorySegment, MemorySegment)}, and
	 * {@link PcapDumper#close()} to write a savefile if there is no pcap_t that
	 * supplies the packets to be written.
	 * </p>
	 * 
	 * <p>
	 * When {@link #openDeadWithTstampPrecision(PcapDlt, int, PcapTStampPrecision)},
	 * is used to create a {@code Pcap} handle for use with
	 * {@link #dumpOpen(String)}, precision specifies the time stamp precision for
	 * packets; PCAP_TSTAMP_PRECISION_MICRO should be specified if the packets to be
	 * written have time stamps in seconds and microseconds, and
	 * PCAP_TSTAMP_PRECISION_NANO should be specified if the packets to be written
	 * have time stamps in seconds and nanoseconds. Its value does not affect
	 * pcap_compile(3PCAP).
	 * </p>
	 *
	 * @param linktype  specifies the link-layer type for the pcap handle
	 * @param snaplen   specifies the snapshot length for the pcap handle
	 * @param precision the requested timestamp precision
	 * @return A dead pcap handle
	 * @throws PcapException any errors
	 * @since libpcap 1.5.1
	 */
	public static Pcap openDeadWithTstampPrecision(PcapDlt linktype, int snaplen, PcapTStampPrecision precision)
			throws PcapException {
		return Pcap1_5.openDeadWithTstampPrecision(latest(), linktype, snaplen, precision);
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
	public static Pcap openLive(PcapIf device,
			int snaplen,
			boolean promisc,
			long timeout,
			TimeUnit unit) throws PcapException {

		return Pcap0_4.openLive(latest(), device.name(), snaplen, promisc, timeout, unit);
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
	public static Pcap openLive(String device,
			int snaplen,
			boolean promisc,
			long timeout,
			TimeUnit unit) throws PcapException {

		return Pcap0_4.openLive(latest(), device, snaplen, promisc, timeout, unit);
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
	 * @param timeout the packet buffer timeout, as a non-negative duration
	 * @return the pcap handle
	 * @throws PcapException any errors
	 * @since libpcap 0.4
	 */
	public static Pcap openLive(String device,
			int snaplen,
			boolean promisc,
			Duration timeout) throws PcapException {

		long nanos = timeout.toMillis();

		return Pcap0_4.openLive(latest(), device, snaplen, promisc, nanos, TimeUnit.NANOSECONDS);
	}

	/**
	 * Open a saved capture file for reading.
	 * 
	 * <p>
	 * pcap_open_offline() and pcap_open_offline_with_tstamp_precision() are called
	 * to open a ``savefile'' for reading.
	 * </p>
	 *
	 * @param file the offline capture file
	 * @return the pcap handle
	 * @throws PcapException any errors
	 * @since libpcap 0.4
	 */
	public static Pcap openOffline(File file) throws PcapException {
		return Pcap0_4.openOffline(latest(), file.getAbsolutePath());
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
	public static Pcap openOffline(String fname) throws PcapException {
		return Pcap0_4.openOffline(latest(), fname);
	}

	/**
	 * Convert an error full value to a string.
	 *
	 * @param error the error full to convert to a string
	 * @return the error string for the given full
	 * @since libpcap 1.0
	 */
	public static String statusToStr(int error) {
		return Pcap1_0.statusToStr(error);
	}

	/**
	 * Convert an error full value to a string.
	 *
	 * @param error the error full to convert to a string
	 * @return the error string for the given full
	 * @since libpcap 1.0
	 */
	public static String statusToStr(PcapCode error) {
		return Pcap1_0.statusToStr(error.getAsInt());
	}

	/**
	 * Convert an error full value to a string. This is a POSIX system error full,
	 * not pcap related as libpcap simply passes the errornum as a system call see
	 * <em>https://linux.die.net/man/3/strerror</em>.
	 *
	 * @param code the code
	 * @return the error string for the given full
	 * @since libpcap 0.4
	 */
	public static String strerror(int code) {
		return Pcap0_4.strerror(code);
	}

	/** The pointer to pointer1. */
	protected final MemorySegment POINTER_TO_POINTER1 = Arena.ofAuto().allocate(ADDRESS);

	/** The pointer to pointer2. */
	protected final MemorySegment POINTER_TO_POINTER2 = Arena.ofAuto().allocate(ADDRESS);

	/** The pointer to pointer3. */
	protected final MemorySegment POINTER_TO_POINTER3 = Arena.ofAuto().allocate(ADDRESS);

	/** The pcap handle or pcap_t * address. */
	private final MemorySegment pcapHandle;

	/**
	 * flag which indicates open/closed status, if true, the pcap address is not
	 * longer valid.
	 */
	protected boolean closed;

	/** The name of this pcap handle. */
	private final String name;

	/** The pcap header ABI. */
	protected final PcapHeaderABI pcapHeaderABI;

	/**
	 * Instantiates a new pcap.
	 *
	 * @param pcapHandle the pcap handle or pcap_t * address.
	 * @param name       the name of this pcap handle.
	 * @param abi        the abi
	 */
	protected Pcap(MemorySegment pcapHandle, String name, PcapHeaderABI abi) {
		this.name = name;
		this.pcapHeaderABI = abi;
		this.pcapHandle = requireNonNull(pcapHandle, "pcapHandle"); //$NON-NLS-1$
	}

	/**
	 * Activate a capture handle
	 * <p>
	 * Is used to activate a packet capture handle to look at packets on the
	 * network, with the options that were set on the handle being in effect.
	 * </p>
	 *
	 * @throws PcapActivatedException thrown if this pcap handle is already
	 *                                activated
	 * @throws PcapException          The possible error values are:
	 *                                <dl>
	 *                                <dt>PCAP_ERROR_ACTIVATED</dt>
	 *                                <dd>The handle has already been activated</dd>
	 *                                <dt>PCAP_ERROR_NO_SUCH_DEVICE</dt>
	 *                                <dd>e capture source specified when the handle
	 *                                was created doesn't exist</dd>
	 *                                <dt>PCAP_ERROR_PERM_DENIED</dt>
	 *                                <dd>The process doesn't have permission to
	 *                                open the capture source</dd>
	 *                                <dt>PCAP_ERROR_PROMISC_PERM_DENIED</dt>
	 *                                <dd>The process has permission to open the
	 *                                capture source but doesn't have permission to
	 *                                put it into promiscuous mode</dd>
	 *                                <dt>PCAP_ERROR_RFMON_NOTSUP</dt>
	 *                                <dd>Monitor mode was specified but the capture
	 *                                source doesn't support monitor mode</dd>
	 *                                <dt>PCAP_ERROR_IFACE_NOT_UP</dt>
	 *                                <dd>The capture source device is not up</dd>
	 *                                <dt>PCAP_ERROR</dt>
	 *                                <dd>Another error occurred</dd>
	 *                                </dl>
	 * @see <a href=
	 *      "https://man7.org/linux/man-pages/man3/pcap_activate.3pcap.html">int
	 *      pcap_activate(pcap_t *)</a>
	 * @since libpcap 1.0
	 */
	public void activate() throws PcapActivatedException, PcapException {
		throw new UnsupportedOperationException(minApi("Pcap1_0", "libpcap 1.0"));
	}

	/**
	 * Force a {@code dispatch} or {@code loop} call to return.
	 * 
	 * <p>
	 * Sets a flag that will force {@code dispatch} or {@code loop} to return rather
	 * than looping; they will return the number of packets that have been processed
	 * so far, or {@link PcapConstants#PCAP_ERROR_BREAK} if no packets have been
	 * processed so far.
	 * </p>
	 * <p>
	 * This routine is safe to use inside a signal handler on UNIX or a console
	 * control handler on Windows, as it merely sets a flag that is checked within
	 * the loop.
	 * </p>
	 * 
	 * <p>
	 * The flag is checked in loops reading packets from the OS - a signal by itself
	 * will not necessarily terminate those loops - as well as in loops processing a
	 * set of packets returned by the OS. Note that if you are catching signals on
	 * UNIX systems that support restarting system calls after a signal, and calling
	 * {@code breakloop} in the signal handler, you must specify, when catching
	 * those signals, that system calls should NOT be restarted by that signal.
	 * Otherwise, if the signal interrupted a call reading packets in a live
	 * capture, when your signal handler returns after calling {@code breakloop},
	 * the call will be restarted, and the loop will not terminate until more
	 * packets arrive and the call completes.
	 * </p>
	 * 
	 * <p>
	 * Note also that, in a multi-threaded application, if one thread is blocked in
	 * {@code dispatch}, {@code loop}, pcap_next(3PCAP), or {@code nextEx}, a call
	 * to {@code breakloop} in a different thread will not unblock that thread. You
	 * will need to use whatever mechanism the OS provides for breaking a thread out
	 * of blocking calls in order to unblock the thread, such as thread cancellation
	 * or thread signalling in systems that support POSIX threads, or SetEvent() on
	 * the result of pcap_getevent() on a pcap_t on which the thread is blocked on
	 * Windows. Asynchronous procedure calls will not work on Windows, as a thread
	 * blocked on a pcap_t will not be in an alertable state.
	 * </p>
	 * 
	 * <p>
	 * Note that {@code next} and {@code nextEx} will, on some platforms, loop
	 * reading packets from the OS; that loop will not necessarily be terminated by
	 * a signal, so {@code breakloop} should be used to terminate packet processing
	 * even if {@code next} or {@code nextEx} is being used.
	 * </p>
	 * 
	 * <p>
	 * {@code breakloop} does not guarantee that no further packets will be
	 * processed by {@code dispatch} or {@code loop} after it is called; at most one
	 * more packet might be processed.
	 * </p>
	 * 
	 * <p>
	 * If {@link PcapConstants#PCAP_ERROR_BREAK} is returned from {@code dispatch}
	 * or {@code loop}, the flag is cleared, so a subsequent call will resume
	 * reading packets. If a positive number is returned, the flag is not cleared,
	 * so a subsequent call will return {@link PcapConstants#PCAP_ERROR_BREAK} and
	 * clear the flag.
	 * </p>
	 *
	 * @since libpcap 0.8
	 */
	public void breakloop() {
		throw new UnsupportedOperationException(minApi("Pcap0_8", "libpcap 0.8"));
	}

	/**
	 * check whether monitor mode can be set for a not-yet-activated capture handle.
	 * 
	 * <p>
	 * Checks whether monitor mode could be set on a capture handle when the handle
	 * is activated.
	 * </p>
	 *
	 * @return true, if rfmon is supported otherwise false
	 * @throws PcapException The possible error values are:
	 *                       <p>
	 *                       PCAP_ERROR_NO_SUCH_DEVICE - The capture source
	 *                       specified when the handle was created doesn't exist
	 *                       </p>
	 *                       <p>
	 *                       PCAP_ERROR_PERM_DENIED - The process doesn't have
	 *                       permission to check whether monitor mode could be
	 *                       supported
	 *                       </p>
	 *                       <p>
	 *                       PCAP_ERROR_ACTIVATED - The capture handle has already
	 *                       been activated
	 *                       </p>
	 *                       <p>
	 *                       PCAP_ERROR - Another error occurred
	 *                       </p>
	 * @since libpcap 1.0
	 */
	public boolean canSetRfmon() throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap1_0", "1.0")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Close a capture device or savefile
	 * 
	 * <p>
	 * Closes the files associated with p and deallocates resources.
	 * </p>
	 * 
	 * @see java.lang.AutoCloseable#close()
	 */
	@Override
	public void close() {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Compile a filter expression without a netmask.
	 * <p>
	 * pcap_compile() is used to compile the string str into a filter program. See
	 * pcap-filter(7) for the syntax of that string. fp is a pointer to a
	 * bpf_program struct and is filled in by pcap_compile(). optimize controls
	 * whether optimization on the resulting full is performed. The netmask of the
	 * network on which packets are being captured isn't known to the program, or if
	 * packets are being captured on the Linux "any" pseudo-interface that can
	 * capture on more than one network, a value of PCAP_NETMASK_UNKNOWN can be
	 * supplied; tests for IPv4 broadcast addresses will fail to compile, but all
	 * other tests in the filter program will be OK.
	 * </p>
	 * <p>
	 * NOTE: in libpcap 1.8.0 and later, pcap_compile() can be used in multiple
	 * threads within a single process. However, in earlier versions of libpcap, it
	 * is not safe to use pcap_compile() in multiple threads in a single process
	 * without some form of mutual exclusion allowing only one thread to call it at
	 * any given time.
	 * </p>
	 *
	 * @param str      filter expression to be compiled
	 * @param optimize controls whether optimization on the resulting full is
	 *                 performed
	 * @return the compiled filter
	 * @throws PcapException any errors
	 * @since Pcap 0.4
	 */
	public BpFilter compile(String str, boolean optimize) throws PcapException {
		return compile(str, optimize, PcapConstants.PCAP_NETMASK_UNKNOWN);
	}

	/**
	 * Compile a filter expression with netmask.
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
	 * @since Pcap 0.4
	 */
	public BpFilter compile(String str, boolean optimize, int netmask) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
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
	public PcapDlt datalink() throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Gets the link-layer header type for the live capture or ``savefile''.
	 *
	 * @return link-layer header type
	 * @throws PcapException the pcap exception
	 */
	public PcapDlt dataLinkExt() throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap1_0", "1.0"));
	}

	/**
	 * Process packets from a live capture or savefile and save them directly to
	 * dump file.
	 * 
	 * <p>
	 * Processes packets from a live capture or ``savefile'' until cnt packets are
	 * processed, the end of the current bufferful of packets is reached when doing
	 * a live capture, the end of the ``savefile'' is reached when reading from a
	 * ``savefile'', pcap_breakloop() is called, or an error occurs. Thus, when
	 * doing a live capture, cnt is the maximum number of packets to process before
	 * returning, but is not a minimum number; when reading a live capture, only one
	 * bufferful of packets is read at a time, so fewer than cnt packets may be
	 * processed. A value of -1 or 0 for cnt causes all the packets received in one
	 * buffer to be processed when reading a live capture, and causes all the
	 * packets in the file to be processed when reading a ``savefile''.
	 * </p>
	 * 
	 * <p>
	 * Note that, when doing a live capture on some platforms, if the read timeout
	 * expires when there are no packets available, pcap_dispatch() will return 0,
	 * even when not in non-blocking mode, as there are no packets to process.
	 * Applications should be prepared for this to happen, but must not rely on it
	 * happening.
	 * </p>
	 * 
	 * <p>
	 * Callback specifies a pcap_handler routine to be called with three arguments:
	 * a u_char pointer which is passed in the user argument to pcap_loop() or
	 * pcap_dispatch(), a const struct pcap_pkthdr pointer pointing to the packet
	 * time stamp and lengths, and a const u_char pointer to the first caplen (as
	 * given in the struct pcap_pkthdr a pointer to which is passed to the callback
	 * routine) bytes of data from the packet. The struct pcap_pkthdr and the packet
	 * data are not to be freed by the callback routine, and are not guaranteed to
	 * be valid after the callback routine returns; if the full needs them to be
	 * valid after the callback, it must make a copy of them.
	 * </p>
	 * 
	 * <p>
	 * The bytes of data from the packet begin with a link-layer header. The format
	 * of the link-layer header is indicated by the return value of the
	 * pcap_datalink(3PCAP) routine when handed the pcap_t value also passed to
	 * pcap_loop() or pcap_dispatch(). https://www.tcpdump.org/linktypes.html lists
	 * the values pcap_datalink() can return and describes the packet formats that
	 * correspond to those values. The value it returns will be valid for all
	 * packets received unless and until pcap_set_datalink(3PCAP) is called; after a
	 * successful call to pcap_set_datalink(), all subsequent packets will have a
	 * link-layer header of the type specified by the link-layer header type value
	 * passed to pcap_set_datalink().
	 * </p>
	 * 
	 * <p>
	 * Do NOT assume that the packets for a given capture or ``savefile`` will have
	 * any given link-layer header type, such as DLT_EN10MB for Ethernet. For
	 * example, the "any" device on Linux will have a link-layer header type of
	 * DLT_LINUX_SLL or DLT_LINUX_SLL2 even if all devices on the system at the time
	 * the "any" device is opened have some other data link type, such as DLT_EN10MB
	 * for Ethernet.
	 * </p>
	 *
	 * @param <U>        the generic type
	 * @param count      maximum number of packets to process before returning
	 * @param pcapDumper the pcap dumper
	 * @return the number of packets processed on success; this can be 0 if no
	 *         packets were read from a live capture (if, for example, they were
	 *         discarded because they didn't pass the packet filter, or if, on
	 *         platforms that support a packet buffer timeout that starts before any
	 *         packets arrive, the timeout expires before any packets arrive, or if
	 *         the file descriptor for the capture device is in non-blocking mode
	 *         and no packets were available to be read) or if no more packets are
	 *         available in a ``savefile.''
	 * @throws PcapException any pcap exceptions during call setup
	 * @since libpcap 0.4
	 */
	public <U> int dispatch(int count, PcapDumper pcapDumper) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Process packets from a live capture or savefile and dispatch using low level
	 * callback. The native callback is low level, and is only capable of passing
	 * native user objects and not compatible with java user objects.
	 * 
	 * <p>
	 * Processes packets from a live capture or ``savefile'' until cnt packets are
	 * processed, the end of the current bufferful of packets is reached when doing
	 * a live capture, the end of the ``savefile'' is reached when reading from a
	 * ``savefile'', pcap_breakloop() is called, or an error occurs. Thus, when
	 * doing a live capture, cnt is the maximum number of packets to process before
	 * returning, but is not a minimum number; when reading a live capture, only one
	 * bufferful of packets is read at a time, so fewer than cnt packets may be
	 * processed. A value of -1 or 0 for cnt causes all the packets received in one
	 * buffer to be processed when reading a live capture, and causes all the
	 * packets in the file to be processed when reading a ``savefile''.
	 * </p>
	 * 
	 * <p>
	 * Note that, when doing a live capture on some platforms, if the read timeout
	 * expires when there are no packets available, pcap_dispatch() will return 0,
	 * even when not in non-blocking mode, as there are no packets to process.
	 * Applications should be prepared for this to happen, but must not rely on it
	 * happening.
	 * </p>
	 * 
	 * <p>
	 * Callback specifies a pcap_handler routine to be called with three arguments:
	 * a u_char pointer which is passed in the user argument to pcap_loop() or
	 * pcap_dispatch(), a const struct pcap_pkthdr pointer pointing to the packet
	 * time stamp and lengths, and a const u_char pointer to the first caplen (as
	 * given in the struct pcap_pkthdr a pointer to which is passed to the callback
	 * routine) bytes of data from the packet. The struct pcap_pkthdr and the packet
	 * data are not to be freed by the callback routine, and are not guaranteed to
	 * be valid after the callback routine returns; if the full needs them to be
	 * valid after the callback, it must make a copy of them.
	 * </p>
	 * 
	 * <p>
	 * The bytes of data from the packet begin with a link-layer header. The format
	 * of the link-layer header is indicated by the return value of the
	 * pcap_datalink(3PCAP) routine when handed the pcap_t value also passed to
	 * pcap_loop() or pcap_dispatch(). https://www.tcpdump.org/linktypes.html lists
	 * the values pcap_datalink() can return and describes the packet formats that
	 * correspond to those values. The value it returns will be valid for all
	 * packets received unless and until pcap_set_datalink(3PCAP) is called; after a
	 * successful call to pcap_set_datalink(), all subsequent packets will have a
	 * link-layer header of the type specified by the link-layer header type value
	 * passed to pcap_set_datalink().
	 * </p>
	 * 
	 * <p>
	 * Do NOT assume that the packets for a given capture or ``savefile`` will have
	 * any given link-layer header type, such as DLT_EN10MB for Ethernet. For
	 * example, the "any" device on Linux will have a link-layer header type of
	 * DLT_LINUX_SLL or DLT_LINUX_SLL2 even if all devices on the system at the time
	 * the "any" device is opened have some other data link type, such as DLT_EN10MB
	 * for Ethernet.
	 * </p>
	 *
	 * @param count   maximum number of packets to process before returning
	 * @param handler the handler
	 * @param user    TODO
	 * @return the number of packets processed on success; this can be 0 if no
	 *         packets were read from a live capture (if, for example, they were
	 *         discarded because they didn't pass the packet filter, or if, on
	 *         platforms that support a packet buffer timeout that starts before any
	 *         packets arrive, the timeout expires before any packets arrive, or if
	 *         the file descriptor for the capture device is in non-blocking mode
	 *         and no packets were available to be read) or if no more packets are
	 *         available in a ``savefile.''
	 * @since libpcap 0.4
	 */
	public int dispatch(int count, PcapHandler.NativeCallback handler, MemorySegment user) {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Process packets from a live capture or savefile and copy to a newly allocated
	 * array and dispatches to handler.
	 * 
	 * <p>
	 * Processes packets from a live capture or ``savefile'' until cnt packets are
	 * processed, the end of the current bufferful of packets is reached when doing
	 * a live capture, the end of the ``savefile'' is reached when reading from a
	 * ``savefile'', pcap_breakloop() is called, or an error occurs. Thus, when
	 * doing a live capture, cnt is the maximum number of packets to process before
	 * returning, but is not a minimum number; when reading a live capture, only one
	 * bufferful of packets is read at a time, so fewer than cnt packets may be
	 * processed. A value of -1 or 0 for cnt causes all the packets received in one
	 * buffer to be processed when reading a live capture, and causes all the
	 * packets in the file to be processed when reading a ``savefile''.
	 * </p>
	 * 
	 * <p>
	 * Note that, when doing a live capture on some platforms, if the read timeout
	 * expires when there are no packets available, pcap_dispatch() will return 0,
	 * even when not in non-blocking mode, as there are no packets to process.
	 * Applications should be prepared for this to happen, but must not rely on it
	 * happening.
	 * </p>
	 * 
	 * <p>
	 * Callback specifies a pcap_handler routine to be called with three arguments:
	 * a u_char pointer which is passed in the user argument to pcap_loop() or
	 * pcap_dispatch(), a const struct pcap_pkthdr pointer pointing to the packet
	 * time stamp and lengths, and a const u_char pointer to the first caplen (as
	 * given in the struct pcap_pkthdr a pointer to which is passed to the callback
	 * routine) bytes of data from the packet. The struct pcap_pkthdr and the packet
	 * data are not to be freed by the callback routine, and are not guaranteed to
	 * be valid after the callback routine returns; if the full needs them to be
	 * valid after the callback, it must make a copy of them.
	 * </p>
	 * 
	 * <p>
	 * The bytes of data from the packet begin with a link-layer header. The format
	 * of the link-layer header is indicated by the return value of the
	 * pcap_datalink(3PCAP) routine when handed the pcap_t value also passed to
	 * pcap_loop() or pcap_dispatch(). https://www.tcpdump.org/linktypes.html lists
	 * the values pcap_datalink() can return and describes the packet formats that
	 * correspond to those values. The value it returns will be valid for all
	 * packets received unless and until pcap_set_datalink(3PCAP) is called; after a
	 * successful call to pcap_set_datalink(), all subsequent packets will have a
	 * link-layer header of the type specified by the link-layer header type value
	 * passed to pcap_set_datalink().
	 * </p>
	 * 
	 * <p>
	 * Do NOT assume that the packets for a given capture or ``savefile`` will have
	 * any given link-layer header type, such as DLT_EN10MB for Ethernet. For
	 * example, the "any" device on Linux will have a link-layer header type of
	 * DLT_LINUX_SLL or DLT_LINUX_SLL2 even if all devices on the system at the time
	 * the "any" device is opened have some other data link type, such as DLT_EN10MB
	 * for Ethernet.
	 * </p>
	 *
	 * @param <U>     the generic type
	 * @param count   maximum number of packets to process before returning
	 * @param handler specifies a handler method to be called
	 * @param user    the user opaque object
	 * @return the number of packets processed on success; this can be 0 if no
	 *         packets were read from a live capture (if, for example, they were
	 *         discarded because they didn't pass the packet filter, or if, on
	 *         platforms that support a packet buffer timeout that starts before any
	 *         packets arrive, the timeout expires before any packets arrive, or if
	 *         the file descriptor for the capture device is in non-blocking mode
	 *         and no packets were available to be read) or if no more packets are
	 *         available in a ``savefile.''
	 * @throws PcapException any pcap exceptions during call setup
	 * @since libpcap 0.4
	 */
	public <U> int dispatch(int count, PcapHandler.OfArray<U> handler, U user) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Process packets from a live capture or savefile and dispatch directly to
	 * handler. The scope of each memory segment dispatched by this call is only
	 * valid for the duration of the dispatch to handler. After that, the packet
	 * memory is reused by libpcap and its contents no longer valid if retained.
	 * 
	 * <p>
	 * Processes packets from a live capture or ``savefile'' until cnt packets are
	 * processed, the end of the current bufferful of packets is reached when doing
	 * a live capture, the end of the ``savefile'' is reached when reading from a
	 * ``savefile'', pcap_breakloop() is called, or an error occurs. Thus, when
	 * doing a live capture, cnt is the maximum number of packets to process before
	 * returning, but is not a minimum number; when reading a live capture, only one
	 * bufferful of packets is read at a time, so fewer than cnt packets may be
	 * processed. A value of -1 or 0 for cnt causes all the packets received in one
	 * buffer to be processed when reading a live capture, and causes all the
	 * packets in the file to be processed when reading a ``savefile''.
	 * </p>
	 * 
	 * <p>
	 * Note that, when doing a live capture on some platforms, if the read timeout
	 * expires when there are no packets available, pcap_dispatch() will return 0,
	 * even when not in non-blocking mode, as there are no packets to process.
	 * Applications should be prepared for this to happen, but must not rely on it
	 * happening.
	 * </p>
	 * 
	 * <p>
	 * Callback specifies a pcap_handler routine to be called with three arguments:
	 * a u_char pointer which is passed in the user argument to pcap_loop() or
	 * pcap_dispatch(), a const struct pcap_pkthdr pointer pointing to the packet
	 * time stamp and lengths, and a const u_char pointer to the first caplen (as
	 * given in the struct pcap_pkthdr a pointer to which is passed to the callback
	 * routine) bytes of data from the packet. The struct pcap_pkthdr and the packet
	 * data are not to be freed by the callback routine, and are not guaranteed to
	 * be valid after the callback routine returns; if the full needs them to be
	 * valid after the callback, it must make a copy of them.
	 * </p>
	 * 
	 * <p>
	 * The bytes of data from the packet begin with a link-layer header. The format
	 * of the link-layer header is indicated by the return value of the
	 * pcap_datalink(3PCAP) routine when handed the pcap_t value also passed to
	 * pcap_loop() or pcap_dispatch(). https://www.tcpdump.org/linktypes.html lists
	 * the values pcap_datalink() can return and describes the packet formats that
	 * correspond to those values. The value it returns will be valid for all
	 * packets received unless and until pcap_set_datalink(3PCAP) is called; after a
	 * successful call to pcap_set_datalink(), all subsequent packets will have a
	 * link-layer header of the type specified by the link-layer header type value
	 * passed to pcap_set_datalink().
	 * </p>
	 * 
	 * <p>
	 * Do NOT assume that the packets for a given capture or ``savefile`` will have
	 * any given link-layer header type, such as DLT_EN10MB for Ethernet. For
	 * example, the "any" device on Linux will have a link-layer header type of
	 * DLT_LINUX_SLL or DLT_LINUX_SLL2 even if all devices on the system at the time
	 * the "any" device is opened have some other data link type, such as DLT_EN10MB
	 * for Ethernet.
	 * </p>
	 *
	 * @param <U>     the generic type
	 * @param count   maximum number of packets to process before returning
	 * @param handler specifies a handler method to be called
	 * @param user    the user opaque object
	 * @return the number of packets processed on success; this can be 0 if no
	 *         packets were read from a live capture (if, for example, they were
	 *         discarded because they didn't pass the packet filter, or if, on
	 *         platforms that support a packet buffer timeout that starts before any
	 *         packets arrive, the timeout expires before any packets arrive, or if
	 *         the file descriptor for the capture device is in non-blocking mode
	 *         and no packets were available to be read) or if no more packets are
	 *         available in a ``savefile.''
	 * @throws PcapException any pcap exceptions during call setup
	 * @since libpcap 0.4
	 */
	public <U> int dispatch(int count, PcapHandler.OfMemorySegment<U> handler, U user) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Open a file to which to write packets.
	 * <p>
	 * pcap_dump_open() is called to open a ``savefile'' for writing. fname
	 * specifies the name of the file to open. The file will have the same format as
	 * those used by tcpdump(1) and tcpslice(1). If the file does not exist, it will
	 * be created; if the file exists, it will be truncated and overwritten. The
	 * name "-" is a synonym for stdout. pcap_dump_fopen() is called to write data
	 * to an existing open stream fp; this stream will be closed by a subsequent
	 * call to pcap_dump_close(3PCAP). The stream is assumed to be at the beginning
	 * of a file that has been newly created or truncated, so that writes will start
	 * at the beginning of the file. Note that on Windows, that stream should be
	 * opened in binary mode.
	 * </p>
	 * <p>
	 * p is a capture or ``savefile'' handle returned by an earlier call to
	 * pcap_create(3PCAP) and activated by an earlier call to pcap_activate(3PCAP),
	 * or returned by an earlier call to pcap_open_offline(3PCAP),
	 * pcap_open_live(3PCAP), or pcap_open_dead(3PCAP). The time stamp precision,
	 * link-layer type, and snapshot length from p are used as the link-layer type
	 * and snapshot length of the output file.
	 * </p>
	 * <p>
	 * pcap_dump_open_append() is like pcap_dump_open() but, if the file already
	 * exists, and is a pcap file with the same byte order as the host opening the
	 * file, and has the same time stamp precision, link-layer header type, and
	 * snapshot length as p, it will write new packets at the end of the file.
	 * </p>
	 * 
	 * @param fname the fname
	 * @return the pcap dumper
	 * @throws PcapException the pcap exception
	 * @since libpcap 0.4
	 */
	public PcapDumper dumpOpen(String fname) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "libpcap 4.0"));
	}

	/**
	 * Get libpcap error message text.
	 *
	 * @return the error text pertaining to the last pcap library error
	 * @since libpcap 0.4
	 */
	public String geterr() {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Dynamic non-pcap utility method to convert libpcap error code to a string, by
	 * various fallback methods with an active pcap handle.
	 *
	 * @param error the code
	 * @return the error string
	 */
	protected String getErrorString(int error) {
		String msg = this.geterr();

		if ((msg == null) || msg.isBlank())
			msg = lookupErrorString(error);

		return msg;
	}

	/**
	 * Gets the name of this pcap handle. The name by default is the offline
	 * filename or network interface name, if specified.
	 *
	 * @return the name of this pcap handle
	 */
	public final String getName() {
		return name;
	}

	/**
	 * Gets the state of non-blocking mode on a capture device.
	 *
	 * <p>
	 * pcap_setnonblock() puts a capture handle into ``non-blocking'' mode, or takes
	 * it out of ``non-blocking'' mode, depending on whether the nonblock argument
	 * is non-zero or zero. It has no effect on ``savefiles''. If there is an error,
	 * PCAP_ERROR is returned and errbuf is filled in with an appropriate error
	 * message; otherwise, 0 is returned. In ``non-blocking'' mode, an attempt to
	 * read from the capture descriptor with pcap_dispatch(3PCAP) and
	 * pcap_next_ex(3PCAP) will, if no packets are currently available to be read,
	 * return 0 immediately rather than blocking waiting for packets to arrive.
	 * </p>
	 * 
	 * <p>
	 * pcap_loop(3PCAP) will loop forever, consuming CPU time when no packets are
	 * currently available; pcap_dispatch() should be used instead. pcap_next(3PCAP)
	 * will return NULL if there are no packets currently available to read; this is
	 * indistinguishable from an error, so pcap_next_ex() should be used instead.
	 * </p>
	 * 
	 * <p>
	 * When first activated with pcap_activate(3PCAP) or opened with
	 * pcap_open_live(3PCAP), a capture handle is not in ``non-blocking mode''; a
	 * call to pcap_setnonblock() is required in order to put it into
	 * ``non-blocking'' mode.
	 * </p>
	 * 
	 * @return the non block
	 * @throws PcapException any pcap errors
	 * @since libpcap 0.7
	 */
	public boolean getNonBlock() throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_7", "0.7"));
	}

	/**
	 * Gets the pcap handle's memory address.
	 *
	 * @return the pcap handle
	 */
	protected MemorySegment getPcapHandle() {
		if (closed)
			throw new IllegalStateException("already closed");

		return pcapHandle;
	}

	/**
	 * Get the time stamp precision returned in captures.
	 * 
	 * <p>
	 * Returns the precision of the time stamp returned in packet captures on the
	 * pcap descriptor.
	 * </p>
	 *
	 * @return returns PCAP_TSTAMP_PRECISION_MICRO or PCAP_TSTAMP_PRECISION_NANO,
	 *         which indicates that pcap captures contains time stamps in
	 *         microseconds or nanoseconds respectively
	 * @throws PcapException any pcap errors
	 * @since libpcap 1.5
	 */
	public PcapTStampPrecision getTstampPrecision() throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap1_5", "1.5")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Transmit a packet.
	 * <p>
	 * pcap_inject() sends a raw packet through the network interface; buf points to
	 * the data of the packet, including the link-layer header, and size is the
	 * number of bytes in the packet. Note that, even if you successfully open the
	 * network interface, you might not have permission to send packets on it, or it
	 * might not support sending packets; as pcap_open_live(3PCAP) doesn't have a
	 * flag to indicate whether to open for capturing, sending, or capturing and
	 * sending, you cannot request an open that supports sending and be notified at
	 * open time whether sending will be possible. Note also that some devices might
	 * not support sending packets.
	 * </p>
	 * <p>
	 * Note that, on some platforms, the link-layer header of the packet that's sent
	 * might not be the same as the link-layer header of the packet supplied to
	 * pcap_inject(), as the source link-layer address, if the header contains such
	 * an address, might be changed to be the address assigned to the interface on
	 * which the packet it sent, if the platform doesn't support sending completely
	 * raw and unchanged packets. Even worse, some drivers on some platforms might
	 * change the link-layer type field to whatever value libpcap used when
	 * attaching to the device, even on platforms that do nominally support sending
	 * completely raw and unchanged packets.
	 * </p>
	 * <p>
	 * pcap_sendpacket() is like pcap_inject(), but it returns 0 on success, rather
	 * than returning the number of bytes written. (pcap_inject() comes from
	 * OpenBSD; pcap_sendpacket() comes from WinPcap/Npcap. Both are provided for
	 * compatibility.)
	 * </p>
	 *
	 * @param packet the packet
	 * @param length the packet length
	 * @return number of bytes written
	 * @throws PcapException the pcap exception
	 * @since libpcap 0.9
	 */
	public int inject(MemorySegment packet, int length) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_9", "0.9"));
	}

	/**
	 * Transmit a packet.
	 * <p>
	 * pcap_inject() sends a raw packet through the network interface; buf points to
	 * the data of the packet, including the link-layer header, and size is the
	 * number of bytes in the packet. Note that, even if you successfully open the
	 * network interface, you might not have permission to send packets on it, or it
	 * might not support sending packets; as pcap_open_live(3PCAP) doesn't have a
	 * flag to indicate whether to open for capturing, sending, or capturing and
	 * sending, you cannot request an open that supports sending and be notified at
	 * open time whether sending will be possible. Note also that some devices might
	 * not support sending packets.
	 * </p>
	 * <p>
	 * Note that, on some platforms, the link-layer header of the packet that's sent
	 * might not be the same as the link-layer header of the packet supplied to
	 * pcap_inject(), as the source link-layer address, if the header contains such
	 * an address, might be changed to be the address assigned to the interface on
	 * which the packet it sent, if the platform doesn't support sending completely
	 * raw and unchanged packets. Even worse, some drivers on some platforms might
	 * change the link-layer type field to whatever value libpcap used when
	 * attaching to the device, even on platforms that do nominally support sending
	 * completely raw and unchanged packets.
	 * </p>
	 * <p>
	 * pcap_sendpacket() is like pcap_inject(), but it returns 0 on success, rather
	 * than returning the number of bytes written. (pcap_inject() comes from
	 * OpenBSD; pcap_sendpacket() comes from WinPcap/Npcap. Both are provided for
	 * compatibility.)
	 * </p>
	 *
	 * @param array the array containing packet data, including the datalink layer
	 * @return number of bytes written
	 * @throws PcapException the pcap exception
	 */
	public final int inject(byte[] array) throws PcapException {
		return inject(array, 0, array.length);
	}

	/**
	 * Transmit a packet.
	 * <p>
	 * pcap_inject() sends a raw packet through the network interface; buf points to
	 * the data of the packet, including the link-layer header, and size is the
	 * number of bytes in the packet. Note that, even if you successfully open the
	 * network interface, you might not have permission to send packets on it, or it
	 * might not support sending packets; as pcap_open_live(3PCAP) doesn't have a
	 * flag to indicate whether to open for capturing, sending, or capturing and
	 * sending, you cannot request an open that supports sending and be notified at
	 * open time whether sending will be possible. Note also that some devices might
	 * not support sending packets.
	 * </p>
	 * <p>
	 * Note that, on some platforms, the link-layer header of the packet that's sent
	 * might not be the same as the link-layer header of the packet supplied to
	 * pcap_inject(), as the source link-layer address, if the header contains such
	 * an address, might be changed to be the address assigned to the interface on
	 * which the packet it sent, if the platform doesn't support sending completely
	 * raw and unchanged packets. Even worse, some drivers on some platforms might
	 * change the link-layer type field to whatever value libpcap used when
	 * attaching to the device, even on platforms that do nominally support sending
	 * completely raw and unchanged packets.
	 * </p>
	 * <p>
	 * pcap_sendpacket() is like pcap_inject(), but it returns 0 on success, rather
	 * than returning the number of bytes written. (pcap_inject() comes from
	 * OpenBSD; pcap_sendpacket() comes from WinPcap/Npcap. Both are provided for
	 * compatibility.)
	 * </p>
	 *
	 * @param array  the array containing packet data, including the datalink layer
	 * @param offset the offset into the byte array
	 * @param length the packet length
	 * @return number of bytes written
	 * @throws PcapException the pcap exception
	 */
	public final int inject(byte[] array, int offset, int length) throws PcapException {
		try (var scope = newArena()) {
			MemorySegment mseg = scope.allocate(length);

			MemorySegment.copy(array, offset, mseg, ValueLayout.JAVA_BYTE, 0, length);

			return inject(mseg, length);
		}
	}

	/**
	 * Transmit a packet.
	 * <p>
	 * pcap_inject() sends a raw packet through the network interface; buf points to
	 * the data of the packet, including the link-layer header, and size is the
	 * number of bytes in the packet. Note that, even if you successfully open the
	 * network interface, you might not have permission to send packets on it, or it
	 * might not support sending packets; as pcap_open_live(3PCAP) doesn't have a
	 * flag to indicate whether to open for capturing, sending, or capturing and
	 * sending, you cannot request an open that supports sending and be notified at
	 * open time whether sending will be possible. Note also that some devices might
	 * not support sending packets.
	 * </p>
	 * <p>
	 * Note that, on some platforms, the link-layer header of the packet that's sent
	 * might not be the same as the link-layer header of the packet supplied to
	 * pcap_inject(), as the source link-layer address, if the header contains such
	 * an address, might be changed to be the address assigned to the interface on
	 * which the packet it sent, if the platform doesn't support sending completely
	 * raw and unchanged packets. Even worse, some drivers on some platforms might
	 * change the link-layer type field to whatever value libpcap used when
	 * attaching to the device, even on platforms that do nominally support sending
	 * completely raw and unchanged packets.
	 * </p>
	 * <p>
	 * pcap_sendpacket() is like pcap_inject(), but it returns 0 on success, rather
	 * than returning the number of bytes written. (pcap_inject() comes from
	 * OpenBSD; pcap_sendpacket() comes from WinPcap/Npcap. Both are provided for
	 * compatibility.)
	 * </p>
	 *
	 * @param buf The packet starts relative to the buffer's position (inclusive)
	 *            and ends relative to the buffer's limit (exclusive)
	 * @return number of bytes written
	 * @throws PcapException the pcap exception
	 */
	public final int inject(ByteBuffer buf) throws PcapException {
		if (buf.hasArray()) {
			return inject(buf.array(), buf.arrayOffset() + buf.position(), buf.remaining());

		} else {
			MemorySegment mseg = MemorySegment.ofBuffer(buf);

			return inject(mseg, buf.remaining());
		}
	}

	/**
	 * Find out whether a savefile has the native byte order.
	 * 
	 * <p>
	 * Returns true if pcap refers to a ``savefile'' that uses a different byte
	 * order than the current system. For a live capture, it always returns false.
	 * </p>
	 *
	 * @return true if swapped, otherwise false
	 * @throws PcapException any pcap errors
	 * @see #order()
	 * @since libpcap 0.4
	 */
	public boolean isSwapped() throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Get a list of link-layer header types supported by a capture device.
	 *
	 * @return a list of link-layer header types
	 * @throws PcapException any pcap errors
	 * @since libpcap 0.8
	 */
	public List<PcapDlt> listDataLinks() throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_8", "0.8")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Get a list of time stamp types supported by a capture device.
	 * <p>
	 * pcap_list_tstamp_types() is used to get a list of the supported time stamp
	 * types of the interface associated with the pcap descriptor
	 * </p>
	 *
	 * @return a list of timestamp types
	 * @throws PcapException any pcap errors
	 * @since libpcap 1.2
	 */
	public List<PcapTstampType> listTstampTypes() throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap1_2", "1.2")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Process packets from a live capture or savefile and save them directly to
	 * dump file.
	 * <p>
	 * pcap_loop() processes packets from a live capture or ``savefile'' until cnt
	 * packets are processed, the end of the ``savefile'' is reached when reading
	 * from a ``savefile'', pcap_breakloop(3PCAP) is called, or an error occurs. It
	 * does not return when live packet buffer timeouts occur. A value of -1 or 0
	 * for cnt is equivalent to infinity, so that packets are processed until
	 * another ending condition occurs.
	 * </p>
	 * <p>
	 * Note that, when doing a live capture on some platforms, if the read timeout
	 * expires when there are no packets available, pcap_dispatch() will return 0,
	 * even when not in non-blocking mode, as there are no packets to process.
	 * Applications should be prepared for this to happen, but must not rely on it
	 * happening.
	 * </p>
	 * <p>
	 * callback specifies a pcap_handler routine to be called with three arguments:
	 * a u_char pointer which is passed in the user argument to pcap_loop() or
	 * pcap_dispatch(), a const struct pcap_pkthdr pointer pointing to the packet
	 * time stamp and lengths, and a const u_char pointer to the first caplen (as
	 * given in the struct pcap_pkthdr a pointer to which is passed to the callback
	 * routine) bytes of data from the packet. The struct pcap_pkthdr and the packet
	 * data are not to be freed by the callback routine, and are not guaranteed to
	 * be valid after the callback routine returns; if the full needs them to be
	 * valid after the callback, it must make a copy of them.
	 * </p>
	 * <p>
	 * The bytes of data from the packet begin with a link-layer header. The format
	 * of the link-layer header is indicated by the return value of the
	 * pcap_datalink(3PCAP) routine when handed the pcap_t value also passed to
	 * pcap_loop() or pcap_dispatch(). https://www.tcpdump.org/linktypes.html lists
	 * the values pcap_datalink() can return and describes the packet formats that
	 * correspond to those values. The value it returns will be valid for all
	 * packets received unless and until pcap_set_datalink(3PCAP) is called; after a
	 * successful call to pcap_set_datalink(), all subsequent packets will have a
	 * link-layer header of the type specified by the link-layer header type value
	 * passed to pcap_set_datalink().
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
	 * @param <U>        the generic user data type
	 * @param count      A value of -1 or 0 for count is equivalent to infinity, so
	 *                   that packets are processed until another ending condition
	 *                   occurs
	 * @param pcapDumper the pcap dumper
	 * @return returns 0 if count is exhausted or if, when reading from a
	 *         ``savefile'', no more packets are available. It returns
	 *         PCAP_ERROR_BREAK if the loop terminated due to a call to
	 *         pcap_breakloop() before any packets were processed
	 * @throws PcapException any pcap errors
	 * @since libpcap 0.4
	 */
	public <U> int loop(int count, PcapDumper pcapDumper) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Process packets from a live capture or savefile and dispatch using low level
	 * callback. The native callback is low level, and is only capable of passing
	 * native user objects and not compatible with java user objects.
	 * 
	 * <p>
	 * pcap_loop() processes packets from a live capture or ``savefile'' until cnt
	 * packets are processed, the end of the ``savefile'' is reached when reading
	 * from a ``savefile'', pcap_breakloop(3PCAP) is called, or an error occurs. It
	 * does not return when live packet buffer timeouts occur. A value of -1 or 0
	 * for cnt is equivalent to infinity, so that packets are processed until
	 * another ending condition occurs.
	 * </p>
	 * <p>
	 * Note that, when doing a live capture on some platforms, if the read timeout
	 * expires when there are no packets available, pcap_dispatch() will return 0,
	 * even when not in non-blocking mode, as there are no packets to process.
	 * Applications should be prepared for this to happen, but must not rely on it
	 * happening.
	 * </p>
	 * <p>
	 * callback specifies a pcap_handler routine to be called with three arguments:
	 * a u_char pointer which is passed in the user argument to pcap_loop() or
	 * pcap_dispatch(), a const struct pcap_pkthdr pointer pointing to the packet
	 * time stamp and lengths, and a const u_char pointer to the first caplen (as
	 * given in the struct pcap_pkthdr a pointer to which is passed to the callback
	 * routine) bytes of data from the packet. The struct pcap_pkthdr and the packet
	 * data are not to be freed by the callback routine, and are not guaranteed to
	 * be valid after the callback routine returns; if the full needs them to be
	 * valid after the callback, it must make a copy of them.
	 * </p>
	 * <p>
	 * The bytes of data from the packet begin with a link-layer header. The format
	 * of the link-layer header is indicated by the return value of the
	 * pcap_datalink(3PCAP) routine when handed the pcap_t value also passed to
	 * pcap_loop() or pcap_dispatch(). https://www.tcpdump.org/linktypes.html lists
	 * the values pcap_datalink() can return and describes the packet formats that
	 * correspond to those values. The value it returns will be valid for all
	 * packets received unless and until pcap_set_datalink(3PCAP) is called; after a
	 * successful call to pcap_set_datalink(), all subsequent packets will have a
	 * link-layer header of the type specified by the link-layer header type value
	 * passed to pcap_set_datalink().
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
	 * @param <U>     the generic user data type
	 * @param count   A value of -1 or 0 for count is equivalent to infinity, so
	 *                that packets are processed until another ending condition
	 *                occurs
	 * @param handler the native handler which receives packets
	 * @param user    native user object
	 * @return returns 0 if count is exhausted or if, when reading from a
	 *         ``savefile'', no more packets are available. It returns
	 *         PCAP_ERROR_BREAK if the loop terminated due to a call to
	 *         pcap_breakloop() before any packets were processed
	 * @since libpcap 0.4
	 */
	public <U> int loop(int count, PcapHandler.NativeCallback handler, MemorySegment user) {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Process packets from a live capture or savefile and copy to a newly allocated
	 * array and dispatches to handler.
	 * 
	 * <p>
	 * pcap_loop() processes packets from a live capture or ``savefile'' until cnt
	 * packets are processed, the end of the ``savefile'' is reached when reading
	 * from a ``savefile'', pcap_breakloop(3PCAP) is called, or an error occurs. It
	 * does not return when live packet buffer timeouts occur. A value of -1 or 0
	 * for cnt is equivalent to infinity, so that packets are processed until
	 * another ending condition occurs.
	 * </p>
	 * <p>
	 * Note that, when doing a live capture on some platforms, if the read timeout
	 * expires when there are no packets available, pcap_dispatch() will return 0,
	 * even when not in non-blocking mode, as there are no packets to process.
	 * Applications should be prepared for this to happen, but must not rely on it
	 * happening.
	 * </p>
	 * <p>
	 * callback specifies a pcap_handler routine to be called with three arguments:
	 * a u_char pointer which is passed in the user argument to pcap_loop() or
	 * pcap_dispatch(), a const struct pcap_pkthdr pointer pointing to the packet
	 * time stamp and lengths, and a const u_char pointer to the first caplen (as
	 * given in the struct pcap_pkthdr a pointer to which is passed to the callback
	 * routine) bytes of data from the packet. The struct pcap_pkthdr and the packet
	 * data are not to be freed by the callback routine, and are not guaranteed to
	 * be valid after the callback routine returns; if the full needs them to be
	 * valid after the callback, it must make a copy of them.
	 * </p>
	 * <p>
	 * The bytes of data from the packet begin with a link-layer header. The format
	 * of the link-layer header is indicated by the return value of the
	 * pcap_datalink(3PCAP) routine when handed the pcap_t value also passed to
	 * pcap_loop() or pcap_dispatch(). https://www.tcpdump.org/linktypes.html lists
	 * the values pcap_datalink() can return and describes the packet formats that
	 * correspond to those values. The value it returns will be valid for all
	 * packets received unless and until pcap_set_datalink(3PCAP) is called; after a
	 * successful call to pcap_set_datalink(), all subsequent packets will have a
	 * link-layer header of the type specified by the link-layer header type value
	 * passed to pcap_set_datalink().
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
	 * @param <U>     the generic user data type
	 * @param count   A value of -1 or 0 for count is equivalent to infinity, so
	 *                that packets are processed until another ending condition
	 *                occurs
	 * @param handler array handler which will receive packets
	 * @param user    user opaque data to be returned with the callback
	 * @return returns 0 if count is exhausted or if, when reading from a
	 *         ``savefile'', no more packets are available. It returns
	 *         PCAP_ERROR_BREAK if the loop terminated due to a call to
	 *         pcap_breakloop() before any packets were processed
	 * @throws PcapException any pcap errors
	 * @since libpcap 0.4
	 */
	public <U> int loop(int count, PcapHandler.OfArray<U> handler, U user) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Process packets from a live capture or savefile and dispatch directly to
	 * handler. The scope of each memory segment dispatched by this call is only
	 * valid for the duration of the dispatch to handler. After that, the packet
	 * memory is reused by libpcap and its contents no longer valid if retained.
	 * 
	 * <p>
	 * pcap_loop() processes packets from a live capture or ``savefile'' until cnt
	 * packets are processed, the end of the ``savefile'' is reached when reading
	 * from a ``savefile'', pcap_breakloop(3PCAP) is called, or an error occurs. It
	 * does not return when live packet buffer timeouts occur. A value of -1 or 0
	 * for cnt is equivalent to infinity, so that packets are processed until
	 * another ending condition occurs.
	 * </p>
	 * <p>
	 * Note that, when doing a live capture on some platforms, if the read timeout
	 * expires when there are no packets available, pcap_dispatch() will return 0,
	 * even when not in non-blocking mode, as there are no packets to process.
	 * Applications should be prepared for this to happen, but must not rely on it
	 * happening.
	 * </p>
	 * <p>
	 * callback specifies a pcap_handler routine to be called with three arguments:
	 * a u_char pointer which is passed in the user argument to pcap_loop() or
	 * pcap_dispatch(), a const struct pcap_pkthdr pointer pointing to the packet
	 * time stamp and lengths, and a const u_char pointer to the first caplen (as
	 * given in the struct pcap_pkthdr a pointer to which is passed to the callback
	 * routine) bytes of data from the packet. The struct pcap_pkthdr and the packet
	 * data are not to be freed by the callback routine, and are not guaranteed to
	 * be valid after the callback routine returns; if the full needs them to be
	 * valid after the callback, it must make a copy of them.
	 * </p>
	 * <p>
	 * The bytes of data from the packet begin with a link-layer header. The format
	 * of the link-layer header is indicated by the return value of the
	 * pcap_datalink(3PCAP) routine when handed the pcap_t value also passed to
	 * pcap_loop() or pcap_dispatch(). https://www.tcpdump.org/linktypes.html lists
	 * the values pcap_datalink() can return and describes the packet formats that
	 * correspond to those values. The value it returns will be valid for all
	 * packets received unless and until pcap_set_datalink(3PCAP) is called; after a
	 * successful call to pcap_set_datalink(), all subsequent packets will have a
	 * link-layer header of the type specified by the link-layer header type value
	 * passed to pcap_set_datalink().
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
	 * @param <U>     the generic type
	 * @param count   A value of -1 or 0 for count is equivalent to infinity, so
	 *                that packets are processed until another ending condition
	 *                occurs
	 * @param handler array handler which will receive packets
	 * @param user    the user opaque java object
	 * @return returns 0 if count is exhausted or if, when reading from a
	 *         ``savefile'', no more packets are available. It returns
	 *         PCAP_ERROR_BREAK if the loop terminated due to a call to
	 *         pcap_breakloop() before any packets were processed
	 * @since libpcap 0.4
	 */
	public <U> int loop(int count, PcapHandler.OfMemorySegment<U> handler, U user) {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Get the version number of a savefile.
	 * <p>
	 * If p refers to a ``savefile'', {@code majorVersion} returns the major number
	 * of the file format of the ``savefile''. The version number is stored in the
	 * ``savefile''; note that the meaning of its values depends on the type of
	 * ``savefile'' (for example, pcap or pcapng).
	 * </p>
	 * <p>
	 * If pcap handle refers to a live capture, the values returned by
	 * {@code majorVersion} and pcap_minor_version() are not meaningful.
	 * </p>
	 *
	 * @return the major number of the file format of the ``savefile''
	 * @throws PcapException the pcap exception
	 */
	public int majorVersion() throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Get the version number of a savefile.
	 * <p>
	 * If p refers to a ``savefile'', {@code minorVersion} returns the minor number
	 * of the file format of the ``savefile''. The version number is stored in the
	 * ``savefile''; note that the meaning of its values depends on the type of
	 * ``savefile'' (for example, pcap or pcapng).
	 * </p>
	 * <p>
	 * If pcap handle refers to a live capture, the values returned by
	 * {@code majorVersion} and pcap_minor_version() are not meaningful.
	 * </p>
	 *
	 * @return the minor number of the file format of the ``savefile''
	 * @throws PcapException the pcap exception
	 */
	public int minorVersion() throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * read the next packet from a handle.
	 * 
	 * <p>
	 * reads the next packet (by calling dispatch with a cnt of 1) and returns a
	 * u_char pointer to the data in that packet. The packet data is not to be freed
	 * by the caller, and is not guaranteed to be valid after the next call to
	 * nextEx, next, loop, or dispatch; if the full needs it to remain valid, it
	 * must make a copy of it. The pcap_pkthdr structure pointed to by h is filled
	 * in with the appropriate values for the packet.
	 * </p>
	 * 
	 * <p>
	 * The bytes of data from the packet begin with a link-layer header. The format
	 * of the link-layer header is indicated by the return value of the
	 * {@code datalink} routine when handed the pcap_t value also passed to
	 * {@code loop} or {@code dispatch}. https://www.tcpdump.org/linktypes.html
	 * lists the values {@code datalink} can return and describes the packet formats
	 * that correspond to those values. The value it returns will be valid for all
	 * packets received unless and until {@code setDatalink} is called; after a
	 * successful call to {@code setDatalink}, all subsequent packets will have a
	 * link-layer header of the type specified by the link-layer header type value
	 * passed to {@code setDatalink}.
	 * </p>
	 * 
	 * <p>
	 * Do NOT assume that the packets for a given capture or ``savefile`` will have
	 * any given link-layer header type, such as DLT_EN10MB for Ethernet. For
	 * example, the "any" device on Linux will have a link-layer header type of
	 * DLT_LINUX_SLL or DLT_LINUX_SLL2 even if all devices on the system at the time
	 * the "any" device is opened have some other data link type, such as DLT_EN10MB
	 * for Ethernet.
	 * </p>
	 *
	 * @return a pointer to the packet data on success, and returns NULL if no
	 *         packets were read from a live capture (if, for example, they were
	 *         discarded because they didn't pass the packet filter, or if, on
	 *         platforms that support a packet buffer timeout that starts before any
	 *         packets arrive, the timeout expires before any packets arrive, or if
	 *         the file descriptor for the capture device is in non-blocking mode
	 *         and no packets were available to be read), or if no more packets are
	 *         available in a ``savefile.'' Unfortunately, there is no way to
	 *         determine whether an error occurred or not.
	 * @throws PcapException Unfortunately, there is no way to determine whether an
	 *                       error occurred or not so exception may be due to no
	 *                       packets being captured and not an actual error.
	 * @since libpcap 0.4
	 */
	public PcapPacketRef next() throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Read the next packet from a pcap handle.
	 * <p>
	 * reads the next packet and returns a success/failure indication. If the packet
	 * was read without problems, the pointer pointed to by the pktHeader argument
	 * is set to point to the pcap_pkthdr struct for the packet, and the pointer
	 * pointed to by the pktData argument is set to point to the data in the packet.
	 * The struct pcap_pkthdr and the packet data are not to be freed by the caller,
	 * and are not guaranteed to be valid after the next call to {@link #nextEx},
	 * {@link #next}, {@link #loop}, or {@link #dispatch}; if the full needs them to
	 * remain valid, it must make a copy of them. *
	 * </p>
	 * <p>
	 * The bytes of data from the packet begin with a link-layer header. The format
	 * of the link-layer header is indicated by the return value of the
	 * {@code datalink} routine when handed the pcap_t value also passed to
	 * {@code loop} or {@code dispatch}. https://www.tcpdump.org/linktypes.html
	 * lists the values {@code datalink} can return and describes the packet formats
	 * that correspond to those values. The value it returns will be valid for all
	 * packets received unless and until {@code setDatalink} is called; after a
	 * successful call to {@code setDatalink}, all subsequent packets will have a
	 * link-layer header of the type specified by the link-layer header type value
	 * passed to {@code setDatalink}.
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
	 * @return a native pcap packet reference or null if packets are being read from
	 *         a ``savefile'' and there are no more packets to read from the
	 *         savefile.
	 * @throws PcapException    any pcap errors such as not activated, etc.
	 * @throws TimeoutException if packets are being read from a live capture and
	 *                          the packet buffer timeout expired
	 * @since Pcap 0.8
	 */
	public PcapPacketRef nextEx() throws PcapException, TimeoutException {
		throw new UnsupportedOperationException(minApi("Pcap0_8", "0.8")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Returns the {@link ByteOrder} of the current capture based on results from
	 * {@link #isSwapped()} method call. Calculates the actual byte order of the
	 * data. For live captures this will equal the native byte order for capture
	 * files, it can be either little or big depending on how the ``savefile'' was
	 * saved.
	 *
	 * @return the byte order
	 * @throws PcapException the pcap exception
	 * @see #isSwapped()
	 */
	public final ByteOrder order() throws PcapException {
		if (isSwapped() == false)
			return ByteOrder.nativeOrder();

		return (ByteOrder.nativeOrder() == ByteOrder.LITTLE_ENDIAN)
				? ByteOrder.BIG_ENDIAN
				: ByteOrder.LITTLE_ENDIAN;
	}

	/**
	 * Print libpcap error message text.
	 * <p>
	 * prints the text of the last pcap library error on stderr, prefixed by prefix
	 * </p>
	 *
	 * @param prefix the message prefix
	 * @return this pcap handle
	 */
	public Pcap perror(String prefix) {
		throw new UnsupportedOperationException(minApi("Pcap0_X", "0.X")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Transmit a packet.
	 * <p>
	 * pcap_sendpacket() sends a raw packet through the network interface; buf
	 * points to the data of the packet, including the link-layer header, and size
	 * is the number of bytes in the packet. Note that, even if you successfully
	 * open the network interface, you might not have permission to send packets on
	 * it, or it might not support sending packets; as pcap_open_live(3PCAP) doesn't
	 * have a flag to indicate whether to open for capturing, sending, or capturing
	 * and sending, you cannot request an open that supports sending and be notified
	 * at open time whether sending will be possible. Note also that some devices
	 * might not support sending packets.
	 * </p>
	 * <p>
	 * Note that, on some platforms, the link-layer header of the packet that's sent
	 * might not be the same as the link-layer header of the packet supplied to
	 * pcap_sendpacket(), as the source link-layer address, if the header contains
	 * such an address, might be changed to be the address assigned to the interface
	 * on which the packet it sent, if the platform doesn't support sending
	 * completely raw and unchanged packets. Even worse, some drivers on some
	 * platforms might change the link-layer type field to whatever value libpcap
	 * used when attaching to the device, even on platforms that do nominally
	 * support sending completely raw and unchanged packets.
	 * </p>
	 *
	 * @param packet the packet
	 * @param length the length number of bytes to send
	 * @throws PcapException the pcap exception
	 * @since libpcap 0.8
	 */
	public void sendPacket(MemorySegment packet, int length) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_8", "0.8")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Transmit a packet.
	 * <p>
	 * pcap_sendpacket() sends a raw packet through the network interface; buf
	 * points to the data of the packet, including the link-layer header, and size
	 * is the number of bytes in the packet. Note that, even if you successfully
	 * open the network interface, you might not have permission to send packets on
	 * it, or it might not support sending packets; as pcap_open_live(3PCAP) doesn't
	 * have a flag to indicate whether to open for capturing, sending, or capturing
	 * and sending, you cannot request an open that supports sending and be notified
	 * at open time whether sending will be possible. Note also that some devices
	 * might not support sending packets.
	 * </p>
	 * <p>
	 * Note that, on some platforms, the link-layer header of the packet that's sent
	 * might not be the same as the link-layer header of the packet supplied to
	 * pcap_sendpacket(), as the source link-layer address, if the header contains
	 * such an address, might be changed to be the address assigned to the interface
	 * on which the packet it sent, if the platform doesn't support sending
	 * completely raw and unchanged packets. Even worse, some drivers on some
	 * platforms might change the link-layer type field to whatever value libpcap
	 * used when attaching to the device, even on platforms that do nominally
	 * support sending completely raw and unchanged packets.
	 * </p>
	 * 
	 * @param buf the buf
	 * @throws PcapException the pcap exception
	 * @since libpcap 0.8
	 */
	public final void sendPacket(final byte[] buf) throws PcapException {
		sendPacket(buf, 0, buf.length);
	}

	/**
	 * Transmit a packet.
	 * <p>
	 * pcap_sendpacket() sends a raw packet through the network interface; buf
	 * points to the data of the packet, including the link-layer header, and size
	 * is the number of bytes in the packet. Note that, even if you successfully
	 * open the network interface, you might not have permission to send packets on
	 * it, or it might not support sending packets; as pcap_open_live(3PCAP) doesn't
	 * have a flag to indicate whether to open for capturing, sending, or capturing
	 * and sending, you cannot request an open that supports sending and be notified
	 * at open time whether sending will be possible. Note also that some devices
	 * might not support sending packets.
	 * </p>
	 * <p>
	 * Note that, on some platforms, the link-layer header of the packet that's sent
	 * might not be the same as the link-layer header of the packet supplied to
	 * pcap_sendpacket(), as the source link-layer address, if the header contains
	 * such an address, might be changed to be the address assigned to the interface
	 * on which the packet it sent, if the platform doesn't support sending
	 * completely raw and unchanged packets. Even worse, some drivers on some
	 * platforms might change the link-layer type field to whatever value libpcap
	 * used when attaching to the device, even on platforms that do nominally
	 * support sending completely raw and unchanged packets.
	 * </p>
	 *
	 * @param buf    array buffer containing packet data to send
	 * @param offset the offset into the buf array
	 * @param length the length number of bytes to send
	 * @throws PcapException the pcap exception
	 * @since libpcap 0.8
	 */
	public final void sendPacket(final byte[] buf, int offset, int length) throws PcapException {
		try (var scope = newArena()) {
			MemorySegment mseg = scope.allocate(length);

			MemorySegment.copy(buf, offset, mseg, ValueLayout.JAVA_BYTE, 0, length);

			sendPacket(mseg, length);
		}
	}

	/**
	 * Transmit a packet.
	 * <p>
	 * pcap_sendpacket() sends a raw packet through the network interface; buf
	 * points to the data of the packet, including the link-layer header, and size
	 * is the number of bytes in the packet. Note that, even if you successfully
	 * open the network interface, you might not have permission to send packets on
	 * it, or it might not support sending packets; as pcap_open_live(3PCAP) doesn't
	 * have a flag to indicate whether to open for capturing, sending, or capturing
	 * and sending, you cannot request an open that supports sending and be notified
	 * at open time whether sending will be possible. Note also that some devices
	 * might not support sending packets.
	 * </p>
	 * <p>
	 * Note that, on some platforms, the link-layer header of the packet that's sent
	 * might not be the same as the link-layer header of the packet supplied to
	 * pcap_sendpacket(), as the source link-layer address, if the header contains
	 * such an address, might be changed to be the address assigned to the interface
	 * on which the packet it sent, if the platform doesn't support sending
	 * completely raw and unchanged packets. Even worse, some drivers on some
	 * platforms might change the link-layer type field to whatever value libpcap
	 * used when attaching to the device, even on platforms that do nominally
	 * support sending completely raw and unchanged packets.
	 * </p>
	 * 
	 * @param buf The packet starts relative to the buffer's position (inclusive)
	 *            and ends relative to the buffer's limit (exclusive)
	 * @throws PcapException the pcap exception
	 * @since libpcap 0.8
	 */
	public final void sendPacket(final ByteBuffer buf) throws PcapException {
		if (buf.hasArray()) {
			sendPacket(buf.array(), buf.arrayOffset() + buf.position(), buf.remaining());

		} else {
			MemorySegment mseg = MemorySegment.ofBuffer(buf);

			sendPacket(mseg, buf.remaining());
		}
	}

	/**
	 * Sets the buffer size for a not-yet- activated capture handle.
	 * 
	 * <p>
	 * sets the buffer size that will be used on a capture handle when the handle is
	 * activated to buffer_size, which is in units of bytes
	 * </p>
	 *
	 * @param bufferSize the buffer size in units of bytes
	 * @return this pcap handle
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.0
	 */
	public Pcap setBufferSize(int bufferSize) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap1_0", "1.0")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Set the link-layer header type to be used by a capture device .
	 *
	 * @param dlt link-layer header type
	 * @return this pcap handle
	 * @throws PcapException the pcap exception
	 * @since libpcap 0.8
	 */
	public Pcap setDatalink(int dlt) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_8", "0.8")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Set the link-layer header type to be used by a capture device .
	 *
	 * @param dlt link-layer header type
	 * @return this pcap handle
	 * @throws PcapException the pcap exception
	 * @since libpcap 0.8
	 */
	public Pcap setDatalink(Optional<PcapDlt> dlt) throws PcapException {
		if (dlt.isEmpty())
			return this;

		return setDatalink(dlt.get().getAsInt());
	}

	/**
	 * Set the link-layer header type to be used by a capture device .
	 *
	 * @param dlt link-layer header type
	 * @return this pcap handle
	 * @throws PcapException the pcap exception
	 * @since libpcap 0.8
	 */
	public Pcap setDatalink(PcapDlt dlt) throws PcapException {
		return setDatalink(dlt.getAsInt());
	}

	/**
	 * <p>
	 * pcap_setdirection() is used to specify a direction that packets will be
	 * captured. d is one of the constants PCAP_D_IN, PCAP_D_OUT or PCAP_D_INOUT.
	 * PCAP_D_IN will only capture packets received by the device, PCAP_D_OUT will
	 * only capture packets sent by the device and PCAP_D_INOUT will capture packets
	 * received by or sent by the device. PCAP_D_INOUT is the default setting if
	 * this function is not called. pcap_setdirection() isn't necessarily fully
	 * supported on all platforms; some platforms might return an error for all
	 * values, and some other platforms might not support PCAP_D_OUT.
	 * </p>
	 * <p>
	 * This operation is not supported if a ``savefile'' is being read.
	 * </p>
	 * 
	 * @param dir one of the constants PCAP_D_IN, PCAP_D_OUT or PCAP_D_INOUT
	 * @return this pcap handle
	 * @throws PcapException the pcap exception
	 * @since libpcap 0.9
	 */
	public Pcap setDirection(int dir) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap090", "0.9")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Set the direction for which packets will be captured.
	 * <p>
	 * pcap_setdirection() is used to specify a direction that packets will be
	 * captured. d is one of the constants PCAP_D_IN, PCAP_D_OUT or PCAP_D_INOUT.
	 * PCAP_D_IN will only capture packets received by the device, PCAP_D_OUT will
	 * only capture packets sent by the device and PCAP_D_INOUT will capture packets
	 * received by or sent by the device. PCAP_D_INOUT is the default setting if
	 * this function is not called. pcap_setdirection() isn't necessarily fully
	 * supported on all platforms; some platforms might return an error for all
	 * values, and some other platforms might not support PCAP_D_OUT.
	 * </p>
	 * <p>
	 * This operation is not supported if a ``savefile'' is being read.
	 * </p>
	 * 
	 * @param dir one of the constants PCAP_D_IN, PCAP_D_OUT or PCAP_D_INOUT
	 * @return this pcap handle
	 * @throws PcapException the pcap exception
	 * @since libpcap 0.9
	 */
	public Pcap setDirection(Optional<PcapDirection> dir) throws PcapException {
		if (dir.isEmpty())
			return this;

		return setDirection(dir.get().getAsInt());
	}

	/**
	 * Set the direction for which packets will be captured.
	 * <p>
	 * pcap_setdirection() is used to specify a direction that packets will be
	 * captured. d is one of the constants PCAP_D_IN, PCAP_D_OUT or PCAP_D_INOUT.
	 * PCAP_D_IN will only capture packets received by the device, PCAP_D_OUT will
	 * only capture packets sent by the device and PCAP_D_INOUT will capture packets
	 * received by or sent by the device. PCAP_D_INOUT is the default setting if
	 * this function is not called. pcap_setdirection() isn't necessarily fully
	 * supported on all platforms; some platforms might return an error for all
	 * values, and some other platforms might not support PCAP_D_OUT.
	 * </p>
	 * <p>
	 * This operation is not supported if a ``savefile'' is being read.
	 * </p>
	 * 
	 * @param dir one of the constants PCAP_D_IN, PCAP_D_OUT or PCAP_D_INOUT
	 * @return this pcap handle
	 * @throws PcapException the pcap exception
	 * @since libpcap 0.9
	 */
	public Pcap setDirection(PcapDirection dir) throws PcapException {
		return setDirection(dir.getAsInt());
	}

	/**
	 * set the filter.
	 * <p>
	 * is used to specify a filter program.
	 * </p>
	 *
	 * @param bpfProgram bpf_program struct, usually the result of a call to
	 *                   pcap_compile
	 * @return this pcap handle
	 * @throws PcapException the pcap exception
	 * @since libpcap 0.4
	 */
	public Pcap setFilter(BpFilter bpfProgram) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * set the filter.
	 * <p>
	 * is used to specify a filter program.
	 * </p>
	 *
	 * @param bpfProgram bpf_program struct, usually the result of a call to
	 *                   pcap_compile
	 * @return this pcap handle
	 * @throws PcapException the pcap exception
	 * @since libpcap 0.4
	 */
	public Pcap setFilter(Optional<BpFilter> bpfProgram) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Set immediate mode for a not-yet- activated capture handle.
	 * 
	 * <p>
	 * sets whether immediate mode should be set on a capture handle when the handle
	 * is activated. In immediate mode, packets are always delivered as soon as they
	 * arrive, with no buffering. If immediate_mode is non-zero, immediate mode will
	 * be set, otherwise it will not be set.
	 * </p>
	 *
	 * @param enable if true, enable immediate mode, otherwise disable
	 * @return this pcap handle
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.5
	 */
	public Pcap setImmediateMode(boolean enable) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap1_5", "1.5")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Sets the state of non-blocking mode on a capture device.
	 * 
	 * <p>
	 * pcap_setnonblock() puts a capture handle into ``non-blocking'' mode, or takes
	 * it out of ``non-blocking'' mode, depending on whether the nonblock argument
	 * is non-zero or zero. It has no effect on ``savefiles''. If there is an error,
	 * PCAP_ERROR is returned and errbuf is filled in with an appropriate error
	 * message; otherwise, 0 is returned. In ``non-blocking'' mode, an attempt to
	 * read from the capture descriptor with pcap_dispatch(3PCAP) and
	 * pcap_next_ex(3PCAP) will, if no packets are currently available to be read,
	 * return 0 immediately rather than blocking waiting for packets to arrive.
	 * </p>
	 * 
	 * <p>
	 * pcap_loop(3PCAP) will loop forever, consuming CPU time when no packets are
	 * currently available; pcap_dispatch() should be used instead. pcap_next(3PCAP)
	 * will return NULL if there are no packets currently available to read; this is
	 * indistinguishable from an error, so pcap_next_ex() should be used instead.
	 * </p>
	 * 
	 * <p>
	 * When first activated with pcap_activate(3PCAP) or opened with
	 * pcap_open_live(3PCAP), a capture handle is not in ``non-blocking mode''; a
	 * call to pcap_setnonblock() is required in order to put it into
	 * ``non-blocking'' mode.
	 * </p>
	 *
	 * @param blockMode if true enable non blocking mode, otherwise block
	 * @return this pcap handle
	 * @throws PcapException the pcap exception
	 * @since libpcap 10.7
	 */
	public Pcap setNonBlock(boolean blockMode) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_7", "0.7")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Set promiscuous mode for a not-yet-activated capture handle.
	 * <p>
	 * pcap_set_promisc() sets whether promiscuous mode should be set on a capture
	 * handle when the handle is activated. If promisc is non-zero, promiscuous mode
	 * will be set, otherwise it will not be set.
	 * </p>
	 *
	 * @param promiscousMode if true enable promiscous mode, otherwise disable it
	 * @return this pcap handle
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.0
	 */
	public Pcap setPromisc(boolean promiscousMode) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap1_0", "1.0")); //$NON-NLS-1$ //$NON-NLS-2$
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
	 * @param rfMonitor the enable rfmon
	 * @return this pcap handle
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.0
	 */
	public Pcap setRfmon(boolean rfMonitor) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap1_0", "1.0")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Set the snapshot length for a not-yet-activated capture handle.
	 * <p>
	 * pcap_set_snaplen() sets the snapshot length to be used on a capture handle
	 * when the handle is activated to snaplen.
	 * </p>
	 *
	 * @param snaplen the snapshot length
	 * @return this pcap handle
	 * @throws PcapException the pcap exception
	 */
	public Pcap setSnaplen(int snaplen) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap1_0", "1.0")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Set the packet buffer timeout for a not-yet-activated capture handle.
	 * <p>
	 * pcap_set_timeout() sets the packet buffer timeout that will be used on a
	 * capture handle when the handle is activated to to_ms, which is in units of
	 * milliseconds. (See pcap(3PCAP) for an explanation of the packet buffer
	 * timeout.)
	 * </p>
	 * <p>
	 * The behavior, if the timeout isn't specified, is undefined, as is the
	 * behavior if the timeout is set to zero or to a negative value. We recommend
	 * always setting the timeout to a non-zero value unless immediate mode is set,
	 * in which case the timeout has no effect. *
	 * </p>
	 * 
	 * @param timeoutInMillis the timeout in milliseconds
	 * @return this pcap handle
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.0
	 */
	public Pcap setTimeout(int timeoutInMillis) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap1_0", "1.0")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Set the time stamp precision returned in captures.
	 * <p>
	 * pcap_set_tstamp_precision() sets the precision of the time stamp desired for
	 * packets captured on the pcap descriptor to the type specified by
	 * tstamp_precision. It must be called on a pcap descriptor created by
	 * pcap_create(3PCAP) that has not yet been activated by pcap_activate(3PCAP).
	 * Two time stamp precisions are supported, microseconds and nanoseconds. One
	 * can use options PCAP_TSTAMP_PRECISION_MICRO and PCAP_TSTAMP_PRECISION_NANO to
	 * request desired precision. By default, time stamps are in microseconds.
	 * </p>
	 *
	 * @param precision one of the following constants PCAP_TSTAMP_PRECISION_MICRO
	 *                  and PCAP_TSTAMP_PRECISION_NANO
	 * @return this pcap handle
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.5
	 */
	public Pcap setTstampPrecision(PcapTStampPrecision precision) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap1_5", "1.5")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Set the time stamp type to be used by a capture device.
	 * <p>
	 * pcap_set_tstamp_type() sets the type of time stamp desired for packets
	 * captured on the pcap descriptor to the type specified by tstamp_type. It must
	 * be called on a pcap descriptor created by pcap_create(3PCAP) that has not yet
	 * been activated by pcap_activate(3PCAP). pcap_list_tstamp_types(3PCAP) will
	 * give a list of the time stamp types supported by a given capture device. See
	 * pcap-tstamp(7) for a list of all the time stamp types.
	 * </p>
	 *
	 * @param type the type
	 * @return this pcap handle
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.2
	 */
	public Pcap setTstampType(PcapTstampType type) throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap1_2", "1.2")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Get the snapshot length.
	 * 
	 * <p>
	 * {@code snapshot} returns the snapshot length specified when
	 * {@link #setSnaplen(int)} or
	 * {@link #openLive(String, int, boolean, long, TimeUnit)} was called, for a
	 * live capture, or the snapshot length from the capture file, for a
	 * ``savefile''.
	 * </p>
	 *
	 * @return the snapshot length
	 * @throws PcapException the pcap exception
	 */
	public int snapshot() throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Get capture statistics.
	 * <p>
	 * pcap_stats() fills in the struct pcap_stat pointed to by its second argument.
	 * The values represent packet statistics from the start of the run to the time
	 * of the call.
	 * </p>
	 * <p>
	 * pcap_stats() is supported only on live captures, not on ``savefiles''; no
	 * statistics are stored in ``savefiles'', so no statistics are available when
	 * reading from a ``savefile''.
	 * </p>
	 * <p>
	 * A struct pcap_stat has the following members:
	 * </p>
	 * <dl>
	 * <dt>ps_recv</dt>
	 * <dd>number of packets received;</dd>
	 * <dt>ps_drop</dt>
	 * <dd>number of packets dropped because there was no room in the operating
	 * system's buffer when they arrived, because packets weren't being read fast
	 * enough;</dd>
	 * <dt>ps_ifdrop</dt>
	 * <dd>number of packets dropped by the network interface or its driver.</dd>
	 * </dl>
	 * <p>
	 * The statistics do not behave the same way on all platforms. ps_recv might
	 * count packets whether they passed any filter set with pcap_setfilter(3PCAP)
	 * or not, or it might count only packets that pass the filter. It also might,
	 * or might not, count packets dropped because there was no room in the
	 * operating system's buffer when they arrived. ps_drop is not available on all
	 * platforms; it is zero on platforms where it's not available. If packet
	 * filtering is done in libpcap, rather than in the operating system, it would
	 * count packets that don't pass the filter. Both ps_recv and ps_drop might, or
	 * might not, count packets not yet read from the operating system and thus not
	 * yet seen by the application. ps_ifdrop might, or might not, be implemented;
	 * if it's zero, that might mean that no packets were dropped by the interface,
	 * or it might mean that the statistic is unavailable, so it should not be
	 * treated as an indication that the interface did not drop any packets.
	 * </p>
	 * 
	 * @return the pcap stat
	 * @throws PcapException the pcap exception
	 * @since libpcap 0.4
	 */
	public PcapStat stats() throws PcapException {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/**
	 * Debug info about this pcap handle.
	 *
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "%s [name=%s, pcapAddress=%s]"
				.formatted(getClass().getSimpleName(), name, getPcapHandle());
	}

	/**
	 * Gets the pcap header ABI (Abstract Binary Interface). Pcap ABI is used to
	 * interpret native structures such as pcap descriptor, correctly on any
	 * specific hardware platform. The ABI abstracts how native integers and
	 * primitive types are represented by CPU architecture on a specific platform.
	 *
	 * @return the ABI of the pcap header for this pcap handle on this CPU
	 *         architecture
	 */
	public PcapHeaderABI getPcapHeaderABI() {
		return pcapHeaderABI;
	}

	/**
	 * Sets the uncaught exception handler for {@link #loop} and {@link #dispatch}
	 * methods. Any exception thrown within the user callback methods, will be
	 * caught and sent to the specified user exception handler.
	 *
	 * @param exceptionHandler the exception handler
	 * @return this pcap
	 */
	public Pcap setUncaughtExceptionHandler(Consumer<? super Throwable> exceptionHandler) {
		return setUncaughtExceptionHandler((t, e) -> exceptionHandler.accept(e));
	}

	/**
	 * Sets the uncaught exception handler for {@link #loop} and {@link #dispatch}
	 * methods. Any exception thrown within the user callback methods, will be
	 * caught and sent to the specified user exception handler.
	 *
	 * @param exceptionHandler the exception handler
	 * @return this pcap
	 */
	public Pcap setUncaughtExceptionHandler(UncaughtExceptionHandler exceptionHandler) {
		throw new UnsupportedOperationException(minApi("Pcap0_4", "0.4")); //$NON-NLS-1$ //$NON-NLS-2$
	}
}
