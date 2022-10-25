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
package org.jnetpcap.internal;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

import org.jnetpcap.Pcap.LibraryPolicy;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapMessages;

/**
 * Pcap specific {@full ForeignInitializer} used to facilitate loading native
 * libary symbols and making of 'downcall' and 'upcall' function calls.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public class PcapForeignInitializer extends ForeignInitializer<PcapForeignDowncall, PcapException> {

	/**
	 * The Constant which defines the default logging output which discards all of
	 * its input.
	 */
	public static final Appendable DEFAULT_LOGGING_OUTPUT = PrintWriter.nullWriter();

	/** Where any jNetPcap logging output is sent. */
	private static Appendable loggingOutput = DEFAULT_LOGGING_OUTPUT;

	/** A policy on action when missing native symbols are encountered. */
	private static LibraryPolicy currentMissingSymbolsPolicy = PcapForeignInitializer::defaultPolicy;

	/**
	 * Default native library policy. Can be overriden with
	 * {@link #setPolicy(LibraryPolicy)}
	 *
	 * @param initializerName the initializer name
	 * @param down            the down
	 * @param up              the up
	 * @throws NoSuchMethodError the no such method error
	 * @throws IOException       Signals that an I/O exception has occurred.
	 */
	private static synchronized void defaultPolicy(String initializerName, List<String> down,
			List<String> up) throws NoSuchMethodError, IOException {

		if (!down.isEmpty())
			loggingOutput.append(PcapMessages.getString("pcap.initializer.policy.downcalls") //$NON-NLS-1$
					.formatted(down, initializerName));

		if (!up.isEmpty())
			loggingOutput.append(PcapMessages.getString("pcap.initializer.policy.upcalls") //$NON-NLS-1$
					.formatted(up, initializerName));

		if (!up.isEmpty())
			throw new NoSuchMethodError(PcapMessages.getString("pcap.initiazlier.policy.failure") //$NON-NLS-1$
					.formatted(up, initializerName));
	}

	/**
	 * @return
	 */
	public static Appendable getLogginOutput() {
		return loggingOutput;
	}

	/**
	 * Gets the default missing symbols policy.
	 *
	 * @return the default missing symbols policy
	 */
	public static LibraryPolicy getPolicy() {
		return currentMissingSymbolsPolicy;
	}

	/**
	 * Load native pcap library, or one of its dirivatives.
	 *
	 * @param ignoreErrors if true, no errors will be thrown but a {@full false}
	 *                     flag will be returned
	 * @return true, if pcap library is loaded otherwise false
	 * @throws ExceptionInInitializerError the exception in initializer error
	 */
	public static boolean loadNativePcapLibrary(boolean ignoreErrors) throws ExceptionInInitializerError {
		boolean npcap = false, wpcap = false, pcap = false;

		// @formatter:off
		try { System.loadLibrary("npcap"); npcap = true; } catch(Throwable e) {}
		try { System.loadLibrary("wpcap"); wpcap = true; } catch(Throwable e) {}
		try { System.loadLibrary("pcap");   pcap = true; } catch(Throwable e) {}
		// @formatter:on

		boolean isLoaded = pcap || npcap || wpcap;

		if (!isLoaded && !ignoreErrors) {
			throw new ExceptionInInitializerError(
					"Unable to load native 'pcap' library! Tried 'pcap', 'wpcap' and 'npcap'");
		}

		return isLoaded;
	}

	/**
	 * Sets the default missing native symbols policy.
	 * <p>
	 * Missing symbols policy is executed during early/static initialization phase
	 * of Pcap library. The policy object receives a list of symbols both for
	 * 'downcall' and 'upcall' symbols which were not found during loading of the
	 * native pcap libarary. The {@full ForeignInitializer} creates stubs for each
	 * missing symbol, that when called at runtime will throw a safe exception. A
	 * missing symbols policy can intercept missing symbols during initialization
	 * phase and if so desired can throw an appropriate exception, halting any
	 * further initialization. A different policy might simply log an error using
	 * application's logger.
	 * </p>
	 *
	 * @param newPolicy the new default missing symbols policy
	 * @see #setLoggingOutput(Appendable)
	 */
	public static void setPolicy(LibraryPolicy newPolicy) {
		currentMissingSymbolsPolicy = newPolicy;
	}

	/**
	 * Sets the logging output produced by the default missing symbols policy
	 * receiver. By default the output is sent to {@full PrintWriter.nullWriter()}
	 * which discards all output. You can set another output consumer or override
	 * the policy using {@link #setPolicy(LibraryPolicy)}.
	 *
	 * @param out the new logging output
	 * @see #setPolicy(LibraryPolicy)
	 */
	public static void setLoggingOutput(Appendable out) {
		loggingOutput = out;
	}

	public PcapForeignInitializer(Class<?> initializerClass) {
		super(initializerClass.toString(), PcapForeignDowncall::new, PcapForeignDowncall::new);

		makeAccessible(true);
		setMissingSymbolsPolicy(currentMissingSymbolsPolicy::onMissingSymbols);
	}

}
