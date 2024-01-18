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
package org.jnetpcap.internal;

import java.io.IOException;
import java.io.PrintWriter;
import java.lang.invoke.MethodHandles;
import java.nio.file.Path;
import java.util.List;

import org.jnetpcap.Pcap.LibraryPolicy;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapErrorHandler;

/**
 * Pcap specific {@code ForeignInitializer} used to facilitate loading native
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
			loggingOutput.append(PcapErrorHandler.getString("pcap.initializer.policy.downcalls") //$NON-NLS-1$
					.formatted(down, initializerName));

		if (!up.isEmpty())
			loggingOutput.append(PcapErrorHandler.getString("pcap.initializer.policy.upcalls") //$NON-NLS-1$
					.formatted(up, initializerName));

		if (!up.isEmpty())
			throw new NoSuchMethodError(PcapErrorHandler.getString("pcap.initiazlier.policy.failure") //$NON-NLS-1$
					.formatted(up, initializerName));
	}

	/**
	 * Gets the loggin output.
	 *
	 * @return the loggin output
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
	 * Load native pcap library, or one of its derivatives. The defaults for the
	 * native library loading procedure, define a list of possible pcap library
	 * undecorated names such as 'wpcap,npcap,pcap' and utilize the relative
	 * {@link System#loadLibrary(String)} to search for the shared object/native
	 * library.
	 * <p>
	 * By specifying various system properties on the java command line, you can
	 * redefine how, where and what to look for when loading the native library.
	 * </p>
	 * The following properties are used in a search in the following order:
	 * <dl>
	 * <dt>{@value LibraryPolicy#SYSTEM_PROPERTY_JAVA_LIBRARY_PATH}:</dt>
	 * <dd>Defines directories where the native library will searched for.</dd>
	 * <dt>{@value LibraryPolicy#SYSTEM_PROPERTY_LIBPCAP_FILE}:</dt>
	 * <dd>Defines an absolute directory and decorated filename path to load the
	 * native library using {@link System.#load(String)} system call.</dd>
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
	 * @param ignoreErrors if true, no errors will be thrown but a {@code false}
	 *                     flag will be returned
	 * @return true, if pcap library is loaded otherwise false
	 * @throws ExceptionInInitializerError the exception in initializer error
	 * @see LibraryPolicy#SYSTEM_PROPERTY_JAVA_LIBRARY_PATH
	 * @see LibraryPolicy#SYSTEM_PROPERTY_LIBPCAP_FILE
	 * @see LibraryPolicy#SYSTEM_PROPERTY_LIBPCAP_FILENAME
	 * @see LibraryPolicy#SYSTEM_PROPERTY_LIBPCAP_NAMES
	 * @see LibraryPolicy#SYSTEM_PROPERTY_SO_EXTENSIONS
	 * @see LibraryPolicy#SYSTEM_PROPERTY_SO_IGNORE_LOAD_ERRORS
	 */
	public static boolean loadNativePcapLibrary(boolean ignoreErrors) throws ExceptionInInitializerError {

		final String DECORATED_FORMAT = "lib%s.%s";
		String javaLibraryPath = System.getProperty(LibraryPolicy.SYSTEM_PROPERTY_JAVA_LIBRARY_PATH);
		String libpcapFile = System.getProperty(LibraryPolicy.SYSTEM_PROPERTY_LIBPCAP_FILE);
		String libpcapFilename = System.getProperty(LibraryPolicy.SYSTEM_PROPERTY_LIBPCAP_FILENAME);
		String libpcapNames = System.getProperty(LibraryPolicy.SYSTEM_PROPERTY_LIBPCAP_NAMES,
				"wpcap,pcap");
		String soExtensions = System.getProperty(LibraryPolicy.SYSTEM_PROPERTY_SO_EXTENSIONS,
				"so,dylib,dll");

		boolean isLoaded = false;
		StringBuilder errorBuilder = new StringBuilder();

		/*
		 * We perform our own scan for the library. We use ';' character as directory
		 * separator.
		 * 
		 * Note that you can not set 'java.library.path' property programatically. It
		 * read by VM on startup from the System properties and never again after that.
		 * Therefore we perform our own scan.
		 */
		if (javaLibraryPath != null) {
			javaLibraryPath = javaLibraryPath.replace(':', ';');
			javaLibraryPath += ";" + LibraryPolicy.DEFAULT_JAVA_LIBRARY_PATH;
		}

		/* Try absolute file path first, highest priority */
		if (!isLoaded && (libpcapFile != null)) {
			try {
				System.load(libpcapFile);
				isLoaded = true;
			} catch (Throwable e) {}

			if (!isLoaded)
				errorBuilder.append("Failed to load absolue file [%s]. "
						.formatted(libpcapFile));
		}

		/* Try building an absolute path, 2nd priority */
		if (!isLoaded && (libpcapFilename != null)) {
			if (javaLibraryPath != null) {
				Path path = Path.of(javaLibraryPath, libpcapFilename);
				try {
					System.load(path.toString());
					isLoaded = true;
				} catch (Throwable e) {}

				if (!isLoaded)
					errorBuilder.append("Failed to load absolute path file [%s] using property '%s'. "
							.formatted(path.toString(), LibraryPolicy.SYSTEM_PROPERTY_LIBPCAP_FILENAME));
			}

			if (javaLibraryPath == null)
				errorBuilder.append("WARNING! 'java.library.path' is not set for use with propery '%s'. "
						.formatted(LibraryPolicy.SYSTEM_PROPERTY_LIBPCAP_FILENAME));
		}

		/* Try relative to java.library.path load per each name in the names */
		if (!isLoaded && (libpcapNames != null)) {
			for (String name : libpcapNames.split("\\s*,\\s*")) {
				if (!isLoaded) {
					try {
						System.loadLibrary(name);
						isLoaded = true;
					} catch (Throwable e) {}
				}
			}

			if (!isLoaded)
				errorBuilder.append("Failed to relative load [%s] using property '%s'. "
						.formatted(libpcapNames, LibraryPolicy.SYSTEM_PROPERTY_LIBPCAP_NAMES));

			if (javaLibraryPath == null)
				errorBuilder.append("WARNING! 'java.library.path' is not set for use with propery '%s'. "
						.formatted(LibraryPolicy.SYSTEM_PROPERTY_LIBPCAP_NAMES));
		}

		/* Last attempt, is to use the lib names and attempt to load absolute paths */
		if (!isLoaded && (libpcapNames != null) && (soExtensions != null)) {
			String[] exts = soExtensions.split("\\s*,\\s*");
			javaLibraryPath = (javaLibraryPath == null)
					? "."
					: javaLibraryPath;

			for (String dir : javaLibraryPath.split(";")) {

				LONG_SHOT_LOOP: for (String name : libpcapNames.split("\\s*,\\s*")) {
					for (String ext : exts) {
						Path path = Path.of(dir, DECORATED_FORMAT.formatted(name, ext));

						try {
							System.load(path.toString());
							isLoaded = true;
							break LONG_SHOT_LOOP;
						} catch (Throwable e) {}
					}
				}
			}

			/* This was a long shot, so we do not report any errors here */
		}

		if (!isLoaded && !ignoreErrors) {
			if (errorBuilder.length() > 0)
				throw new ExceptionInInitializerError(
						"Unable to load native 'pcap' library! %s"
								.formatted(errorBuilder.toString()));

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
	 * native pcap libarary. The {@code ForeignInitializer} creates stubs for each
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
	 * receiver. By default the output is sent to {@code PrintWriter.nullWriter()}
	 * which discards all output. You can set another output consumer or override
	 * the policy using {@link #setPolicy(LibraryPolicy)}.
	 *
	 * @param out the new logging output
	 * @see #setPolicy(LibraryPolicy)
	 */
	public static void setLoggingOutput(Appendable out) {
		loggingOutput = out;
	}

	/**
	 * Instantiates a new pcap foreign initializer.
	 *
	 * @param initializerClass the initializer class
	 */
	public PcapForeignInitializer(Class<?> initializerClass) {
		super(
				initializerClass.toString(),
				PcapForeignDowncall::new,
				PcapForeignDowncall::new,
				MethodHandles.lookup());

		makeAccessible(true);
		setMissingSymbolsPolicy(currentMissingSymbolsPolicy::onMissingSymbols);
	}

}
