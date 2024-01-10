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

import org.jnetpcap.PcapIf;

import static java.lang.foreign.ValueLayout.*;

/**
 * Platforms native ABI (Application Binary Interface, CPU/Instruction set).
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public enum NativeABI {

	/** The sys v. */
	SYS_V,

	/** The win64. */
	WIN64,

	/** The linux64. */
	LINUX64,

	/** The macos64. */
	MACOS64;

	/**
	 * System property if set to true, pcap uses BSD style sockaddr structure which
	 * has the addr_len field. Otherwise the default heuristic are used to determine
	 * the sock address structure format.
	 */
	public static final String SYSTEM_PROPERTY_NATIVE_ABI_BSD = "org.jnetpcap.abi.bsd";

	/** The Constant ABI. */
	private static final NativeABI ABI;

	/** The Constant ARCH. */
	private static final String ARCH;

	/** The Constant OS. */
	private static final String OS;

	/** The Constant ADDRESS_SIZE. */
	private static final long ADDRESS_SIZE;

	static {
		ARCH = System.getProperty("os.arch");
		OS = System.getProperty("os.name");
		ADDRESS_SIZE = ADDRESS.byteSize() * 8;

		// might be running in a 32-bit VM on a 64-bit platform.
		// addressSize will be correctly 32
		if ((ARCH.equals("amd64") || ARCH.equals("x86_64")) && ADDRESS_SIZE == 64) {
			if (OS.startsWith("Windows")) {
				ABI = WIN64;
			} else if (OS.startsWith("Mac")) {
				ABI = MACOS64;
			} else {
				ABI = SYS_V;
			}
		} else if (ARCH.equals("aarch64")) {
			if (OS.startsWith("Mac")) {
				ABI = MACOS64;
			} else {
				// The Linux ABI follows the standard AAPCS ABI
				ABI = LINUX64;
			}
		} else {
			// unsupported
			ABI = null;
		}
	}

	/**
	 * Checks if is 64 bit.
	 *
	 * @return true, if is 64 bit
	 */
	public static boolean is64bit() {
		return ADDRESS_SIZE == 64;
	}

	/**
	 * Checks if is 32 bit.
	 *
	 * @return true, if is 32 bit
	 */
	public static boolean is32bit() {
		return ADDRESS_SIZE == 32;
	}

	/**
	 * Current.
	 *
	 * @return the native ABI
	 */
	public static NativeABI current() {
		if (ABI == null) {
			throw new UnsupportedOperationException(
					"Unsupported os, arch, or address size: " + OS + ", " + ARCH + ", " + ADDRESS_SIZE);
		}
		return ABI;
	}

	/**
	 * Checks if is bsd abi.
	 *
	 * @return true, if is bsd abi
	 */
	public static boolean isBsdAbi() {
		boolean bsdOverride = false;
		try {
			bsdOverride = Boolean.parseBoolean(System.getProperty(PcapIf.SYSTEM_PROPERTY_PCAPIF_SOCKADDR_BSD_STYLE,
					"false"));
		} catch (Throwable e) {}

		return bsdOverride || (NativeABI.current() == NativeABI.MACOS64);
	}
}