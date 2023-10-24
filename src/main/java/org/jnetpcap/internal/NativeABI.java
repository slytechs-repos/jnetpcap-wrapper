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
	SYS_V,
	WIN64,
	LINUX64,
	MACOS64;

	private static final NativeABI ABI;
	private static final String ARCH;
	private static final String OS;
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

	public static boolean is64bit() {
		return ADDRESS_SIZE == 64;
	}

	public static boolean is32bit() {
		return ADDRESS_SIZE == 32;
	}

	public static NativeABI current() {
		if (ABI == null) {
			throw new UnsupportedOperationException(
					"Unsupported os, arch, or address size: " + OS + ", " + ARCH + ", " + ADDRESS_SIZE);
		}
		return ABI;
	}
}