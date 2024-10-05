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
package org.jnetpcap.constant;

import java.util.Optional;
import java.util.function.IntSupplier;

/**
 * WinPcap setmode values.
 * 
 * @author Sly Technologies Inc
 * @author mark
 *
 */
public enum WinPcapMode implements IntSupplier {

	/**
	 * Capture mode, used for capturing packets. More information can be found at:
	 * <a href=
	 * "https://www.winpcap.org/docs/docs_412/html/group__wpcapfunc.html#ga3ed92b36d2d80576e297c8273b4291dc">WinPcap
	 * Capture Mode</a>
	 */
	CAPT,

	/**
	 * Statistics mode, used for collecting statistics. More information can be
	 * found at: <a href=
	 * "https://www.winpcap.org/docs/docs_412/html/group__wpcapfunc.html#ga2a17e78e387f5a4773bc8cc87f8a72f4">WinPcap
	 * Statistics Mode</a>
	 */
	STAT,

	/**
	 * Monitor mode, used for monitoring packets without capturing. More information
	 * can be found at: <a href=
	 * "https://www.winpcap.org/docs/docs_412/html/group__wpcapfunc.html#ga13e3aaf9a0bb9a1e2b558df5d2c7b455">WinPcap
	 * Monitor Mode</a>
	 */
	MON;

	/** The Constant MODE_CAPT. */
	public static final int MODE_CAPT = 0;

	/** The Constant MODE_STAT. */
	public static final int MODE_STAT = 1;

	/** The Constant MODE_MON. */
	public static final int MODE_MON = 2;

	/**
	 * Converts numerical WinPcap mode constant to an enum.
	 *
	 * @param mode the PCAP integer mode constant
	 * @return the pcap mode constant
	 * @throws IllegalArgumentException thrown if not found
	 */
	public static WinPcapMode valueOf(int mode) throws IllegalArgumentException {
		if (mode < 0 || mode >= values().length)
			throw new IllegalArgumentException(Integer.toString(mode));

		return values()[mode];
	}

	/**
	 * Converts numerical WinPcap mode constant to an enum, if found.
	 *
	 * @param mode the WinPcap mode constant
	 * @return the optional enum constant
	 */
	public static Optional<WinPcapMode> toEnum(int mode) {
		if (mode < 0 || mode >= values().length)
			Optional.empty();

		return Optional.of(values()[mode]);
	}

	/**
	 * Gets WinPcap mode as numerical constant.
	 *
	 * @return the WinPcap mode numerical constant
	 * @see java.util.function.IntSupplier#getAsInt()
	 */
	@Override
	public int getAsInt() {
		return ordinal();
	}

}
