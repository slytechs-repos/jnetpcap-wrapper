/*
 * Copyright 2024 Sly Technologies Inc
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
 * Enumeration of options usable with the {@code Pcap.init(PcapOption)} call.
 * These options configure various aspects of the Pcap library.
 * 
 * <p>
 * Example usage:
 * </p>
 * 
 * <h2>Initializing pcap with a specific character encoding</h2>
 * 
 * <pre>
 * Pcap.init(PcapOption.CHAR_ENC_UTF_8);
 * </pre>
 * 
 * <p>
 * Each enum constant corresponds to a specific configuration option.
 * </p>
 * 
 * @see org.jnetpcap.Pcap#init(PcapOption)
 * 
 *      Author: Sly Technologies repos@slytechs.com
 */
public enum PcapOption implements IntSupplier {

	/**
	 * Strings are in the local character encoding. This option indicates that
	 * strings passed to and from the Pcap library should be interpreted using the
	 * local character encoding of the system.
	 */
	CHAR_ENC_LOCAL,

	/**
	 * Strings are in UTF-8. This option indicates that strings passed to and from
	 * the Pcap library should be interpreted using the UTF-8 character encoding.
	 */
	CHAR_ENC_UTF_8;

	/** Constant for local character encoding. */
	public static final int PCAP_CHAR_ENC_LOCAL = 0x00000000;

	/** Constant for UTF-8 character encoding. */
	public static final int PCAP_CHAR_ENC_UTF_8 = 0x00000001;

	/**
	 * Converts an integer value into a PcapOption constant.
	 *
	 * @param option the Pcap option numerical constant
	 * @return the corresponding PcapOption enum constant
	 * @throws IllegalArgumentException if the option constant is not valid
	 */
	public static PcapOption valueOf(int option) throws IllegalArgumentException {
		if (option < 0 || option >= values().length) {
			throw new IllegalArgumentException(Integer.toString(option));
		}
		return values()[option];
	}

	/**
	 * Converts an integer value into an Optional PcapOption constant.
	 *
	 * @param option the Pcap option numerical constant
	 * @return an Optional containing the corresponding PcapOption enum constant, or
	 *         empty if the option constant is not valid
	 */
	public static Optional<PcapOption> toEnum(int option) {
		if (option < 0 || option >= values().length) {
			return Optional.empty();
		}
		return Optional.of(values()[option]);
	}

	/**
	 * Returns the integer value of this PcapOption.
	 *
	 * @return the integer value of this PcapOption
	 * @see java.util.function.IntSupplier#getAsInt()
	 */
	@Override
	public int getAsInt() {
		return ordinal();
	}
}
