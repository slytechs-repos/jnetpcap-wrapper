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
 * Options usable with {@code Pcap.init(PcapOption)} call.
 */
public enum PcapOption implements IntSupplier {

	/** strings are in the local character encoding. */
	CHAR_ENC_LOCAL,

	/** strings are in UTF-8. */
	CHAR_ENC_UTF_8,
	;

	/** strings are in the local character encoding. */
	public static final int PCAP_CHAR_ENC_LOCAL = 0x00000000;

	/** strings are in UTF-8. */
	public static final int PCAP_CHAR_ENC_UTF_8 = 0x00000001;

	/**
	 * Converts an integer value into a PCAP option constant.
	 *
	 * @param option the PCAP option numerical constant
	 * @return the PCAP option enum constant
	 * @throws IllegalArgumentException thrown if not found
	 */
	public static PcapOption valueOf(int option) throws IllegalArgumentException {
		if (option < 0 || option > 1)
			throw new IllegalArgumentException(Integer.toString(option));

		return values()[option];
	}

	/**
	 * Converts an integer value into a PCAP option constant, if found.
	 *
	 * @param option the PCAP option numerical constant
	 * @return the PCAP option enum constant
	 */
	public static Optional<PcapOption> toEnum(int option) {
		if (option < 0 || option > 1)
			return Optional.empty();

		return Optional.of(values()[option]);
	}

	/**
	 * Pcap option integer value.
	 *
	 * @return the pcap option as integer
	 * @see java.util.function.IntSupplier#getAsInt()
	 */
	@Override
	public int getAsInt() {
		return ordinal();
	}

}
