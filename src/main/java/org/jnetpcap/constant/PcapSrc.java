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
 * Internal representation of the type of source in use (file, remote/local
 * interface).
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 */
public enum PcapSrc implements IntSupplier {

	/**
	 * Internal representation of the type of source in use (file, remote/local
	 * interface).
	 */
	SRC_FILE,

	/** local network interface. */
	SRC_IFLOCAL,

	/** interface on a remote host, using RPCAP. */
	SRC_IFREMOTE;

	/** local savefile. */
	public static final int PCAP_SRC_FILE = 2;

	/** local network interface. */
	public static final int PCAP_SRC_IFLOCAL = 3;

	/** interface on a remote host, using RPCAP. */
	public static final int PCAP_SRC_IFREMOTE = 4;

	/**
	 * Converts PCAP src numerical constant to an enum constant.
	 *
	 * @param src the PCAP src numerical constant
	 * @return the PCAP src enum constant
	 * @throws IllegalArgumentException thrown if not found
	 */
	public static PcapSrc valueOf(int src) throws IllegalArgumentException {
		if (src < 0 || src > 2)
			throw new IllegalArgumentException(Integer.toString(src));

		return values()[src];
	}

	/**
	 * Converts PCAP src numerical constant to an enum constant, if found.
	 *
	 * @param src the PCAP src numerical constant
	 * @return the PCAP src enum constant
	 * @throws IllegalArgumentException thrown if not found
	 */
	public static Optional<PcapSrc> toEnum(int src) throws IllegalArgumentException {
		if (src < 0 || src > 2)
			return Optional.empty();

		return Optional.of(values()[src]);
	}

	/**
	 * Get int value of type.
	 *
	 * @return The type of input source, passed to pcap_open
	 * @see java.util.function.IntSupplier#getAsInt()
	 */
	@Override
	public int getAsInt() {
		return ordinal() + 2;
	}
}
