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
 * <p>
 * Example usage:
 * </p>
 * 
 * <h2>Converting an integer source type to a PcapSrc enum constant</h2>
 * 
 * <pre>
 * int srcType = 3;
 * PcapSrc pcapSrc = PcapSrc.toEnum(srcType).orElse(null);
 * System.out.println("Pcap Source Type: " + (pcapSrc != null ? pcapSrc.name() : "Unknown"));
 * </pre>
 * 
 * @see java.util.function.IntSupplier
 * 
 *      Author: Sly Technologies Inc repos@slytechs.com
 */
public enum PcapSrc implements IntSupplier {

	/**
	 * Internal representation of the type of source in use (file, remote/local
	 * interface).
	 * 
	 * @see <a href=
	 *      "https://www.tcpdump.org/manpages/pcap.3pcap.html">PCAP_SRC_FILE</a>
	 */
	SRC_FILE,

	/**
	 * Local network interface.
	 * 
	 * @see <a href=
	 *      "https://www.tcpdump.org/manpages/pcap.3pcap.html">PCAP_SRC_IFLOCAL</a>
	 */
	SRC_IFLOCAL,

	/**
	 * Interface on a remote host, using RPCAP.
	 * 
	 * @see <a href=
	 *      "https://www.tcpdump.org/manpages/pcap.3pcap.html">PCAP_SRC_IFREMOTE</a>
	 */
	SRC_IFREMOTE;

	/** Local savefile. */
	public static final int PCAP_SRC_FILE = 2;

	/** Local network interface. */
	public static final int PCAP_SRC_IFLOCAL = 3;

	/** Interface on a remote host, using RPCAP. */
	public static final int PCAP_SRC_IFREMOTE = 4;

	/**
	 * Converts PCAP src numerical constant to an enum constant.
	 *
	 * @param src the PCAP src numerical constant
	 * @return the PCAP src enum constant
	 * @throws IllegalArgumentException thrown if not found
	 */
	public static PcapSrc valueOf(int src) throws IllegalArgumentException {
		if (src < 2 || src > 4)
			throw new IllegalArgumentException(Integer.toString(src));

		return values()[src - 2];
	}

	/**
	 * Converts PCAP src numerical constant to an enum constant, if found.
	 *
	 * @param src the PCAP src numerical constant
	 * @return the PCAP src enum constant
	 * @throws IllegalArgumentException thrown if not found
	 */
	public static Optional<PcapSrc> toEnum(int src) throws IllegalArgumentException {
		if (src < 2 || src > 4)
			return Optional.empty();

		return Optional.of(values()[src - 2]);
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
