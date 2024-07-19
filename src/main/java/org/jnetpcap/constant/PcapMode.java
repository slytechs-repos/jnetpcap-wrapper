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

/**
 * Enumeration of pcap live capture mode flags. These flags are used to specify
 * whether a network interface should be put into promiscuous or non-promiscuous
 * mode.
 * 
 * <p>
 * Promiscuous mode allows the network interface to capture all packets on the
 * network, while non-promiscuous mode only captures packets addressed to the
 * interface.
 * </p>
 * 
 * <p>
 * Example usages:
 * </p>
 * 
 * <h2>Opening a pcap handle in promiscuous mode</h2>
 * 
 * <pre>
 * PcapHandle handle = Pcaps.openLive("eth0", 65536, PcapMode.PROMISCUOUS, 10, errbuf);
 * </pre>
 * 
 * <h2>Opening a pcap handle in non-promiscuous mode</h2>
 * 
 * <pre>
 * PcapHandle handle = Pcaps.openLive("eth0", 65536, PcapMode.NON_PROMISCUOUS, 10, errbuf);
 * </pre>
 * 
 * <p>
 * Each enum constant corresponds to a specific capture mode value.
 * </p>
 * 
 * @author Sly Technologies 
 * @author repos@slytechs.com
 */
public enum PcapMode {
	/**
	 * Flag used with {@code openLive} to specify that the interface should be put
	 * into non-promiscuous mode. In non-promiscuous mode, the network interface
	 * captures only the packets addressed to it.
	 */
	NON_PROMISCUOUS,

	/**
	 * Flag used with {@code openLive} to specify that the interface should be put
	 * into promiscuous mode. In promiscuous mode, the network interface captures
	 * all packets on the network.
	 */
	PROMISCUOUS;

	/** Constant for non-promiscuous mode. */
	public static final int PCAP_MODE_NON_PROMISCUOUS = 0;

	/** Constant for promiscuous mode. */
	public static final int PCAP_MODE_PROMISCUOUS = 1;

	/**
	 * Converts a numerical PCAP_MODE constant to a PcapMode enum.
	 *
	 * @param mode the PCAP integer mode constant
	 * @return the corresponding PcapMode constant
	 * @throws IllegalArgumentException if the mode constant is not valid
	 */
	public static PcapMode valueOf(int mode) throws IllegalArgumentException {
		if (mode < 0 || mode >= values().length) {
			throw new IllegalArgumentException(Integer.toString(mode));
		}
		return values()[mode];
	}

	/**
	 * Converts a numerical PCAP_MODE constant to an Optional PcapMode enum.
	 *
	 * @param mode the PCAP integer mode constant
	 * @return an Optional containing the corresponding PcapMode constant, or empty
	 *         if the mode constant is not valid
	 */
	public static Optional<PcapMode> toEnum(int mode) {
		if (mode < 0 || mode >= values().length) {
			return Optional.empty();
		}
		return Optional.of(values()[mode]);
	}
}
