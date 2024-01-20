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

import java.util.EnumSet;
import java.util.Set;
import java.util.function.IntSupplier;
import java.util.stream.Collectors;

/**
 * Network interface status flags.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public enum PcapIfFlag implements IntSupplier {

	/** interface is loopback. */
	IF_LOOPBACK(0x00000001, "LOOPBACK"),

	/** interface is up. */
	IF_UP(0x00000002, "UP"),

	/** interface is running. */
	IF_RUNNING(0x00000004, "RUNNING"),

	/** interface is wireless (*NOT* necessarily Wi-Fi!). */
	IF_WIRELESS(0x00000008, "WIRELESS"),

	/** connected. */
	IF_CONNECTION_STATUS_CONNECTED(0x00000010, "CONNECTED"),

	/** disconnected. */
	IF_CONNECTION_STATUS_DISCONNECTED(0x00000020, "DISCONNECTED"),

	/** not applicable. */
	IF_CONNECTION_STATUS_NOT_APPLICABLE(0x00000030, "N/A")

	; /* END of enum table */

	/** interface is loopback. */
	public static final int PCAP_IF_LOOPBACK = 0x00000001;

	/** interface is up. */
	public static final int PCAP_IF_UP = 0x00000002;

	/** interface is running. */
	public static final int PCAP_IF_RUNNING = 0x00000004;

	/** interface is wireless (*NOT* necessarily Wi-Fi!). */
	public static final int PCAP_IF_WIRELESS = 0x00000008;

	/** connection status:. */
	public static final int PCAP_IF_CONNECTION_STATUS = 0x00000030;

	/** unknown. */
	public static final int PCAP_IF_CONNECTION_STATUS_UNKNOWN = 0x00000000;

	/** connected. */
	public static final int PCAP_IF_CONNECTION_STATUS_CONNECTED = 0x00000010;

	/** disconnected. */
	public static final int PCAP_IF_CONNECTION_STATUS_DISCONNECTED = 0x00000020;

	/** not applicable. */
	public static final int PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE = 0x00000030;

	/** The flags. */
	private final int flags;

	private final String label;

	/**
	 * Instantiates a new pcap if flag.
	 *
	 * @param flags the flags
	 * @param label
	 */
	PcapIfFlag(int flags, String label) {
		this.flags = flags;
		this.label = label;
	}

	/**
	 * Converts integer flag bit-field, to an enum set. The method drops
	 * "connection" status bits by ANDing with <code>0x0F</code> value and only uses
	 * PCAP interface flag bits.
	 *
	 * @param flags integer bitfield where each bit is a flag
	 * @return an enum set containing bits flag bits
	 */
	public static Set<PcapIfFlag> toEnumSet(int flags) {
		flags &= 0xF; // drop connection status bits, don't mix with IF status
		Set<PcapIfFlag> set = EnumSet.noneOf(PcapIfFlag.class);

		for (PcapIfFlag f : values()) {
			if ((f.flags & flags) == f.flags)
				set.add(f);
		}

		return set;
	}

	/**
	 * To a set of PcapIf flags..
	 *
	 * @param flags the bitmask of flags
	 * @return the set of enum constants
	 */
	public static Set<String> toLabelSet(int flags) {
		return toEnumSet(flags).stream()
				.map(PcapIfFlag::label)
				.collect(Collectors.toSet());
	}

	/**
	 * A human readable label for this constant.
	 *
	 * @return the label
	 */
	public String label() {
		return label;
	}

	/**
	 * Gets the as int.
	 *
	 * @return the as int
	 * @see java.util.function.IntSupplier#getAsInt()
	 */
	@Override
	public int getAsInt() {
		return flags;
	}

}
