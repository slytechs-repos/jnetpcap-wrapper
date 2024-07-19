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
 * Enumeration of network interface status flags. These flags indicate various
 * statuses and capabilities of a network interface.
 * 
 * <p>
 * Example usages:
 * </p>
 * 
 * <h2>Checking interface status</h2>
 * 
 * <pre>
 * int flags = pcapIf.getFlags();
 * if (PcapIfFlag.IF_UP.equals(flags)) {
 * 	// Interface is up
 * }
 * </pre>
 * 
 * <h2>Converting integer flags to a set of labels</h2>
 * 
 * <pre>
 * int flags = pcapIf.getFlags();
 * Set&lt;String&gt; labels = PcapIfFlag.toLabelSet(flags);
 * System.out.println("Interface flags: " + labels);
 * </pre>
 * 
 * <h2>Converting integer flags to an enum set</h2>
 * 
 * <pre>
 * int flags = pcapIf.getFlags();
 * Set&lt;PcapIfFlag&gt; flagSet = PcapIfFlag.toEnumSet(flags);
 * System.out.println("Interface flags: " + flagSet);
 * </pre>
 * 
 * <p>
 * Each enum constant corresponds to a specific flag value and a human-readable
 * label.
 * </p>
 * 
 * Author: Sly Technologies Inc repos@slytechs.com Mark
 */
public enum PcapIfFlag implements IntSupplier {

	/**
	 * Interface is a loopback interface. Loopback interfaces are used for testing
	 * and internal communication within the host.
	 */
	IF_LOOPBACK(0x00000001, "LOOPBACK"),

	/**
	 * Interface is up. Indicates that the interface is enabled and ready to
	 * transmit data.
	 */
	IF_UP(0x00000002, "UP"),

	/**
	 * Interface is running. Indicates that the interface is operational and capable
	 * of sending and receiving data.
	 */
	IF_RUNNING(0x00000004, "RUNNING"),

	/**
	 * Interface is wireless. Indicates that the interface is a wireless interface
	 * (not necessarily Wi-Fi).
	 */
	IF_WIRELESS(0x00000008, "WIRELESS"),

	/**
	 * Interface is connected. Indicates that the interface is connected to a
	 * network.
	 */
	IF_CONNECTION_STATUS_CONNECTED(0x00000010, "CONNECTED"),

	/**
	 * Interface is disconnected. Indicates that the interface is not connected to
	 * any network.
	 */
	IF_CONNECTION_STATUS_DISCONNECTED(0x00000020, "DISCONNECTED"),

	/**
	 * Connection status not applicable. Indicates that the connection status is not
	 * applicable to this interface.
	 */
	IF_CONNECTION_STATUS_NOT_APPLICABLE(0x00000030, "N/A");

	/** Integer value representing the loopback flag. */
	public static final int PCAP_IF_LOOPBACK = 0x00000001;

	/** Integer value representing the up flag. */
	public static final int PCAP_IF_UP = 0x00000002;

	/** Integer value representing the running flag. */
	public static final int PCAP_IF_RUNNING = 0x00000004;

	/** Integer value representing the wireless flag. */
	public static final int PCAP_IF_WIRELESS = 0x00000008;

	/** Integer value representing the connection status flag. */
	public static final int PCAP_IF_CONNECTION_STATUS = 0x00000030;

	/** Integer value representing the unknown connection status. */
	public static final int PCAP_IF_CONNECTION_STATUS_UNKNOWN = 0x00000000;

	/** Integer value representing the connected status. */
	public static final int PCAP_IF_CONNECTION_STATUS_CONNECTED = 0x00000010;

	/** Integer value representing the disconnected status. */
	public static final int PCAP_IF_CONNECTION_STATUS_DISCONNECTED = 0x00000020;

	/** Integer value representing the not applicable connection status. */
	public static final int PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE = 0x00000030;

	/** The integer flag value representing the status. */
	private final int flags;

	/** A human-readable label for the flag. */
	private final String label;

	/**
	 * Instantiates a new PcapIfFlag enum constant.
	 *
	 * @param flags the integer flag value
	 * @param label the human-readable label
	 */
	PcapIfFlag(int flags, String label) {
		this.flags = flags;
		this.label = label;
	}

	/**
	 * Converts an integer flag bit-field to an EnumSet of PcapIfFlag. The method
	 * drops "connection" status bits by ANDing with &lt;code&gt;0x0F&lt;/code&gt;
	 * value and only uses PCAP interface flag bits.
	 *
	 * @param flags the integer bit-field where each bit represents a flag
	 * @return an EnumSet containing the flag bits
	 */
	public static Set<PcapIfFlag> toEnumSet(int flags) {
		flags &= 0xF; // Drop connection status bits, don't mix with IF status
		Set<PcapIfFlag> set = EnumSet.noneOf(PcapIfFlag.class);

		for (PcapIfFlag f : values()) {
			if ((f.flags & flags) == f.flags) {
				set.add(f);
			}
		}

		return set;
	}

	/**
	 * Converts an integer flag bit-field to a set of human-readable labels.
	 *
	 * @param flags the bitmask of flags
	 * @return a set of labels representing the flags
	 */
	public static Set<String> toLabelSet(int flags) {
		return toEnumSet(flags).stream()
				.map(PcapIfFlag::label)
				.collect(Collectors.toSet());
	}

	/**
	 * Returns the human-readable label for this constant.
	 *
	 * @return the label
	 */
	public String label() {
		return label;
	}

	/**
	 * Returns the integer flag value representing the status.
	 *
	 * @return the integer flag value
	 * @see java.util.function.IntSupplier#getAsInt()
	 */
	@Override
	public int getAsInt() {
		return flags;
	}

}
