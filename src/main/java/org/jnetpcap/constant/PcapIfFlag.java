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

import java.util.HashSet;
import java.util.Set;
import java.util.function.IntSupplier;

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
	IF_LOOPBACK(0x00000001),
	
	/** interface is up. */
	IF_UP(0x00000002),
	
	/** interface is running. */
	IF_RUNNING(0x00000004),
	
	/** interface is wireless (*NOT* necessarily Wi-Fi!). */
	IF_WIRELESS(0x00000008),
	
	/** connection status:. */
	IF_CONNECTION_STATUS(0x00000030),
	
	/** unknown. */
	IF_CONNECTION_STATUS_UNKNOWN(0x00000000),
	
	/** connected. */
	IF_CONNECTION_STATUS_CONNECTED(0x00000010),
	
	/** disconnected. */
	IF_CONNECTION_STATUS_DISCONNECTED(0x00000020),
	
	/** not applicable. */
	IF_CONNECTION_STATUS_NOT_APPLICABLE(0x00000030);

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

	/**
	 * Instantiates a new pcap if flag.
	 *
	 * @param flags the flags
	 */
	PcapIfFlag(int flags) {
		this.flags = flags;
	}

	/**
	 * Converts integer flag value to a set.
	 *
	 * @param flags the single flag
	 * @return the sets the
	 */
	public static Set<PcapIfFlag> toSet(int flags) {
		Set<PcapIfFlag> set = new HashSet<>();

		for (PcapIfFlag f : values()) {
			if (f.flags == flags)
				set.add(f);
		}

		return set;
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
