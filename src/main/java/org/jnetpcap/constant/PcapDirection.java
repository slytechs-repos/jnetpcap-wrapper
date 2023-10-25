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

import java.util.function.IntSupplier;

/**
 * Specifies the packet direction on a live capture, relative to the network
 * interface.
 * 
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
public enum PcapDirection implements IntSupplier {

	/** Packet's direction is in either direction. */
	DIRECTION_INOUT,
	/** Packet's direction is being received. */
	DIRECTION_IN,
	/** Packet's direction is being transmitted. */
	DIRECTION_OUT,

	;

	/** Packet's direction is in either direction. */
	public static final int PCAP_DIRECTION_INOUT = 0;
	/** Packet's direction is being received. */
	public static final int PCAP_DIRECTION_IN = 1;
	/** Packet's direction is being transmitted. */
	public static final int PCAP_DIRECTION_OUT = 2;

	/**
	 * Converts integer pcap direction value to a constant.
	 *
	 * @param intValue the int value
	 * @return the pcap direction
	 */
	public static PcapDirection valueOf(int intValue) {
		if (intValue < 0 || intValue >= values().length)
			throw new IllegalArgumentException("" + intValue);

		return values()[intValue];
	}

	/**
	 * Gets the as int.
	 *
	 * @return the as int
	 * @see java.util.function.IntSupplier#getAsInt()
	 */
	@Override
	public int getAsInt() {
		return ordinal();
	}
}
