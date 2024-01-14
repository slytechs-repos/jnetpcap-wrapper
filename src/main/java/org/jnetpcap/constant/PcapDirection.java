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
	 * Converts integer pcap direction value to an enum.
	 *
	 * @param direction an integer PCAP direction constant
	 * @return the pcap direction enum
	 * @throws IllegalArgumentException thrown if not found
	 */
	public static PcapDirection valueOf(int direction) throws IllegalArgumentException {
		if (direction < 0 || direction >= values().length)
			throw new IllegalArgumentException(Integer.toString(direction));

		return values()[direction];
	}

	/**
	 * Converts integer pcap direction value to an enum.
	 *
	 * @param direction the direction
	 * @return the optional
	 */
	public static Optional<PcapDirection> toEnum(int direction) {
		if (direction < 0 || direction >= values().length)
			return Optional.empty();

		return Optional.of(values()[direction]);
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
