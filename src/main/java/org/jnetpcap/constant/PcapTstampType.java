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
 * Enumeration of timestamp types. Not all systems and interfaces will
 * necessarily support all of these.
 *
 * <p>
 * A system that supports {@link #TSTAMP_TYPE_HOST} offers timestamps provided
 * by the host machine, rather than by the capture device, but does not commit
 * to any specific characteristics of the timestamp.
 * </p>
 *
 * <p>
 * {@link #TSTAMP_TYPE_HOST_LOWPREC} is a timestamp provided by the host
 * machine, characterized by low precision but relatively low overhead to fetch.
 * It is typically obtained using the system clock, ensuring synchronization
 * with times fetched via system calls.
 * </p>
 *
 * <p>
 * {@link #TSTAMP_TYPE_HOST_HIPREC} is a high-precision timestamp provided by
 * the host machine, which might incur higher overhead to fetch. It is
 * synchronized with the system clock.
 * </p>
 *
 * <p>
 * {@link #TSTAMP_TYPE_HOST_HIPREC_UNSYNCED} is a high-precision timestamp
 * provided by the host machine, not synchronized with the system clock. It
 * might have issues with timestamps for packets received on different CPUs
 * depending on the platform but may be more strictly monotonic than
 * {@link #TSTAMP_TYPE_HOST_HIPREC}.
 * </p>
 *
 * <p>
 * {@link #TSTAMP_TYPE_ADAPTER} is a high-precision timestamp supplied by the
 * capture device, synchronized with the system clock.
 * </p>
 *
 * <p>
 * {@link #TSTAMP_TYPE_ADAPTER_UNSYNCED} is a high-precision timestamp supplied
 * by the capture device, not synchronized with the system clock.
 * </p>
 *
 * <p>
 * Note that timestamps synchronized with the system clock can go backwards, as
 * the system clock itself can go backwards. If a clock is not synchronized with
 * the system clock, the discrepancy might be due to inaccuracies in either the
 * system clock or the other clock, or both.
 * </p>
 *
 * <p>
 * Host-provided timestamps typically correspond to the time when the
 * timestamping facility sees the packet, which could be delayed due to factors
 * like batching of interrupts for packet arrival or queueing delays.
 * </p>
 * 
 */
public enum PcapTstampType implements IntSupplier {

	/** Host-provided timestamp with unknown characteristics. */
	TSTAMP_TYPE_HOST,

	/** Host-provided, low precision, synchronized with the system clock. */
	TSTAMP_TYPE_HOST_LOWPREC,

	/** Host-provided, high precision, synchronized with the system clock. */
	TSTAMP_TYPE_HOST_HIPREC,

	/** Device-provided, high precision, synchronized with the system clock. */
	TSTAMP_TYPE_ADAPTER,

	/** Device-provided, high precision, not synchronized with the system clock. */
	TSTAMP_TYPE_ADAPTER_UNSYNCED,

	/** Host-provided, high precision, not synchronized with the system clock. */
	TSTAMP_TYPE_HOST_HIPREC_UNSYNCED;

	/**
	 * Converts a numerical timestamp type constant to an enum, if found.
	 *
	 * @param tstampType the integer timestamp type constant
	 * @return an optional enum constant
	 */
	public static Optional<PcapTstampType> toEnum(int tstampType) {
		if (tstampType < 0 || tstampType >= values().length) {
			return Optional.empty();
		}
		return Optional.of(values()[tstampType]);
	}

	/**
	 * Converts a numerical timestamp type constant to an enum.
	 *
	 * @param tstampType the integer timestamp type constant
	 * @return the corresponding enum constant
	 * @throws IllegalArgumentException if the constant is not found
	 */
	public static PcapTstampType valueOf(int tstampType) throws IllegalArgumentException {
		if (tstampType < 0 || tstampType >= values().length) {
			throw new IllegalArgumentException(Integer.toString(tstampType));
		}
		return values()[tstampType];
	}

	/**
	 * Returns the numerical timestamp type constant.
	 *
	 * @return the timestamp type constant
	 * @see java.util.function.IntSupplier#getAsInt()
	 */
	@Override
	public int getAsInt() {
		return ordinal();
	}
}
