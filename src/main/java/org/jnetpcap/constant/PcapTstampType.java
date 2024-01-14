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

import java.util.Optional;
import java.util.function.IntSupplier;

/**
 * Time stamp types. Not all systems and interfaces will necessarily support all
 * of these.
 *
 * A system that supports PCAP_TSTAMP_HOST is offering time stamps provided by
 * the host machine, rather than by the capture device, but not committing to
 * any characteristics of the time stamp.
 *
 * PCAP_TSTAMP_HOST_LOWPREC is a time stamp, provided by the host machine,
 * that's low-precision but relatively cheap to fetch; it's normally done using
 * the system clock, so it's normally synchronized with times you'd fetch from
 * system calls.
 *
 * PCAP_TSTAMP_HOST_HIPREC is a time stamp, provided by the host machine, that's
 * high-precision; it might be more expensive to fetch. It is synchronized with
 * the system clock.
 *
 * PCAP_TSTAMP_HOST_HIPREC_UNSYNCED is a time stamp, provided by the host
 * machine, that's high-precision; it might be more expensive to fetch. It is
 * not synchronized with the system clock, and might have problems with time
 * stamps for packets received on different CPUs, depending on the platform. It
 * might be more likely to be strictly monotonic than PCAP_TSTAMP_HOST_HIPREC.
 *
 * PCAP_TSTAMP_ADAPTER is a high-precision time stamp supplied by the capture
 * device; it's synchronized with the system clock.
 *
 * PCAP_TSTAMP_ADAPTER_UNSYNCED is a high-precision time stamp supplied by the
 * capture device; it's not synchronized with the system clock.
 *
 * Note that time stamps synchronized with the system clock can go backwards, as
 * the system clock can go backwards. If a clock is not in sync with the system
 * clock, that could be because the system clock isn't keeping accurate time,
 * because the other clock isn't keeping accurate time, or both.
 *
 * Note that host-provided time stamps generally correspond to the time when the
 * time-stamping full sees the packet; this could be some unknown amount of time
 * after the first or last bit of the packet is received by the network adapter,
 * due to batching of interrupts for packet arrival, queueing delays, etc..
 * 
 * <pre>
 * <code>
#define PCAP_TSTAMP_HOST			        0	// host-provided, unknown characteristics
#define PCAP_TSTAMP_HOST_LOWPREC		    1	// host-provided, low precision, synced with the system clock
#define PCAP_TSTAMP_HOST_HIPREC			    2	// host-provided, high precision, synced with the system clock
#define PCAP_TSTAMP_ADAPTER			        3	// device-provided, synced with the system clock
#define PCAP_TSTAMP_ADAPTER_UNSYNCED		4	// device-provided, not synced with the system clock
#define PCAP_TSTAMP_HOST_HIPREC_UNSYNCED	5	// host-provided, high precision, not synced with the system clock 
 * </code>
 * </pre>
 * 
 * @author mark
 *
 */
public enum PcapTstampType implements IntSupplier {

	/** host-provided, unknown characteristics. */
	TSTAMP_TYPE_HOST,

	/** host-provided, low precision, synced with the system clock. */
	TSTAMP_TYPE_HOST_LOWPREC,

	/** host-provided, high precision, synced with the system clock. */
	TSTAMP_TYPE_HOST_HIPREC,

	/** device-provided, synced with the system clock. */
	TSTAMP_TYPE_ADAPTER,

	/** device-provided, not synced with the system clock. */
	TSTAMP_TYPE_ADAPTER_UNSYNCED,

	/** host-provided, high precision, not synced with the system clock. */
	TSTAMP_TYPE_HOST_HIPREC_UNSYNCED;

	/** host-provided, unknown characteristics. */
	public static final int PCAP_TSTAMP_HOST = 0;

	/** host-provided, low precision, synced with the system clock. */
	public static final int PCAP_TSTAMP_HOST_LOWPREC = 1;

	/** host-provided, high precision, synced with the system clock. */
	public static final int PCAP_TSTAMP_HOST_HIPREC = 2;

	/** device-provided, synced with the system clock. */
	public static final int PCAP_TSTAMP_ADAPTER = 3;

	/** device-provided, not synced with the system clock. */
	public static final int PCAP_TSTAMP_ADAPTER_UNSYNCED = 4;

	/** host-provided, high precision, not synced with the system clock. */
	public static final int PCAP_TSTAMP_HOST_HIPREC_UNSYNCED = 5;

	/**
	 * Converts numerical TSTAMP_TYPE constant to an enum, if found.
	 *
	 * @param tstampType the PCAP integer timestamp type constant
	 * @return the optional enum constant
	 */
	public static Optional<PcapTstampType> toEnum(int tstampType) {
		if (tstampType < 0 || tstampType >= values().length)
			Optional.empty();

		return Optional.of(values()[tstampType]);
	}

	/**
	 * Converts numerical TSTAMP_TYPE constant to an enum.
	 *
	 * @param tstampType the PCAP integer timestamp type constant
	 * @return the PCAP timestamp type enum constant
	 * @throws IllegalArgumentException thrown if not found
	 */
	public static PcapTstampType valueOf(int tstampType) throws IllegalArgumentException {
		if (tstampType < 0 || tstampType >= values().length)
			throw new IllegalArgumentException(Integer.toString(tstampType));

		return values()[tstampType];
	}

	/**
	 * Get TSTAMP_TYPE numerical constant.
	 *
	 * @return the timestamp type constant
	 * @see java.util.function.IntSupplier#getAsInt()
	 */
	@Override
	public int getAsInt() {
		return ordinal();
	}
}
