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

import java.util.function.IntSupplier;

/**
 * Enumeration of timestamp precision types. Not all systems and interfaces will
 * necessarily support all of these resolutions when capturing live packets;
 * however, all can be requested when reading from a savefile.
 * 
 * <p>
 * Timestamps can be either in microseconds or nanoseconds precision. The
 * default precision is microseconds.
 * </p>
 * 
 * <ul>
 * <li>{@link #TSTAMP_PRECISION_MICRO}: Use timestamps with microsecond
 * precision (default).</li>
 * <li>{@link #TSTAMP_PRECISION_NANO}: Use timestamps with nanosecond
 * precision.</li>
 * </ul>
 * 
 * <p>
 * Example usage:
 * </p>
 * 
 * <pre>{@code
 * PcapTStampPrecision precision = PcapTStampPrecision.TSTAMP_PRECISION_MICRO;
 * }</pre>
 * 
 */
public enum PcapTStampPrecision implements IntSupplier {

	/** Use timestamps with microsecond precision (default). */
	TSTAMP_PRECISION_MICRO(1_000_000),

	/** Use timestamps with nanosecond precision. */
	TSTAMP_PRECISION_NANO(1_000_000_000);

	/** Constant for microsecond precision. */
	public static final int PCAP_TSTAMP_PRECISION_MICRO = 0;

	/** Constant for nanosecond precision. */
	public static final int PCAP_TSTAMP_PRECISION_NANO = 1;

	/** Scale of the fractional unit. */
	private final long scale;

	/**
	 * Instantiates a new PcapTStampPrecision with the specified scale.
	 *
	 * @param scale the scale of the fractional unit
	 */
	PcapTStampPrecision(long scale) {
		this.scale = scale;
	}

	/**
	 * Converts a numerical value to the corresponding PcapTStampPrecision enum.
	 *
	 * @param value the numerical value
	 * @return the corresponding PcapTStampPrecision enum
	 */
	public static PcapTStampPrecision valueOf(int value) {
		return values()[value];
	}

	/**
	 * Returns the numerical constant for this timestamp precision.
	 *
	 * @return the numerical constant
	 * @see java.util.function.IntSupplier#getAsInt()
	 */
	@Override
	public int getAsInt() {
		return ordinal();
	}

	/**
	 * Converts epoch seconds and fraction of a second to milliseconds since the
	 * start of the epoch.
	 *
	 * @param epochSeconds     the epoch seconds
	 * @param fractionOfSecond the fraction of a second
	 * @return the number of milliseconds since the start of the epoch
	 */
	public long toEpochMilli(long epochSeconds, long fractionOfSecond) {
		long scaleToMillis = (scale / 1000);
		return toEpochTime(epochSeconds, fractionOfSecond) / scaleToMillis;
	}

	/**
	 * Converts the epoch time in this precision to epoch seconds.
	 *
	 * @param epochTime the epoch time in this precision
	 * @return the number of seconds since the start of the epoch
	 */
	public long toEpochSecond(long epochTime) {
		return (epochTime / scale);
	}

	/**
	 * Converts epoch seconds and fraction of a second to epoch time in this
	 * precision.
	 *
	 * @param epochSeconds     the epoch seconds
	 * @param fractionOfSecond the fraction of a second in this precision
	 * @return the number of fractional units in this precision since the start of
	 *         the epoch
	 */
	public long toEpochTime(long epochSeconds, long fractionOfSecond) {
		return (epochSeconds * scale) + fractionOfSecond;
	}

	/**
	 * Extracts the fraction of a second from the given epoch time in this
	 * precision.
	 *
	 * @param epochTime the epoch time
	 * @return the fraction of a second in this precision
	 */
	public long toFractionOfSecond(long epochTime) {
		return (epochTime % scale);
	}
}
