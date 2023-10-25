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

/**
 * Pcap live capture mode flags.
 * 
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
public enum PcapMode {
	/**
	 * Flag used with <code>openLive</code> to specify that the interface should be
	 * put into non-promisuous mode.
	 */
	NON_PROMISCOUS,
	/**
	 * Flag used with <code>openLive</code> to specify that the interface should be
	 * put into promisuous mode.
	 */
	PROMISCUOUS,

	;

	/**
	 * Flag used with <code>openLive</code> to specify that the interface should be
	 * put into non-promisuous mode.
	 */
	public static final int PCAP_MODE_NON_PROMISCUOUS = 0;

	/**
	 * Flag used with <code>openLive</code> to specify that the interface should be
	 * put into promisuous mode.
	 */
	public static final int PCAP_MODE_PROMISCUOUS = 1;

	/**
	 * Value of.
	 *
	 * @param intValue the int value
	 * @return the pcap mode
	 */
	public static PcapMode valueOf(int intValue) {
		if (intValue < 0 || intValue >= values().length)
			throw new IllegalArgumentException("" + intValue);

		return values()[intValue];
	}
}
