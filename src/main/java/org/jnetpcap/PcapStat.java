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
package org.jnetpcap;

import org.jnetpcap.internal.PcapStatRecord;
import org.jnetpcap.windows.PcapStatEx;

/**
 * Provides packet statistics from the start of the pcap run to the time of the
 * call.
 * 
 * <p>
 * The {@code PcapStat} interface models the packet statistics similar to the
 * {@code struct pcap_stat} in the libpcap library. The statistics include:
 * </p>
 * <dl>
 * <dt>recv()</dt>
 * <dd>Number of packets received.</dd>
 * <dt>drop()</dt>
 * <dd>Number of packets dropped because there was no room in the operating
 * system's buffer when they arrived, or because packets weren't being read fast
 * enough.</dd>
 * <dt>ifdrop()</dt>
 * <dd>Number of packets dropped by the network interface or its driver.</dd>
 * <dt>netdrop()</dt>
 * <dd>Number of packets dropped by the network.</dd>
 * <dt>capt()</dt>
 * <dd>Number of packets captured.</dd>
 * <dt>sent()</dt>
 * <dd>Number of packets sent.</dd>
 * </dl>
 * <p>
 * Note that the behavior of these statistics may vary across different
 * platforms:
 * </p>
 * <ul>
 * <li>{@code recv()} might count all packets, whether they pass any filter set
 * with {@code pcap_setfilter(3PCAP)} or not, or only those that pass the
 * filter. It might also include packets dropped because there was no room in
 * the operating system's buffer.</li>
 * <li>{@code drop()} is not available on all platforms and may return zero on
 * platforms where it is not available. It might count packets that don't pass
 * the filter if packet filtering is done in libpcap rather than the operating
 * system.</li>
 * <li>Both {@code recv()} and {@code drop()} might include packets not yet read
 * from the operating system and thus not yet seen by the application.</li>
 * <li>{@code ifdrop()} might not be implemented on all platforms; if it returns
 * zero, it might indicate either that no packets were dropped by the interface
 * or that the statistic is unavailable.</li>
 * </ul>
 * 
 * <p>
 * Implementations of this interface are provided by {@link PcapStatRecord} and
 * {@link PcapStatEx}.
 * </p>
 * 
 * @see PcapStatRecord
 * @see PcapStatEx
 * @see <a href="https://www.tcpdump.org/manpages/pcap.3pcap.html">pcap(3PCAP)
 *      man page</a>
 * @see <a href=
 *      "https://www.tcpdump.org/manpages/pcap_setfilter.3pcap.html">pcap_setfilter(3PCAP)
 *      man page</a>
 * @see <a href="http://www.slytechs.com/free-license-text">Sly Technologies
 *      Free License</a>
 * 
 * @since 1.0
 * 
 */
public sealed interface PcapStat permits PcapStatRecord, PcapStatEx {

	/**
	 * Gets the number of packets captured.
	 *
	 * @return the number of packets captured
	 */
	long capt();

	/**
	 * Gets the number of packets dropped because there was no room in the operating
	 * system's buffer when they arrived, or because packets weren't being read fast
	 * enough.
	 *
	 * @return the number of packets dropped
	 */
	long drop();

	/**
	 * Gets the number of packets dropped by the network interface or its driver.
	 *
	 * @return the number of packets dropped by the network interface or its driver
	 */
	long ifdrop();

	/**
	 * Gets the number of packets dropped by the network.
	 *
	 * @return the number of packets dropped by the network
	 */
	long netdrop();

	/**
	 * Gets the number of packets received.
	 *
	 * @return the number of packets received
	 */
	long recv();

	/**
	 * Gets the number of packets sent.
	 *
	 * @return the number of packets sent
	 */
	long sent();
}
