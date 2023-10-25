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
 * Packet statistics from the start of the pcap run to the time of the call.
 * 
 * <p>
 * A struct pcap_stat has the following members:
 * </p>
 * <dl>
 * <dt>ps_recv</dt>
 * <dd>number of packets received;</dd>
 * <dt>ps_drop</dt>
 * <dd>number of packets dropped because there was no room in the operating
 * system's buffer when they arrived, because packets weren't being read fast
 * enough;</dd>
 * <dt>ps_ifdrop</dt>
 * <dd>number of packets dropped by the network interface or its driver.</dd>
 * </dl>
 * <p>
 * The statistics do not behave the same way on all platforms. ps_recv might
 * count packets whether they passed any filter set with pcap_setfilter(3PCAP)
 * or not, or it might count only packets that pass the filter. It also might,
 * or might not, count packets dropped because there was no room in the
 * operating system's buffer when they arrived. ps_drop is not available on all
 * platforms; it is zero on platforms where it's not available. If packet
 * filtering is done in libpcap, rather than in the operating system, it would
 * count packets that don't pass the filter. Both ps_recv and ps_drop might, or
 * might not, count packets not yet read from the operating system and thus not
 * yet seen by the application. ps_ifdrop might, or might not, be implemented;
 * if it's zero, that might mean that no packets were dropped by the interface,
 * or it might mean that the statistic is unavailable, so it should not be
 * treated as an indication that the interface did not drop any packets.
 * </p>
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public sealed interface PcapStat permits PcapStatRecord, PcapStatEx {

	/**
	 * Capt.
	 *
	 * @return the long
	 */
	long capt();

	/**
	 * number of packets dropped because there was no room in the operating system's
	 * buffer when they arrived, because packets weren't being read fast enough.
	 *
	 * @return the long
	 */
	long drop();

	/**
	 * number of packets dropped by the network interface or its driver.
	 *
	 * @return the long
	 */
	long ifdrop();

	/**
	 * Netdrop.
	 *
	 * @return the long
	 */
	long netdrop();

	/**
	 * number of packets received.
	 *
	 * @return the long
	 */
	long recv();

	/**
	 * Sent.
	 *
	 * @return the long
	 */
	long sent();
}