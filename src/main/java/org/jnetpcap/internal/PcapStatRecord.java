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
package org.jnetpcap.internal;

import static java.lang.Integer.toUnsignedLong;
import static java.lang.foreign.MemoryLayout.structLayout;
import static java.lang.foreign.MemoryLayout.PathElement.groupElement;
import static java.lang.foreign.ValueLayout.JAVA_INT;

import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;

import org.jnetpcap.PcapStat;
import org.jnetpcap.windows.WinPcap;

/**
 * Packet statistics from the start of the pcap run to the time of the call.
 *
 * <p>
 * A struct pcap_stat has the following members:
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
 * </p>
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
public record PcapStatRecord(long recv, long drop, long ifdrop, long capt, long sent, long netdrop) implements
		PcapStat {

	/** The Constant LAYOUT. */
	private static final MemoryLayout LAYOUT = structLayout(
			JAVA_INT.withName("ps_recv"),
			JAVA_INT.withName("ps_drop"),
			JAVA_INT.withName("ps_ifdrop"),
			JAVA_INT.withName("ps_capt"), // WIN32
			JAVA_INT.withName("ps_sent"), // WIN32
			JAVA_INT.withName("ps_netdrop") // WIN32
	);

	/** The Constant ps_recv. */
	private static final VarHandle ps_recv = LAYOUT.varHandle(groupElement("ps_recv"));

	/** The Constant ps_drop. */
	private static final VarHandle ps_drop = LAYOUT.varHandle(groupElement("ps_drop"));

	/** The Constant ps_ifdrop. */
	private static final VarHandle ps_ifdrop = LAYOUT.varHandle(groupElement("ps_ifdrop"));

	/** The Constant ps_capt. */
	private static final VarHandle ps_capt = LAYOUT.varHandle(groupElement("ps_ifdrop"));

	/** The Constant ps_sent. */
	private static final VarHandle ps_sent = LAYOUT.varHandle(groupElement("ps_ifdrop"));

	/** The Constant ps_netdrop. */
	private static final VarHandle ps_netdrop = LAYOUT.varHandle(groupElement("ps_ifdrop"));

	/**
	 * Of memory platform dependent.
	 *
	 * @param mseg the mseg
	 * @return the pcap stat
	 */
	public static PcapStat ofMemoryPlatformDependent(MemorySegment mseg) {
		if (WinPcap.isSupported())
			return ofMemoryOnWin32(mseg);

		return new PcapStatRecord(
				toUnsignedLong((int) ps_recv.get(mseg, 0L)),
				toUnsignedLong((int) ps_drop.get(mseg, 0L)),
				toUnsignedLong((int) ps_ifdrop.get(mseg, 0L)),
				0, 0, 0);
	}

	/**
	 * Of memory on win 32.
	 *
	 * @param mseg the mseg
	 * @return the pcap stat
	 */
	private static PcapStat ofMemoryOnWin32(MemorySegment mseg) {
		return new PcapStatRecord(
				toUnsignedLong((int) ps_recv.get(mseg, 0L)),
				toUnsignedLong((int) ps_drop.get(mseg, 0L)),
				toUnsignedLong((int) ps_ifdrop.get(mseg, 0L)),
				toUnsignedLong((int) ps_capt.get(mseg, 0L)),
				toUnsignedLong((int) ps_sent.get(mseg, 0L)),
				toUnsignedLong((int) ps_netdrop.get(mseg, 0L)));
	}

}
