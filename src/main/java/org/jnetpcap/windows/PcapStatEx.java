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
package org.jnetpcap.windows;

import org.jnetpcap.PcapStat;
import org.jnetpcap.internal.PcapStatExRecord;

/**
 * The Interface PcapStatEx.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 */
public sealed interface PcapStatEx extends PcapStat permits PcapStatExRecord {

	/** The length of the pcap_stat_ex structure in bytes. */
	public static final int PCAP_STAT_EX_LENGTH = PcapStatExRecord.PCAP_STAT_EX_LENGTH;

	/**
	 * Size of this structure in bytes. Is used to differentiate between the
	 * standard size pcap_stat structure and pcap_stat_ex. The lengths will be
	 * different.
	 *
	 * @return the int
	 */
	int size();

	/**
	 * Recv.
	 *
	 * @return the long
	 * @see org.jnetpcap.PcapStat#recv()
	 */
	@Override
	long recv();

	/**
	 * Drop.
	 *
	 * @return the long
	 * @see org.jnetpcap.PcapStat#drop()
	 */
	@Override
	long drop();

	/**
	 * Ifdrop.
	 *
	 * @return the long
	 * @see org.jnetpcap.PcapStat#ifdrop()
	 */
	@Override
	long ifdrop();

	/**
	 * Capt.
	 *
	 * @return the long
	 * @see org.jnetpcap.PcapStat#capt()
	 */
	@Override
	long capt();

	/**
	 * Sent.
	 *
	 * @return the long
	 * @see org.jnetpcap.PcapStat#sent()
	 */
	@Override
	long sent();

	/**
	 * Netdrop.
	 *
	 * @return the long
	 * @see org.jnetpcap.PcapStat#netdrop()
	 */
	@Override
	long netdrop();

	/**
	 * total packets received.
	 *
	 * @return the long
	 */
	long rxPackets();

	/**
	 * total packets transmitted.
	 *
	 * @return the long
	 */
	long txPackets();

	/**
	 * total bytes received.
	 *
	 * @return the long
	 */
	long rxBytes();

	/**
	 * total bytes transmitted.
	 *
	 * @return the long
	 */
	long txBytes();

	/**
	 * bad packets received.
	 *
	 * @return the long
	 */
	long rxErrors();

	/**
	 * packet transmit problems.
	 *
	 * @return the long
	 */
	long txErrors();

	/**
	 * no space in Rx buffers.
	 *
	 * @return the long
	 */
	long rxDropped();

	/**
	 * no space available for Tx.
	 *
	 * @return the long
	 */
	long txDropped();

	/**
	 * multicast packets received.
	 *
	 * @return the long
	 */
	long multicast();

	/**
	 * Collisions.
	 *
	 * @return the long
	 */
	long collisions();

	/**
	 * Rx length errors.
	 *
	 * @return the long
	 */
	long rxLengthErrors();

	/**
	 * receiver ring buff overflow.
	 *
	 * @return the long
	 */
	long rxOverErrors();

	/**
	 * recv'd pkt with crc error.
	 *
	 * @return the long
	 */
	long rxCrcErrors();

	/**
	 * recv'd frame alignment error.
	 *
	 * @return the long
	 */
	long rxFrameErrors();

	/**
	 * recv'r fifo overrun.
	 *
	 * @return the long
	 */
	long rxFifoErrors();

	/**
	 * recv'r missed packet.
	 *
	 * @return the long
	 */
	long rxMissedErrors();

	/**
	 * Tx aborted errors.
	 *
	 * @return the long
	 */
	long txAbortedErrors();

	/**
	 * Tx carrier errros.
	 *
	 * @return the long
	 */
	long txCarrierErrors();

	/**
	 * Tx fifo errors.
	 *
	 * @return the long
	 */
	long txFifoErrors();

	/**
	 * Tx heartbeat errors.
	 *
	 * @return the long
	 */
	long txHeartbeatErrors();

	/**
	 * Tx window errrors.
	 *
	 * @return the long
	 */
	long txWindowErrrors();
}
