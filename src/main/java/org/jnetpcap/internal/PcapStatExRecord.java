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

import static java.lang.Integer.*;

import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;

import org.jnetpcap.windows.PcapStatEx;

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;
import static java.lang.foreign.ValueLayout.*;

/**
 * The PcapStatExRecord.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 */
public record PcapStatExRecord(
		int size,

		long recv,
		long drop,
		long ifdrop,
		long capt,
		long sent,
		long netdrop,

		long rxPackets,
		long txPackets,
		long rxBytes,
		long txBytes,
		long rxErrors,
		long txErrors,
		long rxDropped,
		long txDropped,
		long multicast,
		long collisions,

		long rxLengthErrors,
		long rxOverErrors,
		long rxCrcErrors,
		long rxFrameErrors,
		long rxFifoErrors,
		long rxMissedErrors,

		long txAbortedErrors,
		long txCarrierErrors,
		long txFifoErrors,
		long txHeartbeatErrors,
		long txWindowErrrors) implements PcapStatEx {

	/** The Constant LAYOUT. */
	private static final MemoryLayout LAYOUT = structLayout(
			JAVA_INT.withName("ps_recv"),
			JAVA_INT.withName("ps_drop"),
			JAVA_INT.withName("ps_ifdrop"),
			JAVA_INT.withName("ps_capt"),
			JAVA_INT.withName("ps_sent"),
			JAVA_INT.withName("ps_netdrop"),

			JAVA_LONG.withName("rx_packets"),
			JAVA_LONG.withName("tx_packets"),
			JAVA_LONG.withName("rx_bytes"),
			JAVA_LONG.withName("tx_bytes"),
			JAVA_LONG.withName("rx_errors"),
			JAVA_LONG.withName("tx_errors"),
			JAVA_LONG.withName("rx_dropped"),
			JAVA_LONG.withName("tx_dropped"),
			JAVA_LONG.withName("multicast_cnt"),
			JAVA_LONG.withName("collisions_cnt"),

			JAVA_LONG.withName("rx_length_errors"),
			JAVA_LONG.withName("rx_over_errors"),
			JAVA_LONG.withName("rx_crc_errors"),
			JAVA_LONG.withName("rx_frame_errors"),
			JAVA_LONG.withName("rx_fifo_errors"),
			JAVA_LONG.withName("rx_missed_errors"),

			JAVA_LONG.withName("tx_aborted_errors"),
			JAVA_LONG.withName("tx_carrier_errors"),
			JAVA_LONG.withName("tx_fifo_errors"),
			JAVA_LONG.withName("tx_heartbeat_errors"),
			JAVA_LONG.withName("tx_window_errors")

	);

	/** The Constant PCAP_STAT_EX_LENGTH. */
	public static final int PCAP_STAT_EX_LENGTH = (int) LAYOUT.byteSize();

	/** The Constant ps_recv. */
	private static final VarHandle ps_recv = LAYOUT.select(groupElement("ps_recv")).varHandle();

	/** The Constant ps_drop. */
	private static final VarHandle ps_drop = LAYOUT.select(groupElement("ps_drop")).varHandle();

	/** The Constant ps_ifdrop. */
	private static final VarHandle ps_ifdrop = LAYOUT.select(groupElement("ps_ifdrop")).varHandle();

	/** The Constant ps_capt. */
	private static final VarHandle ps_capt = LAYOUT.select(groupElement("ps_ifdrop")).varHandle();

	/** The Constant ps_sent. */
	private static final VarHandle ps_sent = LAYOUT.select(groupElement("ps_ifdrop")).varHandle();

	/** The Constant ps_netdrop. */
	private static final VarHandle ps_netdrop = LAYOUT.select(groupElement("ps_ifdrop")).varHandle();

	/** The Constant rx_packets. */
	private static final VarHandle rx_packets = LAYOUT.select(groupElement("rx_packets")).varHandle();

	/** The Constant tx_packets. */
	private static final VarHandle tx_packets = LAYOUT.select(groupElement("tx_packets")).varHandle();

	/** The Constant rx_bytes. */
	private static final VarHandle rx_bytes = LAYOUT.select(groupElement("rx_bytes")).varHandle();

	/** The Constant tx_bytes. */
	private static final VarHandle tx_bytes = LAYOUT.select(groupElement("tx_bytes")).varHandle();

	/** The Constant rx_errors. */
	private static final VarHandle rx_errors = LAYOUT.select(groupElement("rx_errors")).varHandle();

	/** The Constant tx_errors. */
	private static final VarHandle tx_errors = LAYOUT.select(groupElement("tx_errors")).varHandle();

	/** The Constant rx_dropped. */
	private static final VarHandle rx_dropped = LAYOUT.select(groupElement("rx_dropped")).varHandle();

	/** The Constant tx_dropped. */
	private static final VarHandle tx_dropped = LAYOUT.select(groupElement("tx_dropped")).varHandle();

	/** The Constant multicast_cnt. */
	private static final VarHandle multicast_cnt = LAYOUT.select(groupElement("multicast_cnt")).varHandle();

	/** The Constant collisions_cnt. */
	private static final VarHandle collisions_cnt = LAYOUT.select(groupElement("collisions_cnt")).varHandle();

	/** The Constant rx_length_errors. */
	private static final VarHandle rx_length_errors = LAYOUT.select(groupElement("rx_length_errors")).varHandle();

	/** The Constant rx_over_errors. */
	private static final VarHandle rx_over_errors = LAYOUT.select(groupElement("rx_over_errors")).varHandle();

	/** The Constant rx_crc_errors. */
	private static final VarHandle rx_crc_errors = LAYOUT.select(groupElement("rx_crc_errors")).varHandle();

	/** The Constant rx_frame_errors. */
	private static final VarHandle rx_frame_errors = LAYOUT.select(groupElement("rx_frame_errors")).varHandle();

	/** The Constant rx_fifo_errors. */
	private static final VarHandle rx_fifo_errors = LAYOUT.select(groupElement("rx_fifo_errors")).varHandle();

	/** The Constant rx_missed_errors. */
	private static final VarHandle rx_missed_errors = LAYOUT.select(groupElement("rx_missed_errors")).varHandle();

	/** The Constant tx_aborted_errors. */
	private static final VarHandle tx_aborted_errors = LAYOUT.select(groupElement("tx_aborted_errors")).varHandle();

	/** The Constant tx_carrier_errors. */
	private static final VarHandle tx_carrier_errors = LAYOUT.select(groupElement("tx_carrier_errors")).varHandle();

	/** The Constant tx_fifo_errors. */
	private static final VarHandle tx_fifo_errors = LAYOUT.select(groupElement("tx_fifo_errors")).varHandle();

	/** The Constant tx_heartbeat_errors. */
	private static final VarHandle tx_heartbeat_errors = LAYOUT.select(groupElement("tx_heartbeat_errors")).varHandle();

	/** The Constant tx_window_errors. */
	private static final VarHandle tx_window_errors = LAYOUT.select(groupElement("tx_window_errors")).varHandle();

	/**
	 * Instantiates a new pcap stat ex record.
	 *
	 * @param size the size
	 * @param mseg the mseg
	 */
	public PcapStatExRecord(int size, MemorySegment mseg) {
		this(
				size,

				toUnsignedLong((int) ps_recv.get(mseg, 0L)),
				toUnsignedLong((int) ps_drop.get(mseg, 0L)),
				toUnsignedLong((int) ps_ifdrop.get(mseg, 0L)),
				toUnsignedLong((int) ps_capt.get(mseg, 0L)),
				toUnsignedLong((int) ps_sent.get(mseg, 0L)),
				toUnsignedLong((int) ps_netdrop.get(mseg, 0L)),

				(long) rx_packets.get(mseg, 0L),
				(long) tx_packets.get(mseg, 0L),
				(long) rx_bytes.get(mseg, 0L),
				(long) tx_bytes.get(mseg, 0L),
				(long) rx_errors.get(mseg, 0L),
				(long) tx_errors.get(mseg, 0L),
				(long) rx_dropped.get(mseg, 0L),
				(long) tx_dropped.get(mseg, 0L),
				(long) multicast_cnt.get(mseg, 0L),
				(long) collisions_cnt.get(mseg, 0L),

				(long) rx_length_errors.get(mseg, 0L),
				(long) rx_over_errors.get(mseg, 0L),
				(long) rx_crc_errors.get(mseg, 0L),
				(long) rx_frame_errors.get(mseg, 0L),
				(long) rx_fifo_errors.get(mseg, 0L),
				(long) rx_missed_errors.get(mseg, 0L),

				(long) tx_aborted_errors.get(mseg, 0L),
				(long) tx_carrier_errors.get(mseg, 0L),
				(long) tx_fifo_errors.get(mseg, 0L),
				(long) tx_heartbeat_errors.get(mseg, 0L),
				(long) tx_window_errors.get(mseg, 0L)

		);
	}
}
