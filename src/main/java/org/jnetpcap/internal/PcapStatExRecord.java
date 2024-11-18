/*
 * Copyright 2023-2024 Sly Technologies Inc
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
 * Represents extended statistics about network interface performance and error
 * counts. This record encapsulates both standard pcap statistics and additional
 * network interface statistics typically available on Linux and Windows
 * systems.
 * 
 * <h2>Statistics Categories</h2> The statistics are grouped into several
 * categories:
 * 
 * <h3>1. Basic Pcap Statistics</h3>
 * <ul>
 * <li>recv - Packets received by the interface</li>
 * <li>drop - Packets dropped by the interface due to insufficient buffer
 * space</li>
 * <li>ifdrop - Packets dropped by the interface driver</li>
 * <li>capt - Packets actually captured and processed</li>
 * <li>sent - Packets sent by the interface</li>
 * <li>netdrop - Packets dropped by the network</li>
 * </ul>
 * 
 * <h3>2. General Interface Statistics</h3>
 * <ul>
 * <li>rxPackets/txPackets - Total packets received/transmitted</li>
 * <li>rxBytes/txBytes - Total bytes received/transmitted</li>
 * <li>rxErrors/txErrors - Total error counts for receive/transmit</li>
 * <li>rxDropped/txDropped - Packets dropped during receive/transmit</li>
 * <li>multicast - Multicast packets received</li>
 * <li>collisions - Number of collisions detected</li>
 * </ul>
 * 
 * <h3>3. Detailed Receive Errors</h3>
 * <ul>
 * <li>rxLengthErrors - Packets dropped due to incorrect length</li>
 * <li>rxOverErrors - Receiver ring buffer overflow errors</li>
 * <li>rxCrcErrors - Packets with CRC/FCS errors</li>
 * <li>rxFrameErrors - Packets with frame alignment errors</li>
 * <li>rxFifoErrors - FIFO buffer errors</li>
 * <li>rxMissedErrors - Packets missed due to lack of resources</li>
 * </ul>
 * 
 * <h3>4. Detailed Transmit Errors</h3>
 * <ul>
 * <li>txAbortedErrors - Transmission aborted errors</li>
 * <li>txCarrierErrors - Carrier errors during transmission</li>
 * <li>txFifoErrors - FIFO buffer errors during transmission</li>
 * <li>txHeartbeatErrors - Heartbeat errors during transmission</li>
 * <li>txWindowErrors - TCP window errors during transmission</li>
 * </ul>
 * 
 * <h2>Usage Example</h2>
 * 
 * <pre>{@code 
 * PcapStatExRecord stats = ...;
 * 
 * // Check basic packet statistics
 * long packetsReceived = stats.recv();
 * long packetsDropped = stats.drop();
 * 
 * // Analyze error rates
 * double errorRate = (double) stats.rxErrors() / stats.rxPackets();
 * 
 * // Check specific error types
 * if (stats.rxCrcErrors() > 0) {
 *     // Handle CRC errors
 * }
 * }</pre>
 * 
 * @see org.jnetpcap.windows.PcapStatEx
 * @author Mark Bednarczyk
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

	/** The Constant rx_packets. */
	private static final VarHandle rx_packets = LAYOUT.varHandle(groupElement("rx_packets"));

	/** The Constant tx_packets. */
	private static final VarHandle tx_packets = LAYOUT.varHandle(groupElement("tx_packets"));

	/** The Constant rx_bytes. */
	private static final VarHandle rx_bytes = LAYOUT.varHandle(groupElement("rx_bytes"));

	/** The Constant tx_bytes. */
	private static final VarHandle tx_bytes = LAYOUT.varHandle(groupElement("tx_bytes"));

	/** The Constant rx_errors. */
	private static final VarHandle rx_errors = LAYOUT.varHandle(groupElement("rx_errors"));

	/** The Constant tx_errors. */
	private static final VarHandle tx_errors = LAYOUT.varHandle(groupElement("tx_errors"));

	/** The Constant rx_dropped. */
	private static final VarHandle rx_dropped = LAYOUT.varHandle(groupElement("rx_dropped"));

	/** The Constant tx_dropped. */
	private static final VarHandle tx_dropped = LAYOUT.varHandle(groupElement("tx_dropped"));

	/** The Constant multicast_cnt. */
	private static final VarHandle multicast_cnt = LAYOUT.varHandle(groupElement("multicast_cnt"));

	/** The Constant collisions_cnt. */
	private static final VarHandle collisions_cnt = LAYOUT.varHandle(groupElement("collisions_cnt"));

	/** The Constant rx_length_errors. */
	private static final VarHandle rx_length_errors = LAYOUT.varHandle(groupElement("rx_length_errors"));

	/** The Constant rx_over_errors. */
	private static final VarHandle rx_over_errors = LAYOUT.varHandle(groupElement("rx_over_errors"));

	/** The Constant rx_crc_errors. */
	private static final VarHandle rx_crc_errors = LAYOUT.varHandle(groupElement("rx_crc_errors"));

	/** The Constant rx_frame_errors. */
	private static final VarHandle rx_frame_errors = LAYOUT.varHandle(groupElement("rx_frame_errors"));

	/** The Constant rx_fifo_errors. */
	private static final VarHandle rx_fifo_errors = LAYOUT.varHandle(groupElement("rx_fifo_errors"));

	/** The Constant rx_missed_errors. */
	private static final VarHandle rx_missed_errors = LAYOUT.varHandle(groupElement("rx_missed_errors"));

	/** The Constant tx_aborted_errors. */
	private static final VarHandle tx_aborted_errors = LAYOUT.varHandle(groupElement("tx_aborted_errors"));

	/** The Constant tx_carrier_errors. */
	private static final VarHandle tx_carrier_errors = LAYOUT.varHandle(groupElement("tx_carrier_errors"));

	/** The Constant tx_fifo_errors. */
	private static final VarHandle tx_fifo_errors = LAYOUT.varHandle(groupElement("tx_fifo_errors"));

	/** The Constant tx_heartbeat_errors. */
	private static final VarHandle tx_heartbeat_errors = LAYOUT.varHandle(groupElement("tx_heartbeat_errors"));

	/** The Constant tx_window_errors. */
	private static final VarHandle tx_window_errors = LAYOUT.varHandle(groupElement("tx_window_errors"));

	/**
	 * Returns the size of the native pcap_stat_ex structure in bytes. This value is
	 * platform-dependent and may vary based on the operating system and
	 * architecture.
	 *
	 * @return The size of the native structure in bytes
	 */
	public static long sizeOf() {
		return LAYOUT.byteSize();
	}

	/**
	 * Creates a new PcapStatExRecord instance from a native memory segment. This
	 * constructor reads all statistics fields from the native memory and converts
	 * them to appropriate Java types.
	 *
	 * @param size The expected size of the native structure
	 * @param mseg The memory segment containing the native pcap_stat_ex structure
	 * @throws IllegalArgumentException if the memory segment size doesn't match the
	 *                                  expected size
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
