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

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemoryLayout.PathElement;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.VarHandle;

import org.jnetpcap.Pcap.Linux;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.internal.PcapForeignDowncall;
import org.jnetpcap.internal.PcapForeignInitializer;

/**
 * A queue of raw packets that will be sent to the network with {@code transmit}
 * on Microsoft Windows platforms.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 */
public class PcapSendQueue implements AutoCloseable {

	/**
	 * The Class Struct.
	 *
	 * <pre>
	struct pcap_send_queue {
		u_int maxlen;	// Maximum size of the queue, in bytes. This variable contains the size of the buffer field.
		u_int len;	// Current size of the queue, in bytes.
		char *buffer;	// Buffer containing the packets to be sent.
	};
	 * </pre>
	 */
	@SuppressWarnings("unused")
	private static class Struct {

		/** The Constant LAYOUT. */
		private static final MemoryLayout LAYOUT = MemoryLayout.structLayout(
				ValueLayout.JAVA_INT.withName("maxlen"), /*
															 * Maximum size of the queue, in bytes. This variable
															 * contains the size of the buffer field.
															 */
				ValueLayout.JAVA_INT.withName("len"), /* Current size of the queue, in bytes. */
				ValueLayout.ADDRESS.withName("buffer")); /* Buffer containing the packets to be sent. */

		/** The Constant MAXLEN. */
		private static final VarHandle MAXLEN = LAYOUT.varHandle(PathElement.groupElement("maxlen"));

		/** The Constant LEN. */
		private static final VarHandle LEN = LAYOUT.varHandle(PathElement.groupElement("len"));
	}

	/**
	 * The Constant pcap_sendqueue_alloc.
	 *
	 * @see {@code pcap_send_queue* pcap_sendqueue_alloc(u_int memsize)}
	 * @since WinPcap 1.0
	 */
	private static final PcapForeignDowncall pcap_sendqueue_alloc;

	/**
	 * The Constant pcap_sendqueue_destroy.
	 *
	 * @see {@code void pcap_sendqueue_destroy(pcap_send_queue* queue)}
	 * @since WinPcap 1.0
	 */
	private static final PcapForeignDowncall pcap_sendqueue_destroy;

	/**
	 * The Constant pcap_sendqueue_queue.
	 *
	 * @see {@code int pcap_sendqueue_queue(pcap_send_queue* queue, const struct
	 *      pcap_pkthdr *pkt_header, const u_char *pkt_data)}
	 * @since WinPcap 1.0
	 */
	private static final PcapForeignDowncall pcap_sendqueue_queue;

	/**
	 * The Constant pcap_sendqueue_transmit.
	 *
	 * @see {@code u_int pcap_sendqueue_transmit(pcap_t *p, pcap_send_queue* queue,
	 *      int sync)}
	 * @since WinPcap 1.0
	 */
	private static final PcapForeignDowncall pcap_sendqueue_transmit;
	static {
		try (var foreign = new PcapForeignInitializer(Linux.class)) {

			// @formatter:off
			pcap_sendqueue_alloc    = foreign.downcall("pcap_sendqueue_alloc(I)A");
			pcap_sendqueue_destroy  = foreign.downcall("pcap_sendqueue_destroy(A)V");
			pcap_sendqueue_queue    = foreign.downcall("pcap_sendqueue_queue(AAA)I");
			pcap_sendqueue_transmit = foreign.downcall("pcap_sendqueue_transmit(AAI)I");
			// @formatter:on

		}
	}

	/**
	 * Allocate a send queue.
	 * <p>
	 * This function allocates a send queue, i.e. a buffer containing a set of raw
	 * packets that will be transimtted on the network with
	 * pcap_sendqueue_transmit().
	 * </p>
	 * <p>
	 * memsize is the size, in bytes, of the queue, therefore it determines the
	 * maximum amount of data that the queue will contain.
	 * <p>
	 * </p>
	 * Use pcap_sendqueue_queue() to insert packets in the queue.
	 * </p>
	 *
	 * @param capacity maximum size of the send queue in bytes
	 * @return address of the allocated sendqueue
	 */
	private static MemorySegment alloc(int capacity) {
		return pcap_sendqueue_alloc.invokeObj(capacity);
	}

	/** The queue ptr. */
	private final MemorySegment queue_ptr;

	/** The arena. */
	private final Arena arena;

	/**
	 * Instantiates a new pcap send queue.
	 *
	 * @param capacity Maximum size of the queue, in bytes
	 */
	public PcapSendQueue(int capacity) {
		this.arena = Arena.ofShared();
		this.queue_ptr = alloc(capacity);
	}

	/**
	 * Close and destroy the send queue.
	 *
	 * @see java.lang.AutoCloseable#close()
	 */
	@Override
	public void close() {
		destroy();
	}

	/**
	 * Destroy the send queue
	 * <p>
	 * Deletes a send queue and frees all the memory associated with it
	 * </p>
	 * .
	 */
	private void destroy() {
		if (!arena.scope().isAlive())
			throw new IllegalStateException("already closed");

		try {
			pcap_sendqueue_destroy.invokeVoid(queue_ptr);
		} finally {
			arena.close();
		}
	}

	/**
	 * Add a packet to a send queue.
	 *
	 * <p>
	 * pcap_sendqueue_queue() adds a packet at the end of the send queue pointed by
	 * the queue parameter. pkt_header points to a pcap_pkthdr structure with the
	 * timestamp and the length of the packet, pkt_data points to a buffer with the
	 * data of the packet.
	 * </p>
	 * <p>
	 * The pcap_pkthdr structure is the same used by WinPcap and libpcap to store
	 * the packets in a file, therefore sending a capture file is straightforward.
	 * 'Raw packet' means that the sending application will have to include the
	 * protocol headers, since every packet is sent to the network 'as is'. The CRC
	 * of the packets needs not to be calculated, because it will be transparently
	 * added by the network interface.
	 * </p>
	 *
	 * @param header the header
	 * @param packet the packet
	 * @return the int
	 */
	public int queue(MemorySegment header, MemorySegment packet) {
		return pcap_sendqueue_queue.invokeInt(queue_ptr, header, packet);
	}

	/**
	 * Add a packet to a send queue.
	 *
	 * <p>
	 * pcap_sendqueue_queue() adds a packet at the end of the send queue pointed by
	 * the queue parameter. pkt_header points to a pcap_pkthdr structure with the
	 * timestamp and the length of the packet, pkt_data points to a buffer with the
	 * data of the packet.
	 * </p>
	 * <p>
	 * The pcap_pkthdr structure is the same used by WinPcap and libpcap to store
	 * the packets in a file, therefore sending a capture file is straightforward.
	 * 'Raw packet' means that the sending application will have to include the
	 * protocol headers, since every packet is sent to the network 'as is'. The CRC
	 * of the packets needs not to be calculated, because it will be transparently
	 * added by the network interface.
	 * </p>
	 *
	 * @param header the header
	 * @param packet the packet
	 * @param offset the offset
	 * @return the int
	 */
	public int queue(PcapHeader header, byte[] packet, int offset) {
		if (offset < 0 || offset >= packet.length)
			throw new IllegalArgumentException("offset out of bounds");

		try (var arena = WinPcap.newArena()) {

			MemorySegment byteArray = MemorySegment.ofArray(packet)
					.asSlice(offset);

			MemorySegment pkt = arena.allocate(byteArray.byteSize())
					.copyFrom(byteArray);
			MemorySegment hdr = header.asMemoryReference();

			return queue(hdr, pkt);
		}
	}

	/**
	 * Transmit all packets in the send queue.
	 * <p>
	 * This function transmits the content of a queue to the wire. p is a pointer to
	 * the adapter on which the packets will be sent, queue points to a
	 * pcap_send_queue structure containing the packets to send (see
	 * pcap_sendqueue_alloc() and pcap_sendqueue_queue()), sync determines if the
	 * send operation must be synchronized: if it is non-zero, the packets are sent
	 * respecting the timestamps, otherwise they are sent as fast as possible.
	 * </p>
	 * <p>
	 * The return value is the amount of bytes actually sent. If it is smaller than
	 * the size parameter, an error occurred during the send. The error can be
	 * caused by a driver/adapter problem or by an inconsistent/bogus send queue.
	 * </p>
	 * <p>
	 * Note: Using this function is more efficient than issuing a series of
	 * pcap_sendpacket(), because the packets are buffered in the kernel driver, so
	 * the number of context switches is reduced. Therefore, expect a better
	 * throughput when using pcap_sendqueue_transmit. When Sync is set to TRUE, the
	 * packets are synchronized in the kernel with a high precision timestamp. This
	 * requires a non-negligible amount of CPU, but allows normally to send the
	 * packets with a precision of some microseconds (depending on the accuracy of
	 * the performance counter of the machine). Such a precision cannot be reached
	 * sending the packets with pcap_sendpacket().
	 * </p>
	 *
	 * @param pcap_t the pcap t
	 * @param sync   if true, the packets are synchronized in the kernel with a high
	 *               precision timestamp
	 * @return number of packets transmitted
	 */
	int transmit(MemorySegment pcap_t, boolean sync) {
		return pcap_sendqueue_transmit.invokeInt(pcap_t, queue_ptr, sync ? 1 : 0);
	}

	/**
	 * The value of the {code pcap_sendqueue_t.maxlen} structure field.
	 *
	 * @return the maxlen or capacity, in bytes, of this send queue
	 */
	public int maxlen() {
		return (int) Struct.MAXLEN.get(queue_ptr, 0L);
	}

	/**
	 * The value of the {code pcap_sendqueue_t.len} structure field.
	 *
	 * @return the length or current size, in bytes, of this send queue
	 */
	public int len() {
		return (int) Struct.LEN.get(queue_ptr, 0L);
	}
}
