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
 * Represents a queue of raw packets for efficient batch transmission on
 * Microsoft Windows platforms. This class provides functionality to queue
 * multiple packets and transmit them either as quickly as possible or with
 * precise timing synchronization.
 * 
 * <h2>Native Structure</h2> Maps to the native {@code pcap_send_queue}
 * structure:
 * 
 * <pre>{@code
 * struct pcap_send_queue {
 *     u_int maxlen;  // Maximum size of the queue buffer in bytes
 *     u_int len;     // Current size of the queue in bytes
 *     char *buffer;  // Buffer containing queued packets
 * };
 * }</pre>
 * 
 * <h2>Usage Example</h2>
 * 
 * <pre>{@code
 * try (PcapSendQueue queue = new PcapSendQueue(65536)) { // 64KB queue
 * 	// Queue multiple packets
 * 	queue.queue(header1, packet1);
 * 	queue.queue(header2, packet2);
 * 
 * 	// Transmit all queued packets with timing synchronization
 * 	int bytesSent = queue.transmit(pcapHandle, true);
 * }
 * }</pre>
 * 
 * <h2>Performance Considerations</h2>
 * <ul>
 * <li>Using a send queue is more efficient than multiple
 * {@code pcap_sendpacket()} calls due to reduced context switching</li>
 * <li>Synchronized transmission (sync=true) provides microsecond precision but
 * requires more CPU resources</li>
 * <li>The CRC is automatically calculated by the network interface</li>
 * </ul>
 * 
 * <h2>Platform Support</h2> This functionality is only available on Microsoft
 * Windows platforms through WinPcap/Npcap.
 * 
 * @see org.jnetpcap.PcapHeader
 * @since WinPcap 1.0
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
	 * Creates a new send queue with specified capacity. The capacity determines the
	 * maximum amount of packet data that can be queued.
	 *
	 * @param capacity Maximum size of the queue in bytes
	 * @throws OutOfMemoryError if native memory allocation fails
	 */
	public PcapSendQueue(int capacity) {
		this.arena = Arena.ofShared();
		this.queue_ptr = alloc(capacity);
	}

	/**
	 * Closes and deallocates the send queue. This method must be called to prevent
	 * memory leaks.
	 *
	 * @throws IllegalStateException if the queue has already been closed
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
	 * Adds a packet to the end of the send queue using native memory segments. Both
	 * packet header and data must be properly formatted in native memory.
	 *
	 * @param header The pcap_pkthdr structure containing timestamp and length
	 * @param packet The packet data buffer
	 * @return 0 on success, -1 on failure (queue full)
	 */
	public int queue(MemorySegment header, MemorySegment packet) {
		return pcap_sendqueue_queue.invokeInt(queue_ptr, header, packet);
	}

	/**
	 * Adds a packet to the end of the send queue using Java byte array.
	 * Automatically handles conversion to native memory format.
	 *
	 * @param header The pcap header containing timestamp and length
	 * @param packet The packet data as byte array
	 * @param offset Starting offset in the packet array
	 * @return 0 on success, -1 on failure
	 * @throws IllegalArgumentException if offset is outside packet array bounds
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
	 * Internal method to transmit all queued packets.
	 * 
	 * @param pcap_t The pcap handle to transmit on
	 * @param sync   If true, maintains packet timing specified in headers. If
	 *               false, sends as fast as possible.
	 * @return The number of bytes actually transmitted, or less than queue size on
	 *         error
	 */
	int transmit(MemorySegment pcap_t, boolean sync) {
		return pcap_sendqueue_transmit.invokeInt(pcap_t, queue_ptr, sync ? 1 : 0);
	}

	/**
	 * Returns the maximum capacity of the send queue in bytes.
	 *
	 * @return The maximum number of bytes that can be queued
	 */
	public int maxlen() {
		return (int) Struct.MAXLEN.get(queue_ptr, 0L);
	}

	/**
	 * Returns the current size of the queue in bytes.
	 *
	 * @return The number of bytes currently queued
	 */
	public int len() {
		return (int) Struct.LEN.get(queue_ptr, 0L);
	}
}
