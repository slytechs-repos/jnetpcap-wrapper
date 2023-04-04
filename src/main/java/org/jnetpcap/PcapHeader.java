/*
 * Apache License, Version 2.0
 * 
 * Copyright 2013-2022 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 *   
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jnetpcap;

import static org.jnetpcap.internal.PcapHeaderABI.*;

import java.lang.foreign.MemoryAddress;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.nio.ByteBuffer;

import org.jnetpcap.Pcap.LibraryPolicy;
import org.jnetpcap.PcapHeaderException.OutOfRangeException;
import org.jnetpcap.internal.PcapHeaderABI;

/**
 * A Pcap packet header also called a descriptor that precedes each packet. The
 * pcap header is supplied natively by libpcap library and {@code PcapHeader}
 * can bind to native memory without copy to access its fields.
 * <p>
 * {@code PcapHeader} supplies vital information about the captured packet.
 * These fields disclaim the length of the data capture and if a packet was
 * truncated with <em>snaplen</em> parameter on the {@code Pcap} handle, the
 * packet length as originally seen on the wire. Additionally a timestamp of the
 * instant when the packet was captured.
 * </p>
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 * @see LibraryPolicy#SYSTEM_PROPERTY_ABI
 */
public class PcapHeader {

	/**
	 * New initialized buffer.
	 *
	 * @param abi           the abi
	 * @param tvSec         the tv sec
	 * @param tvUsec        the tv usec
	 * @param captureLength the capture length
	 * @param wireLength    the wire length
	 * @return the byte buffer
	 */
	private static ByteBuffer newInitializedBuffer(
			PcapHeaderABI abi, int tvSec, int tvUsec, int captureLength,
			int wireLength) {
		ByteBuffer buffer = allocateBuffer(abi);

		buffer.putInt(abi.tvSecOffset(), tvSec);
		buffer.putInt(abi.tvUsecOffset(), tvUsec);
		buffer.putInt(abi.captureLengthOffset(), captureLength);
		buffer.putInt(abi.wireLengthOffset(), wireLength);

		return buffer;
	}

	/**
	 * Allocate buffer.
	 *
	 * @param abi the abi
	 * @return the byte buffer
	 */
	private static ByteBuffer allocateBuffer(PcapHeaderABI abi) {
		ByteBuffer buffer = ByteBuffer
				.allocateDirect(abi.headerLength())
				.order(abi.order());

		return buffer;
	}

	/** The Constant MILLI_TIME_SCALE. */
	private static final int MILLI_TIME_SCALE = 1000_000;

	/** The Constant NANO_TIME_SCALE. */
	private static final int NANO_TIME_SCALE = 1000_000_000;

	/** The Constant HEADER_LEN_MAX. */
	private static final int HEADER_LEN_MAX = 24;

	/** The buffer. */
	private final ByteBuffer buffer;

	/** The abi. */
	private final PcapHeaderABI abi;

	/**
	 * Instantiates a new pcap header.
	 *
	 * @param abi the abi
	 */
	PcapHeader(PcapHeaderABI abi) {
		this.abi = abi;
		this.buffer = allocateBuffer(abi);
	}

	/**
	 * Instantiates a new pcap header.
	 *
	 * @param abi           the abi
	 * @param tvSec         the tv sec
	 * @param tvUsec        the tv usec
	 * @param captureLength the capture length
	 * @param wireLength    the wire length
	 */
	PcapHeader(PcapHeaderABI abi, int tvSec, int tvUsec, int captureLength, int wireLength) {
		this.abi = abi;
		this.buffer = newInitializedBuffer(abi, tvSec, tvUsec, captureLength, wireLength);
	}

	/**
	 * Instantiates a new pcap header.
	 *
	 * @param abi    the abi
	 * @param array  the array
	 * @param offset the offset
	 */
	PcapHeader(PcapHeaderABI abi, byte[] array, int offset) {
		this.abi = abi;
		this.buffer = ByteBuffer
				.wrap(array, offset, HEADER_LEN_MAX)
				.order(abi.order());
	}

	/**
	 * Instantiates a new pcap header.
	 *
	 * @param abi          the abi
	 * @param headerBuffer the header buffer
	 */
	PcapHeader(PcapHeaderABI abi, ByteBuffer headerBuffer) {
		this.abi = abi;
		this.buffer = headerBuffer.order(abi.order());
	}

	/**
	 * Instantiates a new pcap header.
	 *
	 * @param abi           the abi
	 * @param headerAddress the header address
	 * @param session       the session
	 */
	PcapHeader(PcapHeaderABI abi, MemoryAddress headerAddress, MemorySession session) {
		this.abi = abi;
		this.buffer = MemorySegment.ofAddress(headerAddress, HEADER_LEN_MAX, session)
				.asByteBuffer()
				.order(abi.order());
	}

	/**
	 * Instantiates a new pcap header.
	 *
	 * @param abi           the abi
	 * @param headerSegment the header segment
	 */
	PcapHeader(PcapHeaderABI abi, MemorySegment headerSegment) {
		this.abi = abi;
		this.buffer = headerSegment
				.asByteBuffer()
				.order(abi.order());
	}

	/**
	 * Capture length.
	 *
	 * @return the int
	 * @throws OutOfRangeException the out of range exception
	 */
	public int captureLength() throws OutOfRangeException {
		try {
			try {
				return abi.captureLength(buffer);
			} catch (OutOfRangeException e) {
				throw throwListOfAllAbiPossibilities( // Throw a more robust explanation
						buffer,
						e,
						"captureLength",
						PcapHeaderABI::captureLength);
			}

		} catch (IndexOutOfBoundsException e) {
			throw new IndexOutOfBoundsException("%s".formatted(buffer));
		}
	}

	/**
	 * Timestamp with 32-bit seconds (MSB bits) and 32-bit usecs (LSB bits) from a
	 * base of January 1, 1970.
	 *
	 * @return the long
	 * @throws PcapHeaderException the pcap header exception
	 */
	public long timestamp() throws PcapHeaderException {
		return (tvSec() << 32 | tvUsec());
	}

	/**
	 * To epoch milli.
	 *
	 * @return the long
	 * @throws PcapHeaderException the pcap header exception
	 */
	public long toEpochMilli() throws PcapHeaderException {
		return toEpochMilli(false);
	}

	/**
	 * To epoch milli.
	 *
	 * @param nanoTime the nano time
	 * @return the long
	 * @throws PcapHeaderException the pcap header exception
	 */
	public long toEpochMilli(boolean nanoTime) throws PcapHeaderException {
		if (nanoTime)
			return tvSec() * NANO_TIME_SCALE + tvUsec();
		else
			return tvSec() * MILLI_TIME_SCALE + tvUsec();
	}

	/**
	 * Tv sec.
	 *
	 * @return the int
	 * @throws PcapHeaderException the pcap header exception
	 */
	public int tvSec() throws PcapHeaderException {
		return buffer.getInt(abi.tvSecOffset());
	}

	/**
	 * Tv usec.
	 *
	 * @return the int
	 * @throws PcapHeaderException the pcap header exception
	 */
	public int tvUsec() throws PcapHeaderException {
		return buffer.getInt(abi.tvUsecOffset());
	}

	/**
	 * Wire length.
	 *
	 * @return the int
	 * @throws PcapHeaderException the pcap header exception
	 */
	public int wireLength() throws PcapHeaderException {
		try {
			try {
				return abi.wireLength(buffer);
			} catch (OutOfRangeException e) {
				throw throwListOfAllAbiPossibilities( // Throw a more robust explanation
						buffer,
						e,
						"wireLength",
						PcapHeaderABI::captureLength);
			}

		} catch (IndexOutOfBoundsException e) {
			throw new IndexOutOfBoundsException("%s".formatted(buffer));
		}
	}

	/**
	 * As memory reference.
	 *
	 * @return the memory address
	 */
	public MemoryAddress asMemoryReference() {
		return asMemorySegment().address();
	}

	/**
	 * As memory segment.
	 *
	 * @return the memory segment
	 */
	public MemorySegment asMemorySegment() {
		return MemorySegment.ofBuffer(buffer);
	}

}
