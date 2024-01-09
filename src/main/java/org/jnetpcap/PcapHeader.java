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

import static org.jnetpcap.internal.PcapHeaderABI.*;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.time.Instant;

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
 * @see LibraryPolicy#SYSTEM_PROPERTY_ABI
 */
public final class PcapHeader {

	/** The Constant MILLI_TIME_SCALE. */
	private static final int MILLI_TIME_SCALE = 1000_000;

	/** The Constant NANO_TIME_SCALE. */
	private static final int NANO_TIME_SCALE = 1000_000_000;

	/** The Constant HEADER_LEN_MAX. */
	private static final int HEADER_LEN_MAX = 24;

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

	/**
	 * Packet capture length.
	 *
	 * @param headerBuffer the buffer containing pcap header contents
	 * @return the number of packet bytes captured
	 * @throws OutOfRangeException the out of range exception, typically indicates
	 *                             invalid ABI (Application Binary Interface)
	 *                             setting which is platform and offline capture
	 *                             file dependent
	 */
	public static int captureLength(ByteBuffer headerBuffer) throws OutOfRangeException {
		PcapHeaderABI abi = PcapHeaderABI.nativeAbi();
		try {
			try {
				return abi.captureLength(headerBuffer);
			} catch (OutOfRangeException e) {
				throw throwListOfAllAbiPossibilities( // Throw a more robust explanation
						headerBuffer,
						e,
						"captureLength",
						PcapHeaderABI::captureLength);
			}

		} catch (IndexOutOfBoundsException e) {
			throw new IndexOutOfBoundsException("%s".formatted(headerBuffer));
		}
	}

	/**
	 * Packet capture length for offline file capture.
	 *
	 * @param headerBuffer the buffer containing pcap header contents
	 * @param isSwapped    for offline files which were captured according to the
	 *                     capturing system ABI, the bytes written maybe swapped for
	 *                     this system's architecture.
	 * @return the number of packet bytes captured
	 * @throws OutOfRangeException the out of range exception, typically indicates
	 *                             invalid ABI (Application Binary Interface)
	 *                             setting which is platform and offline capture
	 *                             file dependent
	 */
	public static int captureLength(ByteBuffer headerBuffer, boolean isSwapped) throws OutOfRangeException {
		PcapHeaderABI abi = PcapHeaderABI.selectOfflineAbi(isSwapped);
		try {
			try {
				return abi.captureLength(headerBuffer);
			} catch (OutOfRangeException e) {
				throw throwListOfAllAbiPossibilities( // Throw a more robust explanation
						headerBuffer,
						e,
						"captureLength",
						PcapHeaderABI::captureLength);
			}

		} catch (IndexOutOfBoundsException e) {
			throw new IndexOutOfBoundsException("%s".formatted(headerBuffer));
		}
	}

	/**
	 * Packet capture length for offline file capture.
	 *
	 * @param headerSegment the memory segment containing pcap header contents
	 * @return the number of packet bytes captured
	 * @throws OutOfRangeException the out of range exception, typically indicates
	 *                             invalid ABI (Application Binary Interface)
	 *                             setting which is platform and offline capture
	 *                             file dependent
	 */
	public static int captureLength(MemorySegment headerSegment) throws OutOfRangeException {
		PcapHeaderABI abi = PcapHeaderABI.nativeAbi();
		return abi.captureLength(headerSegment);
	}

	/**
	 * Packet capture length for offline file capture.
	 *
	 * @param headerSegment the memory segment containing pcap header contents
	 * @param isSwapped     for offline files which were captured according to the
	 *                      capturing system ABI, the bytes written maybe swapped
	 *                      for this system's architecture.
	 * @return the number of packet bytes captured
	 * @throws OutOfRangeException the out of range exception, typically indicates
	 *                             invalid ABI (Application Binary Interface)
	 *                             setting which is platform and offline capture
	 *                             file dependent
	 */
	public static int captureLength(MemorySegment headerSegment, boolean isSwapped) throws OutOfRangeException {
		PcapHeaderABI abi = PcapHeaderABI.selectOfflineAbi(isSwapped);
		return abi.captureLength(headerSegment);
	}

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
	 * Packet wire length .
	 *
	 * @param headerBuffer the buffer containing pcap header contents
	 * @return the number of packet bytes originally seen on the network
	 *         wire/wireless before truncation due to "snaplen" parameter if set.
	 * @throws OutOfRangeException the out of range exception, typically indicates
	 *                             invalid ABI (Application Binary Interface)
	 *                             setting which is platform and offline capture
	 *                             file dependent
	 */
	public static int wireLength(ByteBuffer headerBuffer) throws OutOfRangeException {
		PcapHeaderABI abi = PcapHeaderABI.nativeAbi();
		try {
			try {
				return abi.wireLength(headerBuffer);
			} catch (OutOfRangeException e) {
				throw throwListOfAllAbiPossibilities( // Throw a more robust explanation
						headerBuffer,
						e,
						"wireLength",
						PcapHeaderABI::wireLength);
			}

		} catch (IndexOutOfBoundsException e) {
			throw new IndexOutOfBoundsException("%s".formatted(headerBuffer));
		}
	}

	/**
	 * Packet wire length for offline file capture.
	 *
	 * @param headerBuffer the buffer containing pcap header contents
	 * @param isSwapped    for offline files which were captured according to the
	 *                     capturing system ABI, the bytes written maybe swapped for
	 *                     this system's architecture.
	 * @return the number of packet bytes originally seen on the network
	 *         wire/wireless before truncation due to "snaplen" parameter if set.
	 * @throws OutOfRangeException the out of range exception, typically indicates
	 *                             invalid ABI (Application Binary Interface)
	 *                             setting which is platform and offline capture
	 *                             file dependent
	 */
	public static int wireLength(ByteBuffer headerBuffer, boolean isSwapped) throws OutOfRangeException {
		PcapHeaderABI abi = PcapHeaderABI.selectOfflineAbi(isSwapped);
		try {
			try {
				return abi.wireLength(headerBuffer);
			} catch (OutOfRangeException e) {
				throw throwListOfAllAbiPossibilities( // Throw a more robust explanation
						headerBuffer,
						e,
						"wireLength",
						PcapHeaderABI::wireLength);
			}

		} catch (IndexOutOfBoundsException e) {
			throw new IndexOutOfBoundsException("%s".formatted(headerBuffer));
		}
	}

	/**
	 * Packet wire length.
	 *
	 * @param headerSegment the memory segment containing pcap header contents
	 * @return the number of packet bytes originally seen on the network
	 *         wire/wireless before truncation due to "snaplen" parameter if set.
	 * @throws OutOfRangeException the out of range exception, typically indicates
	 *                             invalid ABI (Application Binary Interface)
	 *                             setting which is platform and offline capture
	 *                             file dependent
	 */
	public static int wireLength(MemorySegment headerSegment) throws OutOfRangeException {
		PcapHeaderABI abi = PcapHeaderABI.nativeAbi();
		return abi.wireLength(headerSegment);
	}

	/**
	 * Packet wire length for offline file capture.
	 *
	 * @param headerSegment the memory segment containing pcap header contents
	 * @param isSwapped     for offline files which were captured according to the
	 *                      capturing system ABI, the bytes written maybe swapped
	 *                      for this system's architecture.
	 * @return the number of packet bytes originally seen on the network
	 *         wire/wireless before truncation due to "snaplen" parameter if set.
	 * @throws OutOfRangeException the out of range exception, typically indicates
	 *                             invalid ABI (Application Binary Interface)
	 *                             setting which is platform and offline capture
	 *                             file dependent
	 */
	public static int wireLength(MemorySegment headerSegment, boolean isSwapped) throws OutOfRangeException {
		PcapHeaderABI abi = PcapHeaderABI.selectOfflineAbi(isSwapped);
		return abi.wireLength(headerSegment);
	}

	/** The buffer. */
	private final ByteBuffer buffer;

	/** The abi. */
	private final PcapHeaderABI abi;

	/** The is nano time. */
	private boolean isNanoTime = false;

	/**
	 * Instantiates a new pcap header.
	 *
	 * @param headerBuffer the header buffer
	 */
	public PcapHeader(ByteBuffer headerBuffer) {
		this(PcapHeaderABI.nativeAbi(), headerBuffer);
	}

	/**
	 * Instantiates a new pcap header.
	 *
	 * @param tvSec         the tv sec
	 * @param tvUsec        the tv usec
	 * @param captureLength the capture length
	 * @param wireLength    the wire length
	 */
	public PcapHeader(int tvSec, int tvUsec, int captureLength, int wireLength) {
		this.abi = PcapHeaderABI.nativeAbi();
		this.buffer = newInitializedBuffer(abi, tvSec, tvUsec, captureLength, wireLength);
	}

	/**
	 * Instantiates a new pcap header.
	 *
	 * @param mseg the {@code struct pcap_pkthdr} memory address.
	 */
	public PcapHeader(MemorySegment mseg) {
		this(PcapHeaderABI.nativeAbi(), mseg);
	}

	/**
	 * Instantiates a new pcap header.
	 *
	 * @param mseg      the {@code struct pcap_pkthdr} memory address.
	 * @param isSwapped the flag indicates that the header is referencing memory for
	 *                  an offline capture and that the header field byte may be
	 *                  swapped, as recorded based on the original capture system
	 *                  architecture.
	 */
	public PcapHeader(MemorySegment mseg, boolean isSwapped) {
		this(PcapHeaderABI.selectOfflineAbi(isSwapped), mseg);
	}

	/**
	 * Instantiates a new pcap header.
	 *
	 * @param mseg         the {@code struct pcap_pkthdr} memory address.
	 * @param isSwapped    the flag indicates that the header is referencing memory
	 *                     for an offline capture and that the header field byte may
	 *                     be swapped, as recorded based on the original capture
	 *                     system architecture. *
	 * @param isCompactAbi if true, forces the pcap binary interface to use the
	 *                     compact form.
	 * @see LibraryPolicy#SYSTEM_PROPERTY_ABI
	 */
	public PcapHeader(MemorySegment mseg, boolean isSwapped, boolean isCompactAbi) {
		this(PcapHeaderABI.compactAbi(isSwapped), mseg);
	}

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
	 * @param arena         the session
	 */
	PcapHeader(PcapHeaderABI abi, MemorySegment headerAddress, Arena arena) {
		this.abi = abi;
		this.buffer = headerAddress.reinterpret(HEADER_LEN_MAX, arena, __ -> {})
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
	 * As memory reference.
	 *
	 * @return the memory address
	 */
	public MemorySegment asMemoryReference() {
		return asMemorySegment();
	}

	/**
	 * As memory segment.
	 *
	 * @return the memory segment
	 */
	public MemorySegment asMemorySegment() {
		return MemorySegment.ofBuffer(buffer);
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
	 * The length of this header.
	 *
	 * @return the length of this header in bytes.
	 */
	public int headerLength() {
		return abi.headerLength();
	}

	/**
	 * Sets a flag if the timestamp for this header is calculated using nanosecond
	 * or the default microsecond precision.
	 *
	 * @param nanoTime if true, a call to {@link #timestamp()} or
	 *                 {@link #toEpochMilli()} will use nano second precision
	 * @return this pcap header
	 */
	public PcapHeader setNanoTimePrecision(boolean nanoTime) {
		this.isNanoTime = nanoTime;

		return this;
	}

	/**
	 * Timestamp with 32-bit seconds (MSB bits) and 32-bit usecs (LSB bits) from a
	 * base of January 1, 1970.
	 *
	 * @return the long
	 * @throws PcapHeaderException the pcap header exception
	 */
	public long timestamp() throws PcapHeaderException {
		return timestamp(isNanoTime);
	}

	/**
	 * Timestamp in either nano or milli second precision.
	 *
	 * @param nanoTime if true, timestamp is returned with nano second precision,
	 *                 otherwise millis is returned
	 * @return the timestamp value as 64-bit long
	 * @throws PcapHeaderException the pcap header exception
	 */
	public long timestamp(boolean nanoTime) throws PcapHeaderException {
		if (nanoTime)
			return tvSec() * NANO_TIME_SCALE + tvUsec();
		else
			return tvSec() * MILLI_TIME_SCALE + tvUsec();
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
			return timestamp(nanoTime) / 1000_000;
		else
			return timestamp() / 1000;
	}

	/**
	 * To string.
	 *
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "PcapHeader ["
				+ "captureLength=%4d".formatted(captureLength())
				+ ", wireLength=%4d".formatted(wireLength())
				+ ", timestamp=\"%s\" [s=%d, us=%6d]".formatted(
						Instant.ofEpochMilli(toEpochMilli()),
						tvSec(), tvUsec())
				+ ", abi=%s".formatted(abi)
				+ "]";
	}

	/**
	 * Tv sec.
	 *
	 * @return the int
	 * @throws PcapHeaderException the pcap header exception
	 */
	public long tvSec() throws PcapHeaderException {
		return Integer.toUnsignedLong(buffer.getInt(abi.tvSecOffset()));
	}

	/**
	 * Tv usec.
	 *
	 * @return the int
	 * @throws PcapHeaderException the pcap header exception
	 */
	public long tvUsec() throws PcapHeaderException {
		return Integer.toUnsignedLong(buffer.getInt(abi.tvUsecOffset()));
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
}
