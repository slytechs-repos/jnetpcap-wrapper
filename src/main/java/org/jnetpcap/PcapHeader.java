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

import static org.jnetpcap.internal.PcapHeaderABI.nativeAbi;

import java.lang.foreign.Addressable;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.jnetpcap.constant.PcapTStampPrecision;
import org.jnetpcap.internal.PcapHeaderABI;

/**
 * The pcap header which describes how many bytes of a packet were seen on the
 * network, how many were actually captured and the capture timestamp.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public sealed interface PcapHeader permits PcapHeaderMemory, PcapHeaderBuffer, PcapHeaderRecord, PcapHeaderObject {

	/**
	 * The normal header length is 16 bytes. This is when all of the pcap header
	 * structure fields are compacted or one 32-bit system.
	 */
	public static final int PCAP_HEADER_LENGTH = 16;

	/**
	 * The padded header length can be up to 24 bytes. This is when tv_sec and
	 * tv_usec fields are padded to 8 bytes each instead of 4 bytes of actual field
	 * sizes. When allocating native memory to hold a header, it is safer and
	 * recommended to use the padded length.
	 */
	public static final int PCAP_HEADER_PADDED_LENGTH = nativeAbi().headerLength();

	/**
	 * Allocates a new PcapHeader in native memory. Current, low resolution time
	 * source is used to estimate the tvSec and tvUsec values.
	 * 
	 * @param length the length of the packet in bytes, used to initialize both
	 *               wireLength and captureLength fields.
	 * @param scope  for memory allocation
	 * @return new native memory backed pcap header
	 */
	static PcapHeader allocate(int length, MemorySession scope) {
		return PcapHeaderMemory.allocate(length, scope);
	}

	/**
	 * Allocates a new PcapHeader in native memory. All fields are uninitialized and
	 * may not be zeroed out, depending on the constants of the native memory.
	 *
	 * @param scope for memory allocation
	 * @return new native memory backed pcap header
	 */
	static PcapHeader allocate(MemorySession scope) {
		return PcapHeaderMemory.allocate(scope);
	}

	/**
	 * Creates a new writable instance of the pcap header. The header field values
	 * are copied from the memory into this header. Byte ordering defaults to native
	 * byte order.
	 *
	 * @param src the src
	 * @return new pcap header
	 */
	static PcapHeader newInstance(Addressable src) {
		return newInstance(src, ByteOrder.nativeOrder());
	}

	/**
	 * Creates a new writable instance of the pcap header. The header field values
	 * are copied from the memory into this header. Byte ordering defaults to native
	 * byte order.
	 *
	 * @param src   the src
	 * @param order byte ordering
	 * @return new pcap header
	 */
	static PcapHeader newInstance(Addressable src, ByteOrder order) {
		return PcapHeaderMemory.newObjectHeader(src, order);
	}

	/**
	 * Creates a new writable instance of the pcap header. The header field values
	 * are copied from the memory into this header using native byte ordering.
	 *
	 * @param tvSec   the tv sec epoch time in seconds since Jan 1st, 1970 12:00am
	 * @param tvUsec  the tv usec micro or nano second fraction of a second
	 * @param caplen  the caplen how much data was captured
	 * @param wirelen the wirelen actual packet length as seen on the wire
	 * @return new pcap header
	 */
	static PcapHeader newInstance(long tvSec, long tvUsec, int caplen, int wirelen) {
		return new PcapHeaderObject(tvSec, tvUsec, wirelen, wirelen, ByteOrder.nativeOrder());
	}

	/**
	 * Creates a new writable instance of the pcap header. The header field values
	 * are copied from the memory into this header using the provided byte ordering.
	 *
	 * @param tvSec   the tv sec epoch time in seconds since Jan 1st, 1970 12:00am
	 * @param tvUsec  the tv usec micro or nano second fraction of a second
	 * @param caplen  the caplen how much data was captured
	 * @param wirelen the wirelen actual packet length as seen on the wire
	 * @param order   byte ordering
	 * @return new pcap header
	 */
	static PcapHeader newInstance(long tvSec, long tvUsec, int caplen, int wirelen, ByteOrder order) {
		return new PcapHeaderObject(tvSec, tvUsec, wirelen, wirelen, order);
	}

	/**
	 * Creates a new fast read only instance of the pcap header. The header field
	 * values are copied from the memory into this header. Byte ordering defaults to
	 * native byte order.
	 *
	 * @param src memory source where native pcap header is found
	 * @return new pcap header
	 */
	static PcapHeader newReadOnlyInstance(Addressable src) {
		return newReadOnlyInstance(src, ByteOrder.nativeOrder());
	}

	/**
	 * Creates a new fast read only instance of the pcap header. The header field
	 * values are copied from the memory into this header using the provided byte
	 * ordering.
	 *
	 * @param src   memory source where native pcap header is found
	 * @param order byte order of the native memory segment
	 * @return new pcap header
	 */
	static PcapHeader newReadOnlyInstance(Addressable src, ByteOrder order) {
		return PcapHeaderMemory.newRecordHeader(src, order);
	}

	/**
	 * Creates a new fast read only instance of the pcap header. The header field
	 * values are copied from the memory into this header using the specified byte
	 * ordering.
	 *
	 * @param tvSec   the tv sec epoch time in seconds since Jan 1st, 1970 12:00am
	 * @param tvUsec  the tv usec micro or nano second fraction of a second
	 * @param caplen  the caplen how much data was captured
	 * @param wirelen the wirelen actual packet length as seen on the wire
	 * @param order   byte ordering
	 * @return new pcap header
	 */
	static PcapHeader newReadOnlyInstance(long tvSec, long tvUsec, int caplen, int wirelen, ByteOrder order) {
		return new PcapHeaderRecord(tvSec, tvUsec, caplen, wirelen, order);
	}

	/**
	 * Wraps a header instance around the provided memory object. If addressable is
	 * a {@code MemorySegment} it will be wrapped directly. If the addressible is a
	 * {@code MemoryAddress}, a new {@code MemorySegment} will be created and
	 * wrapped around the address.
	 *
	 * @param addressable native memory address or segment at the start of the pcap
	 *                    structure in native memory
	 * @return new PcapHeader instance
	 */
	static PcapHeader ofAddress(Addressable addressable) {
		return new PcapHeaderMemory(addressable.address());
	}

	/**
	 * Creates a no-copy, Pcap header that wraps around the byte array. The integer
	 * byte ordering is assumed to be {@code ByteOrder.nativeOrder()}.
	 *
	 * @param arr the arr
	 * @return the new pcap header
	 */
	static PcapHeader ofArray(byte[] arr) {
		return ofArray(arr, 0);
	}

	/**
	 * Creates a no-copy, Pcap header that wraps around the byte array. The integer
	 * byte ordering is assumed to be {@code ByteOrder.nativeOrder()}.
	 *
	 * @param arr    the byte array containing the header data at a specific offset
	 * @param offset the offset in to arr where the header start
	 * @return the new pcap header
	 */
	static PcapHeader ofArray(byte[] arr, int offset) {
		ByteBuffer buf = ByteBuffer.wrap(arr, offset, PCAP_HEADER_PADDED_LENGTH);
		return new PcapHeaderBuffer(buf);
	}

	/**
	 * Of buffer.
	 *
	 * @param buffer the buffer
	 * @return the pcap header
	 */
	static PcapHeader ofBuffer(ByteBuffer buffer) {
		return new PcapHeaderBuffer(buffer);
	}

	/**
	 * Reads the {@code captureLength} field value from the memory object.
	 *
	 * @param memory the memory
	 * @return number of bytes captured, possibly truncated
	 */
	static int readCaptureLength(Addressable memory) {
		return PcapHeaderABI.nativeAbi().captureLength(memory.address());
	}

	/**
	 * Reads the {@code tvSec} field value from the memory object.
	 *
	 * @param memory the memory
	 * @return number of seconds from the start of epoch time, Jan 1st 1970 12:00am.
	 */
	static long readTvSec(Addressable memory) {
		return PcapHeaderABI.nativeAbi().tvSec(memory.address());
	}

	/**
	 * Reads the {@code tvUsec} field value from the memory object.
	 *
	 * @param memory the memory
	 * @return faction of a second either in nanos or micros depending the capture
	 *         source
	 */
	static long readTvUsec(Addressable memory) {
		return PcapHeaderABI.nativeAbi().tvUsec(memory.address());
	}

	/**
	 * Reads the {@code wireLength} field value from the memory object.
	 *
	 * @param memory the memory
	 * @return number of bytes in the original packet seen on the wire
	 */
	static int readWireLength(Addressable memory) {
		return PcapHeaderABI.nativeAbi().wireLength(memory.address());
	}

	/**
	 * Writes values directly into native memory.
	 *
	 * @param tvSec   the tv sec epoch time in seconds since Jan 1st, 1970 12:00am
	 * @param tvUsec  the tv usec micro or nano second fraction of a second
	 * @param caplen  the caplen how much data was captured
	 * @param wirelen the wirelen actual packet length as seen on the wire
	 * @param dst     dst could be a memory address or a memory segment, either of
	 *                which is acceptable
	 * @param order   the endianness of the values to be written
	 * @return the int
	 */
	static int write(long tvSec, long tvUsec, int caplen, int wirelen, Addressable dst, ByteOrder order) {
		return PcapHeaderMemory.write(tvSec, tvUsec, caplen, wirelen, dst, order);
	}

	/**
	 * Writes values directly into the destination byte array at specified offset.
	 *
	 * @param tvSec   the tv sec epoch time in seconds since Jan 1st, 1970 12:00am
	 * @param tvUsec  the tv usec micro or nano second fraction of a second
	 * @param caplen  the caplen how much data was captured
	 * @param wirelen the wirelen actual packet length as seen on the wire
	 * @param dst     the byte array to write to
	 * @param offset  the offset in to dst array
	 * @param order   the endianness of the values to be written
	 * @return the int
	 */
	static int write(long tvSec, long tvUsec, int caplen, int wirelen, byte[] dst, int offset, ByteOrder order) {
		return PcapHeaderBuffer.write(tvSec, tvUsec, caplen, wirelen, dst, offset, order);
	}

	/**
	 * Writes values directly into the destination buffer.
	 *
	 * @param tvSec   the tv sec epoch time in seconds since Jan 1st, 1970 12:00am
	 * @param tvUsec  the tv usec micro or nano second fraction of a second
	 * @param caplen  the caplen how much data was captured
	 * @param wirelen the wirelen actual packet length as seen on the wire
	 * @param dst     the byte array to write to at current buffers position
	 * @return the int
	 */
	static int write(long tvSec, long tvUsec, int caplen, int wirelen, ByteBuffer dst) {
		return PcapHeaderBuffer.write(tvSec, tvUsec, caplen, wirelen, dst);
	}

	/**
	 * Returns a memory address of this pcap header as addressable, suitable for use
	 * in native downcall functions. An addressable keeps any backing memory
	 * segments, arrays or buffers reachable. If implementating header is non-memory
	 * based, a new memory segment will be allocated and its address returned.
	 * 
	 * <p>
	 * Note, that if this header instance is backed by native memory, the backing
	 * native memory segment will be returned. If the header instance is non-memory
	 * based, a new native memory segment will be allocated and values of this
	 * header copied into it. Therefore if pcap header is be to used natively, it is
	 * more efficient to wrap and instance around a memory segment using one of the
	 * {@linkplain PcapHeader#ofAddress(Addressable)} factory methods.
	 * </p>
	 *
	 * @return the memory segment containing this header's field values
	 */
	Addressable asMemoryReference();

	/**
	 * Returns a read-only version of the pcap header.
	 *
	 * @return the pcap header
	 */
	PcapHeader asReadOnly();

	/**
	 * Number of packet bytes actually captured, up to maximum length of 'snaplen'
	 * if set on a capture. Only 16-bits LSB are significant.
	 *
	 * @return actual number of bytes captured
	 */
	int captureLength();

	/**
	 * Copies this header's contents to the destination byte array at specific
	 * offset. The values of this pcap header are copied into the array compacted
	 * (no padding).
	 *
	 * @param dst    the destination byte array
	 * @param offset the offset in to the byte array
	 * @return number of bytes copied which should be {@value #PCAP_HEADER_LENGTH}
	 *         non non-padded header length
	 */
	default int copyTo(byte[] dst, int offset) {
		return write((int) tvSec(), (int) tvUsec(), captureLength(), wireLength(), dst, offset, order());
	}

	/**
	 * Copies this header's contents to the destination buffer starting at the
	 * buffer's position. The buffer's position is not advanced. The values of this
	 * pcap header are copied into the buffer compacted (no padding).
	 *
	 * @param dst the destination buffer
	 * @return number of bytes copied which should be {@value #PCAP_HEADER_LENGTH}
	 *         non non-padded header length
	 */
	default int copyTo(ByteBuffer dst) {
		return write((int) tvSec(), (int) tvUsec(), captureLength(), wireLength(), dst);
	}

	/**
	 * Copies this header's contents to the destination memory segment. Values are
	 * copied into the memory segment with ABI padding, if any and using the byte
	 * ordering of this header.
	 *
	 * @param dst the destination memory segment
	 * @return the number of byte written to memory, on certain systems (i.e.
	 *         64-bit) the number may reflected padding as well and should be the
	 *         same value as {@code 24}.
	 */
	int copyTo(MemorySegment dst);

	/**
	 * Checks if the header is read only.
	 *
	 * @return true, if is read only
	 */
	boolean isReadOnly();

	/**
	 * Byte ordering of the values of this header.
	 *
	 * @return endianness of the pcap header
	 */
	ByteOrder order();

	/**
	 * changes the byte order of values are read from this pcap header.
	 *
	 * @param newOrder the new byte order
	 * @return this pcap header
	 */
	PcapHeader order(ByteOrder newOrder);

	/**
	 * Sets new header values by estimating the tvSec and tvUsec values using a
	 * current low resolution time source and setting both captureLength and
	 * wireLength fields to length.
	 *
	 * @param length packet length in bytes
	 * @return this pcap header
	 */
	default PcapHeader set(int length) {
		return set(length, length);
	}

	/**
	 * Sets new header values by estimating the tvSec and tvUsec values using a
	 * current low resolution time source.
	 *
	 * @param caplen  number of bytes captured
	 * @param wirelen number of bytes in the packet on the wire
	 * @return this pcap header
	 */
	default PcapHeader set(int caplen, int wirelen) {
		long time = System.currentTimeMillis();
		long tvSec = time / 1000;
		long tvUsec = (time % 1000) * 1000;

		return set(tvSec, tvUsec, caplen, wirelen);
	}

	/**
	 * Sets new header values.
	 *
	 * @param tvSec   set the tvSec field or number of seconds since start of epoch,
	 *                Jan 1st, 1970 12:00am
	 * @param tvUsec  set the tvUsec field or fraction of a second in micros or
	 *                nanos
	 * @param caplen  number of bytes captured
	 * @param wirelen number of bytes in the packet on the wire
	 * @return this pcap header
	 */
	PcapHeader set(long tvSec, long tvUsec, int caplen, int wirelen);

	/**
	 * Converts the {@link #tvSec()} and {@link #tvUsec()} values into a epoch
	 * microsecond value.
	 *
	 * @return Number of microseconds since epoch start, Jan 1st, 1970 12:00am.
	 */
	default long toEpochMicros() {
		return toEpochTime(PcapTStampPrecision.TSTAMP_PRECISION_MICRO);
	}

	/**
	 * Converts the {@link #tvSec()} and {@link #tvUsec()} values into a epoch
	 * millisecond value, compatible with java {@code Date} class and
	 * {@code java.time} package. The method uses the default
	 * {@link PcapTStampPrecision#TSTAMP_PRECISION_MICRO} precision value for
	 * {@link #tvUsec()} field.
	 *
	 * @return Number of milliseconds since epoch start, Jan 1st, 1970 12:00am.
	 */
	default long toEpochMillis() {
		return PcapTStampPrecision.TSTAMP_PRECISION_MICRO.toEpochMillis(tvSec(), tvUsec());
	}

	/**
	 * Converts the {@link #tvSec()} and {@link #tvUsec()} values into a epoch time
	 * of provided precision.
	 *
	 * @param precision the precision of {@link #tvUsec()} field and how it is
	 *                  interpreted
	 * @return Number of micro or nano seconds since epoch start, Jan 1st, 1970
	 *         12:00am, depending on the precision argument
	 */
	default long toEpochTime(PcapTStampPrecision precision) {
		return precision.toEpochTime(tvSec(), tvUsec());
	}

	/**
	 * Pcap timestamp seconds value within pcap header. The value is an epoch or
	 * unix time, which is number of seconds since Jan 1, 1970 at 12:00am. Only
	 * 32-bits LSB are significant.
	 *
	 * @return Number of seconds since epoch start (Jan 1st, 1970 12:00am)
	 */
	long tvSec();

	/**
	 * A fraction of a second, by default in micro-seconds but may also be in
	 * nanoseconds depending on the capture device or how the timestamp was stored
	 * in a 'savefile'. Only 32-bits LSB are significant.
	 *
	 * @return fraction of a second in micros or nanos
	 */
	long tvUsec();

	/**
	 * Original packet length in bytes as seen on the wire. This can be different
	 * from {@link #captureLength()} value, as packets can be captured truncated
	 * resulting in smaller packet capture size. Only 16-bits LSB are significant.
	 *
	 * @return the length of a packet in bytes as seen on the wire before any
	 *         truncation, if any
	 */
	int wireLength();

}