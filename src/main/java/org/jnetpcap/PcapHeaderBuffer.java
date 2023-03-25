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

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
final class PcapHeaderBuffer implements PcapHeader {

	private static final int BITMASK16 = 0xFFFFFFF;
	private static final int IX_SEC = 0; // compact offset
	private static final int IX_USEC = 4; // compact offset
	private static final int IX_CAPLEN = 8; // compact offset
	private static final int IX_WIRELEN = 12; // compact offset

	static int write(long tvSec, long tvUsec, int caplen, int wirelen, byte[] dst, int offset, ByteOrder order) {
		ByteBuffer buf = ByteBuffer
				.wrap(dst, offset, PCAP_HEADER_LENGTH)
				.order(order);

		return write(tvSec, tvUsec, caplen, wirelen, buf);
	}

	static int write(long tvSec, long tvUsec, int caplen, int wirelen, ByteBuffer dst) {
		dst.putInt((int) tvSec);
		dst.putInt((int) tvUsec);
		dst.putInt(caplen & BITMASK16);
		dst.putInt(wirelen & BITMASK16);

		return PCAP_HEADER_LENGTH;
	}

	private final ByteBuffer buffer;

	public PcapHeaderBuffer(byte[] array) {
		this(array, ByteOrder.nativeOrder());
	}

	public PcapHeaderBuffer(byte[] array, ByteOrder order) {
		this(array, 0, order);
	}

	public PcapHeaderBuffer(byte[] array, int offset, ByteOrder order) {
		this.buffer = ByteBuffer
				.wrap(array, offset, PCAP_HEADER_LENGTH)
				.order(order);
	}

	public PcapHeaderBuffer(ByteBuffer buffer) {
		this.buffer = buffer.slice().limit(PCAP_HEADER_LENGTH);
	}

	/**
	 * @see org.jnetpcap.PcapHeader#asMemoryReference()
	 */
	@Override
	public MemorySegment asMemoryReference(Arena arena) {

		if (PCAP_HEADER_LENGTH == PCAP_HEADER_PADDED_LENGTH) {
			/* We can return compact (non-padded) directly without copy */
			return MemorySegment.ofBuffer(buffer); // Can return compact segment

		} else {
			/* Copy to new segment using padded ABI */
			return PcapHeaderMemory.newMemoryFrom(this, arena);
		}
	}

	/**
	 * @see org.jnetpcap.PcapHeader#asReadOnly()
	 */
	@Override
	public PcapHeader asReadOnly() {
		if (!buffer.isReadOnly())
			return new PcapHeaderBuffer(buffer.asReadOnlyBuffer());

		return this;
	}

	@Override
	public int captureLength() {
		return buffer.getInt(IX_CAPLEN) & BITMASK16;
	}

	/**
	 * @see org.jnetpcap.PcapHeader#copyTo(java.lang.foreign.MemorySegment)
	 */
	@Override
	public int copyTo(MemorySegment dst) {
		return PcapHeaderMemory.write(tvSec(), tvUsec(), captureLength(), wireLength(), dst, order());
	}

	/**
	 * @see org.jnetpcap.PcapHeader#isReadOnly()
	 */
	@Override
	public boolean isReadOnly() {
		return buffer.isReadOnly();
	}

	/**
	 * @see org.jnetpcap.PcapHeader#order()
	 */
	@Override
	public ByteOrder order() {
		return buffer.order();
	}

	/**
	 * @see org.jnetpcap.PcapHeader#order(java.nio.ByteOrder)
	 */
	@Override
	public PcapHeader order(ByteOrder newOrder) {
		this.buffer.order(newOrder);

		return this;
	}

	/**
	 * @see org.jnetpcap.PcapHeader#set(long, long, int, int)
	 */
	@Override
	public PcapHeader set(long tvSec, long tvUsec, int caplen, int wirelen) {

		buffer.putInt((int) tvSec);
		buffer.putInt((int) tvUsec);
		buffer.putInt(caplen & BITMASK16);
		buffer.putInt(wirelen & BITMASK16);
		buffer.rewind();

		return this;
	}

	@Override
	public String toString() {
		return "PcapHeaderBuffer "
				+ "[caplen=%-4d".formatted(captureLength())
				+ " wirelen=%-4d".formatted(wireLength())
				+ " tvSec=%d".formatted(tvSec())
				+ " tvUsec=%-6d".formatted(tvUsec())
				+ " arrayOffset=%d".formatted(buffer.arrayOffset())
				+ "]";
	}

	@Override
	public long tvSec() {
		return Integer.toUnsignedLong(buffer.getInt(IX_SEC));
	}

	@Override
	public long tvUsec() {
		return Integer.toUnsignedLong(buffer.getInt(IX_USEC));
	}

	@Override
	public int wireLength() {
		return buffer.getInt(IX_WIRELEN) & BITMASK16;
	}

}
