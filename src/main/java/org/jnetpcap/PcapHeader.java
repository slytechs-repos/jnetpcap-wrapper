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

import java.lang.foreign.MemoryAddress;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.jnetpcap.internal.PcapHeaderABI;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
public class PcapHeader {

	private static final PcapHeaderABI ABI = PcapHeaderABI.nativeAbi();

	private static ByteBuffer newInitializedBuffer(int tvSec, int tvUsec, int captureLength, int wireLength) {
		ByteBuffer buffer = ByteBuffer.allocateDirect(ABI.headerLength())
				.order(ByteOrder.nativeOrder());

		buffer.putInt(ABI.tvSecOffset(), tvSec);
		buffer.putInt(ABI.tvUsecOffset(), tvUsec);
		buffer.putInt(ABI.captureLengthOffset(), captureLength);
		buffer.putInt(ABI.wireLengthOffset(), wireLength);

		return buffer;
	}

	private static final int MILLI_TIME_SCALE = 1000_000;
	private static final int NANO_TIME_SCALE = 1000_000_000;

	private final ByteBuffer buffer;

	public PcapHeader() {
		this(ByteBuffer.allocateDirect(ABI.headerLength()).order(ByteOrder.nativeOrder()));
	}

	public PcapHeader(int tvSec, int tvUsec, int captureLength, int wireLength) {
		this(newInitializedBuffer(tvSec, tvUsec, captureLength, wireLength));
	}

	public PcapHeader(byte[] array, int offset) {
		this.buffer = ByteBuffer.wrap(array, offset, ABI.headerLength());
	}

	public PcapHeader(ByteBuffer headerBuffer) {
		this.buffer = headerBuffer;
	}

	public PcapHeader(MemoryAddress headerAddress, MemorySession session) {
		this.buffer = MemorySegment.ofAddress(headerAddress, ABI.headerLength(), session)
				.asByteBuffer();
	}

	public PcapHeader(MemorySegment headerSegment) {
		this.buffer = headerSegment.asByteBuffer();
	}

	public int captureLength() {
		return buffer.getInt(ABI.captureLengthOffset());
	}

	/**
	 * Timestamp with 32-bit seconds (MSB bits) and 32-bit usecs (LSB bits) from a
	 * base of January 1, 1970.
	 *
	 * @return the long
	 */
	public long timestamp() {
		return (tvSec() << 32 | tvUsec());
	}

	public long toTimestampEpochMilli() {
		return toTimestampEpochMilli(false);
	}

	public long toTimestampEpochMilli(boolean nanoTime) {
		if (nanoTime)
			return tvSec() * NANO_TIME_SCALE + tvUsec();
		else
			return tvSec() * MILLI_TIME_SCALE + tvUsec();
	}

	public int tvSec() {
		return buffer.getInt(ABI.tvSecOffset());
	}

	public int tvUsec() {
		return buffer.getInt(ABI.tvUsecOffset());
	}

	public int wireLength() {
		return buffer.getInt(ABI.wireLengthOffset());
	}

	public MemoryAddress asMemoryReference() {
		return asMemorySegment().address();
	}

	public MemorySegment asMemorySegment() {
		return MemorySegment.ofBuffer(buffer);
	}

}
