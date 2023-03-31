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

import org.jnetpcap.internal.PcapHeaderABI;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
public class PcapHeader {

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

	private static ByteBuffer allocateBuffer(PcapHeaderABI abi) {
		ByteBuffer buffer = ByteBuffer
				.allocateDirect(abi.headerLength())
				.order(abi.order());

		return buffer;
	}

	private static final int MILLI_TIME_SCALE = 1000_000;
	private static final int NANO_TIME_SCALE = 1000_000_000;

	private final ByteBuffer buffer;
	private final PcapHeaderABI abi;

	public PcapHeader(PcapHeaderABI abi) {
		this.abi = abi;
		this.buffer = allocateBuffer(abi);
	}

	public PcapHeader(PcapHeaderABI abi, int tvSec, int tvUsec, int captureLength, int wireLength) {
		this.abi = abi;
		this.buffer = newInitializedBuffer(abi, tvSec, tvUsec, captureLength, wireLength);
	}

	public PcapHeader(PcapHeaderABI abi, byte[] array, int offset) {
		this.abi = abi;
		this.buffer = ByteBuffer
				.wrap(array, offset, abi.headerLength())
				.order(abi.order());
	}

	public PcapHeader(PcapHeaderABI abi, ByteBuffer headerBuffer) {
		this.abi = abi;
		this.buffer = headerBuffer.order(abi.order());
	}

	public PcapHeader(PcapHeaderABI abi, MemoryAddress headerAddress, MemorySession session) {
		this.abi = abi;
		this.buffer = MemorySegment.ofAddress(headerAddress, abi.headerLength(), session)
				.asByteBuffer()
				.order(abi.order());
	}

	public PcapHeader(PcapHeaderABI abi, MemorySegment headerSegment) {
		this.abi = abi;
		this.buffer = headerSegment
				.asByteBuffer()
				.order(abi.order());
	}

	public int captureLength() {
		return abi.captureLength(buffer);
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

	public long toEpochMilli() {
		return toEpochMilli(false);
	}

	public long toEpochMilli(boolean nanoTime) {
		if (nanoTime)
			return tvSec() * NANO_TIME_SCALE + tvUsec();
		else
			return tvSec() * MILLI_TIME_SCALE + tvUsec();
	}

	public int tvSec() {
		return buffer.getInt(abi.tvSecOffset());
	}

	public int tvUsec() {
		return buffer.getInt(abi.tvUsecOffset());
	}

	public int wireLength() {
		return abi.wireLength(buffer);
	}

	public MemoryAddress asMemoryReference() {
		return asMemorySegment().address();
	}

	public MemorySegment asMemorySegment() {
		return MemorySegment.ofBuffer(buffer);
	}

}
