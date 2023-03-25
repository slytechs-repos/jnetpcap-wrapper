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
import java.nio.ByteOrder;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
record PcapHeaderRecord(long tvSec, long tvUsec, int captureLength, int wireLength, ByteOrder order) implements
		PcapHeader {

	private static UnsupportedOperationException readOnlyError() {
		return new UnsupportedOperationException("read-only pcap header");
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	/**
	 * @see org.jnetpcap.PcapHeader#copyTo(java.lang.foreign.MemorySegment)
	 */
	@Override
	public int copyTo(MemorySegment dst) {
		return PcapHeader.write(tvSec, tvUsec, captureLength, wireLength, dst, order);
	}

	/**
	 * @see org.jnetpcap.PcapHeader#asMemoryReference()
	 */
	@Override
	public MemorySegment asMemoryReference(Arena arena) {
		return PcapHeaderMemory.newMemoryFrom(this, arena).asReadOnly();
	}

	/**
	 * @see org.jnetpcap.PcapHeader#order(java.nio.ByteOrder)
	 */
	@Override
	public PcapHeader order(ByteOrder newOrder) {
		throw readOnlyError();
	}

	/**
	 * @see org.jnetpcap.PcapHeader#set(long, long, int, int)
	 */
	@Override
	public PcapHeader set(long tvSec, long tvUsec, int caplen, int wirelen) {
		throw readOnlyError();
	}

	/**
	 * @see org.jnetpcap.PcapHeader#asReadOnly()
	 */
	@Override
	public PcapHeader asReadOnly() {
		return this;
	}

}
