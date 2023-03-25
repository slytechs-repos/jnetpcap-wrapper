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
final class PcapHeaderObject implements PcapHeader {

	private long tvSec;
	private long tvUsec;
	private int captureLength;
	private int wireLength;
	private ByteOrder order;

	/**
	 * Instantiates a new pcap header object.
	 *
	 * @param tvSec         the tv sec
	 * @param tvUsec        the tv usec
	 * @param captureLength the capture length
	 * @param wireLength    the wire length
	 * @param order         the order
	 */
	public PcapHeaderObject(long tvSec, long tvUsec, int captureLength, int wireLength, ByteOrder order) {
		this.tvSec = tvSec;
		this.tvUsec = tvUsec;
		this.captureLength = captureLength;
		this.wireLength = wireLength;
		this.order = order;
	}

	/**
	 * @see org.jnetpcap.PcapHeader#asMemoryReference()
	 */
	@Override
	public MemorySegment asMemoryReference(Arena arena) {
		return PcapHeaderMemory.newMemory(tvSec, tvUsec, captureLength, wireLength, order, arena);
	}

	/**
	 * @see org.jnetpcap.PcapHeader#asReadOnly()
	 */
	@Override
	public PcapHeader asReadOnly() {
		return new PcapHeaderRecord(tvSec, tvUsec, captureLength, wireLength, order);
	}

	/**
	 * @see org.jnetpcap.PcapHeader#captureLength()
	 */
	@Override
	public int captureLength() {
		return captureLength;
	}

	/**
	 * @see org.jnetpcap.PcapHeader#copyTo(java.lang.foreign.MemorySegment)
	 */
	@Override
	public int copyTo(MemorySegment dst) {
		PcapHeaderMemory.write(tvSec, tvUsec, captureLength, wireLength, dst, order);

		return PcapHeader.PCAP_HEADER_PADDED_LENGTH;
	}

	/**
	 * @see org.jnetpcap.PcapHeader#isReadOnly()
	 */
	@Override
	public boolean isReadOnly() {
		return false;
	}

	/**
	 * @see org.jnetpcap.PcapHeader#order()
	 */
	@Override
	public ByteOrder order() {
		return order;
	}

	/**
	 * @see org.jnetpcap.PcapHeader#order(java.nio.ByteOrder)
	 */
	@Override
	public PcapHeader order(ByteOrder newOrder) {
		this.order = newOrder;

		return this;
	}

	/**
	 * @see org.jnetpcap.PcapHeader#set(long, long, int, int)
	 */
	@Override
	public PcapHeader set(long tvSec, long tvUsec, int caplen, int wirelen) {
		this.tvSec = tvSec;
		this.tvUsec = tvUsec;
		this.captureLength = caplen;
		this.wireLength = wirelen;

		return this;
	}

	/**
	 * @see org.jnetpcap.PcapHeader#tvSec()
	 */
	@Override
	public long tvSec() {
		return tvSec;
	}

	/**
	 * @see org.jnetpcap.PcapHeader#tvUsec()
	 */
	@Override
	public long tvUsec() {
		return tvUsec;
	}

	/**
	 * @see org.jnetpcap.PcapHeader#wireLength()
	 */
	@Override
	public int wireLength() {
		return wireLength;
	}

}
