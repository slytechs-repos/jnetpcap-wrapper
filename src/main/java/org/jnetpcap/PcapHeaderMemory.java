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

import java.lang.foreign.Addressable;
import java.lang.foreign.MemoryAddress;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.nio.ByteOrder;

import org.jnetpcap.internal.PcapHeaderABI;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
final class PcapHeaderMemory implements PcapHeader {

	/**
	 * Allocates a new PcapHeader in native memory. Current, low resolution time
	 * source is used to estimate the tvSec and tvUsec values.
	 * 
	 * @param length the length of the packet in bytes, used to initialize both
	 *               wireLength and captureLength fields.
	 * @param scope  for memory allocation
	 * @return new native memory backed pcap header
	 */
	public static PcapHeader allocate(int length, MemorySession scope) {
		MemorySegment mseg = scope.allocate(PcapHeader.PCAP_HEADER_PADDED_LENGTH);
		long time = System.currentTimeMillis();
		long tvSec = time / 1000;
		long tvUsed = (time % 1000) * 1000;

		write(tvSec, tvUsed, length, length, mseg, ByteOrder.nativeOrder());

		return new PcapHeaderMemory(mseg);
	}

	/**
	 * Allocates a new PcapHeader in native memory. All fields are uninitialized and
	 * may not be zeroed out, depending on the constants of the native memory.
	 *
	 * @param scope for memory allocation
	 * @return new native memory backed pcap header
	 */
	public static PcapHeader allocate(MemorySession scope) {
		MemorySegment mseg = scope.allocate(PcapHeader.PCAP_HEADER_PADDED_LENGTH);

		return new PcapHeaderMemory(mseg);
	}

	static MemorySegment newMemory(long tvSec, long tvUsec, int caplen, int wirelen, ByteOrder order) {
		MemorySegment dst = MemorySegment.allocateNative(PCAP_HEADER_PADDED_LENGTH, MemorySession.global());
		PcapHeaderABI abi = PcapHeaderABI.nativeAbi(order);

		writeUsingAbi0(abi, dst.address(), tvSec, tvUsec, caplen, wirelen);

		return dst;
	}

	static MemorySegment newMemoryFrom(PcapHeader src) {
		return newMemory(src.tvSec(), src.tvUsec(), src.captureLength(), src.wireLength(), src.order());
	}

	static PcapHeader newObjectHeader(Addressable address, ByteOrder order) {
		PcapHeaderABI abi = PcapHeaderABI.nativeAbi(order);
		MemoryAddress addr = address.address();

		return new PcapHeaderObject(
				abi.tvSec(addr),
				abi.tvUsec(addr),
				abi.captureLength(addr),
				abi.wireLength(addr),
				order);
	}

	static PcapHeader newRecordHeader(Addressable address, ByteOrder order) {
		PcapHeaderABI abi = PcapHeaderABI.nativeAbi(order);
		MemoryAddress addr = address.address();

		return new PcapHeaderRecord(
				abi.tvSec(addr),
				abi.tvUsec(addr),
				abi.captureLength(addr),
				abi.wireLength(addr),
				order);
	}

	static int write(long tvSec, long tvUsec, int caplen, int wirelen, Addressable dst, ByteOrder order) {
		PcapHeaderABI abi = PcapHeaderABI.nativeAbi(order);

		writeUsingAbi0(abi, dst.address(), tvSec, tvUsec, caplen, wirelen);

		return abi.headerLength();
	}

	private static void writeUsingAbi0(PcapHeaderABI abi, Addressable addressable, long tvSec, long tvUsec, int caplen,
			int wirelen) {

		var mseg = addressable instanceof MemorySegment seg
				? seg
				: MemorySegment.ofAddress(addressable.address(), PCAP_HEADER_PADDED_LENGTH, MemorySession.global());

		abi.tvSec(mseg, tvSec);
		abi.tvUsec(mseg, tvUsec);
		abi.captureLength(mseg, caplen);
		abi.wireLength(mseg, wirelen);

	}

	private MemorySegment mseg;

	private PcapHeaderABI abi;

	public PcapHeaderMemory(Addressable addressable) {
		this.abi = PcapHeaderABI.nativeAbi();
		this.mseg = addressable instanceof MemorySegment mseg
				? mseg
				: MemorySegment.ofAddress(addressable.address(), PCAP_HEADER_PADDED_LENGTH, MemorySession.global());
	}

	/**
	 * @see org.jnetpcap.PcapHeader#asMemoryReference()
	 */
	@Override
	public Addressable asMemoryReference() {
		return mseg;
	}

	/**
	 * @see org.jnetpcap.PcapHeader#asReadOnly()
	 */
	@Override
	public PcapHeader asReadOnly() {
		if (!mseg.isReadOnly())
			return new PcapHeaderMemory(mseg.asReadOnly());

		return this;
	}

	/**
	 * @see org.jnetpcap.PcapHeader#captureLength()
	 */
	@Override
	public int captureLength() {
		return abi.captureLength(mseg);
	}

	/**
	 * @see org.jnetpcap.PcapHeader#copyTo(java.lang.foreign.MemorySegment)
	 */
	@Override
	public int copyTo(MemorySegment dst) {
		dst.copyFrom(mseg);

		return abi.headerLength();
	}

	/**
	 * @see org.jnetpcap.PcapHeader#isReadOnly()
	 */
	@Override
	public boolean isReadOnly() {
		return mseg.isReadOnly();
	}

	/**
	 * @see org.jnetpcap.PcapHeader#order()
	 */
	@Override
	public ByteOrder order() {
		return abi.order();
	}

	/**
	 * @see org.jnetpcap.PcapHeader#order(java.nio.ByteOrder)
	 */
	@Override
	public PcapHeader order(ByteOrder newOrder) {
		this.abi = PcapHeaderABI.nativeAbi(newOrder);
		return this;
	}

	/**
	 * @see org.jnetpcap.PcapHeader#set(int, int, int, int)
	 */
	@Override
	public PcapHeader set(long tvSec, long tvUsec, int caplen, int wirelen) {

		writeUsingAbi0(this.abi, this.mseg, tvSec, tvUsec, caplen, wirelen);

		return this;
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "PcapHeader"
				+ " [tvSec=" + tvSec()
				+ ", tvUsec=" + tvUsec()
				+ ", captureLength=" + captureLength()
				+ ", wireLength=" + wireLength()
				+ ", memory=" + mseg
				+ "]";
	}

	/**
	 * @see org.jnetpcap.PcapHeader#tvSec()
	 */
	@Override
	public long tvSec() {
		return abi.tvSec(mseg);
	}

	/**
	 * @see org.jnetpcap.PcapHeader#tvUsec()
	 */
	@Override
	public long tvUsec() {
		return abi.tvUsec(mseg);
	}

	/**
	 * @see org.jnetpcap.PcapHeader#wireLength()
	 */
	@Override
	public int wireLength() {
		return abi.wireLength(mseg);
	}
}
