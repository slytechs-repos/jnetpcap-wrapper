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
package org.jnetpcap.internal;

import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.nio.ByteOrder.BIG_ENDIAN;
import static java.nio.ByteOrder.LITTLE_ENDIAN;

import java.lang.foreign.MemoryAddress;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout.OfInt;
import java.nio.ByteOrder;

/**
 * Configures different ABI (Application Binary Interfaces) for access to binary
 * pcap header data. On 64-bit architectures the header structure in native
 * memory received from libpcap will be padded to end up with 24 byte header
 * length. When stored in ''savefiles'' and handling in non native storage will
 * be represented as 16 byte compact structure.
 * 
 * Note that MemoryLayouts are actually harder to use in this case. Thus we poke
 * the values directly, plus its more efficient this way.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public enum PcapHeaderABI {
	PCAP_HEADER_COMPACT_LE(0, 4, 8, 12, LITTLE_ENDIAN), // 16 byte size
	PCAP_HEADER_COMPACT_BE(0, 4, 8, 12, BIG_ENDIAN), // 16 byte size
	PCAP_HEADER_PADDED_LE(0, 8, 16, 20, LITTLE_ENDIAN), // 24 byte size due to padding
	PCAP_HEADER_PADDED_BE(0, 8, 16, 20, BIG_ENDIAN); // 24 byte size due to padding

	private static final PcapHeaderABI NATIVE_ABI;
	private static final int BITMASK16 = 0xFFFFFFFF;
	static {
		if (NativeABI.is32bit() && (ByteOrder.nativeOrder() == LITTLE_ENDIAN))
			NATIVE_ABI = PCAP_HEADER_COMPACT_LE;

		else if (NativeABI.is64bit() && (ByteOrder.nativeOrder() == LITTLE_ENDIAN))
			NATIVE_ABI = PCAP_HEADER_PADDED_LE;

		else if (NativeABI.is32bit())
			NATIVE_ABI = PCAP_HEADER_COMPACT_BE;

		else
			NATIVE_ABI = PCAP_HEADER_PADDED_BE;

	}

	public static PcapHeaderABI compactAbi() {
		return compactAbi(ByteOrder.nativeOrder());
	}

	public static PcapHeaderABI compactAbi(ByteOrder bo) {

		return (bo == ByteOrder.BIG_ENDIAN)
				? PCAP_HEADER_COMPACT_BE
				: PCAP_HEADER_COMPACT_LE;
	}

	public static PcapHeaderABI paddedAbi() {
		return compactAbi(ByteOrder.nativeOrder());
	}

	public static PcapHeaderABI paddedAbi(ByteOrder bo) {

		return (bo == ByteOrder.BIG_ENDIAN)
				? PCAP_HEADER_PADDED_BE
				: PCAP_HEADER_PADDED_LE;
	}

	public static PcapHeaderABI nativeAbi() {
		return NATIVE_ABI;
	}

	public static PcapHeaderABI nativeAbi(ByteOrder bo) {
		if (bo == ByteOrder.nativeOrder())
			return NATIVE_ABI;

		if (bo == LITTLE_ENDIAN) {
			return switch (NATIVE_ABI) {
			case PCAP_HEADER_COMPACT_BE -> PCAP_HEADER_COMPACT_LE;
			case PCAP_HEADER_PADDED_BE -> PCAP_HEADER_PADDED_LE;
			default -> NATIVE_ABI;
			};

		} else {
			return switch (NATIVE_ABI) {
			case PCAP_HEADER_COMPACT_LE -> PCAP_HEADER_COMPACT_BE;
			case PCAP_HEADER_PADDED_LE -> PCAP_HEADER_PADDED_BE;
			default -> NATIVE_ABI;
			};

		}
	}

	private final int tvSecOffset;

	private final int tvUsecOffset;
	private final int captureLengthOffset;
	private final int wireLengthOffset;

	private final OfInt layout;
	private final int headerLenth;
	private final ByteOrder order;

	PcapHeaderABI(int secOff, int usecOff, int capOff, int wireOff, ByteOrder bo) {
		this.tvSecOffset = secOff;
		this.tvUsecOffset = usecOff;
		this.captureLengthOffset = capOff;
		this.wireLengthOffset = wireOff;
		this.layout = JAVA_INT.withOrder(bo);
		this.headerLenth = (wireOff == 12) ? 16 : 24;
		this.order = bo;
	}

	public int captureLength(MemoryAddress address) {
		return address.get(layout, captureLengthOffset) & BITMASK16;
	}

	public void captureLength(MemoryAddress address, int newLength) {
		address.set(layout, captureLengthOffset, newLength & BITMASK16);
	}

	public int captureLength(MemorySegment mseg) {
		return mseg.get(layout, captureLengthOffset) & BITMASK16;
	}

	public void captureLength(MemorySegment mseg, int newLength) {
		mseg.set(layout, captureLengthOffset, newLength & BITMASK16);
	}

	public int captureLengthOffset() {
		return captureLengthOffset;
	}

	/**
	 * Actual, in memory, header length as per this ABI and compiler padding.
	 *
	 * @return the int
	 */
	public int headerLength() {
		return headerLenth;
	}

	public ByteOrder order() {
		return this.order;
	}

	public long tvSec(MemoryAddress address) {
		return Integer.toUnsignedLong(address.get(layout, tvSecOffset));
	}

	public long tvSec(MemorySegment mseg) {
		return Integer.toUnsignedLong(mseg.get(layout, tvSecOffset));
	}

	public void tvSec(MemoryAddress address, long newTvSec) {
		address.set(layout, tvSecOffset, (int) newTvSec);
	}

	public void tvSec(MemorySegment mseg, long newTvSec) {
		mseg.set(layout, tvSecOffset, (int) newTvSec);
	}

	public int tvSecOffset() {
		return tvSecOffset;
	}

	public long tvUsec(MemoryAddress address) {
		return Integer.toUnsignedLong(address.get(layout, tvUsecOffset));
	}

	public long tvUsec(MemorySegment mseg) {
		return Integer.toUnsignedLong(mseg.get(layout, tvUsecOffset));
	}

	public void tvUsec(MemoryAddress address, long newTvUsec) {
		address.set(layout, tvUsecOffset, (int) newTvUsec);
	}

	public void tvUsec(MemorySegment mseg, long newTvUsec) {
		mseg.set(layout, tvUsecOffset, (int) newTvUsec);
	}

	public int tvUsecOffset() {
		return tvUsecOffset;
	}

	public int wireLength(MemoryAddress address) {
		return address.get(layout, wireLengthOffset) & BITMASK16;
	}

	public void wireLength(MemoryAddress address, int newLength) {
		address.set(layout, wireLengthOffset, newLength & BITMASK16);
	}

	public int wireLength(MemorySegment mseg) {
		return mseg.get(layout, wireLengthOffset) & BITMASK16;
	}

	public void wireLength(MemorySegment mseg, int newLength) {
		mseg.set(layout, wireLengthOffset, newLength & BITMASK16);
	}

	public int wireLengthOffset() {
		return wireLengthOffset;
	}

}
