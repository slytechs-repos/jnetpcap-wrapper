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

import static java.nio.ByteOrder.*;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout.OfInt;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Optional;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiFunction;

import org.jnetpcap.Pcap.LibraryPolicy;
import org.jnetpcap.PcapHeaderException;
import org.jnetpcap.PcapHeaderException.OutOfRangeException;

import static java.lang.foreign.ValueLayout.*;

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

	COMPACT_LE("CL", 0, 4, 8, 12, LITTLE_ENDIAN), // 16 byte size
	COMPACT_BE("CB", 0, 4, 8, 12, BIG_ENDIAN), // 16 byte size
	PADDED_LE("PL", 0, 8, 16, 20, LITTLE_ENDIAN), // 24 byte size due to padding
	PADDED_BE("PB", 0, 8, 16, 20, BIG_ENDIAN) // 24 byte size due to padding

	;

	private static final PcapHeaderABI NATIVE_ABI;
	private static final boolean NATIVE_ABI_OVERRIDE;

	private static final int BITMASK16 = 0xFFFFFFFF;
	private static final int MIN_FRAME_SIZE = 14;
	private static final int MAX_FRAME_SIZE = 64 * 1024;
	private static final Lock CAREFUL_LOCK = new ReentrantLock();

	static {

		if (System.getProperty(LibraryPolicy.SYSTEM_PROPERTY_ABI) != null) {
			String constantName = System.getProperty(LibraryPolicy.SYSTEM_PROPERTY_ABI);

			NATIVE_ABI = Optional
					.ofNullable(PcapHeaderABI.valueOfPcapHeaderABI(constantName))
					.orElseGet(PcapHeaderABI::selectNativeABI);
			NATIVE_ABI_OVERRIDE = NATIVE_ABI.name().equalsIgnoreCase(constantName);

			if (!NATIVE_ABI_OVERRIDE) {
				try {
					LibraryPolicy.getLogginOutput().append(""
							+ "Failed override ABI [-D%s=%s], reverting to defaults. "
							+ ""
									.formatted(
											LibraryPolicy.SYSTEM_PROPERTY_ABI,
											constantName));
				} catch (IOException e) {
					throw new ExceptionInInitializerError(e);
				}
			}
		} else {
			NATIVE_ABI = selectNativeABI();
			NATIVE_ABI_OVERRIDE = false;
		}

	}

	private static volatile boolean disableValidation = false;

	private static PcapHeaderABI calcSwappedABI(PcapHeaderABI abi) {
		return switch (abi) {
		case COMPACT_BE -> COMPACT_LE;
		case COMPACT_LE -> COMPACT_BE;
		case PADDED_BE -> PADDED_LE;
		case PADDED_LE -> PADDED_BE;

		};
	}

	public static PcapHeaderABI compactAbi() {
		return compactAbi(ByteOrder.nativeOrder());
	}

	public static PcapHeaderABI compactAbi(boolean isSwapped) {
		if (isSwapped) {
			return calcSwappedABI(compactAbi(ByteOrder.nativeOrder()));

		} else {
			return compactAbi(ByteOrder.nativeOrder());
		}
	}

	public static PcapHeaderABI compactAbi(ByteOrder bo) {

		return (bo == ByteOrder.BIG_ENDIAN)
				? COMPACT_BE
				: COMPACT_LE;
	}

	public static PcapHeaderABI nativeAbi() {
		return NATIVE_ABI;
	}

	public static PcapHeaderABI nativeAbi(ByteOrder bo) {
		if (bo == ByteOrder.nativeOrder())
			return NATIVE_ABI;

		if (bo == LITTLE_ENDIAN) {
			return switch (NATIVE_ABI) {
			case COMPACT_BE -> COMPACT_LE;
			case PADDED_BE -> PADDED_LE;
			default -> NATIVE_ABI;
			};

		} else {
			return switch (NATIVE_ABI) {
			case COMPACT_LE -> COMPACT_BE;
			case PADDED_LE -> PADDED_BE;
			default -> NATIVE_ABI;
			};

		}
	}

	public static PcapHeaderABI paddedAbi() {
		return compactAbi(ByteOrder.nativeOrder());
	}

	public static PcapHeaderABI selectDeadAbi() {
		return NATIVE_ABI;
	}

	public static PcapHeaderABI selectLiveAbi() {
		return NATIVE_ABI;
	}

	private static PcapHeaderABI selectNativeABI() {
		/* Npcap compiles all structures in "compact" mode even on 64-bit machines */
		if (NativeABI.current() == NativeABI.WIN64)
			return ByteOrder.nativeOrder() == LITTLE_ENDIAN
					? COMPACT_LE
					: COMPACT_BE;

		if (NativeABI.is32bit() && (ByteOrder.nativeOrder() == LITTLE_ENDIAN))
			return COMPACT_LE;

		else if (NativeABI.is64bit() && (ByteOrder.nativeOrder() == LITTLE_ENDIAN))
			return PADDED_LE;

		else if (NativeABI.is32bit())
			return COMPACT_BE;

		else
			return PADDED_BE;
	}

	public static PcapHeaderABI selectOfflineAbi(boolean isSwapped) {
		return isSwapped
				? calcSwappedABI(NATIVE_ABI)
				: NATIVE_ABI;
	}

	public static PcapHeaderException throwListOfAllAbiPossibilities(
			ByteBuffer buffer,
			OutOfRangeException cause,
			String name,
			BiFunction<PcapHeaderABI, ByteBuffer, Integer> action)
			throws PcapHeaderException {

		if (action == null)
			return cause;

		final ByteOrder savedOrder = buffer.order();

		try {
			CAREFUL_LOCK.lock();

			var list = new ArrayList<String>();

			disableValidation = true;
			for (PcapHeaderABI abi : PcapHeaderABI.values()) {
				try {
					buffer.order(abi.order); // Switch ABIs byte order
					int value = action.apply(abi, buffer);
					boolean isInRange = value > MIN_FRAME_SIZE && value < MAX_FRAME_SIZE;

					int off = name.startsWith("cap")
							? abi.captureLengthOffset
							: abi.wireLengthOffset;

					if (isInRange)
						list.add("%s(%d)".formatted(abi, value));
					else
						list.add("%s(+%d=0x%04X)".formatted(abi.abbr, off, value));

				} catch (PcapHeaderException e) {
					list.add(e.getMessage());
				}
			}

			list.add("Buf[%d/%d/%d]"
					.formatted(buffer.position(), buffer.limit(), buffer.capacity()));

			return cause
					.setPossiblities(list)
					.setMethodName(name);
		} finally {
			buffer.order(savedOrder);
			disableValidation = false;
			CAREFUL_LOCK.unlock();
		}
	}

	private static PcapHeaderABI valueOfPcapHeaderABI(String name) {
		for (PcapHeaderABI abi : values()) {
			if (abi.name().equalsIgnoreCase(name))
				return abi;
		}

		return null;
	}

	private final int tvSecOffset;

	private final int tvUsecOffset;
	private final int captureLengthOffset;
	private final int wireLengthOffset;

	private final OfInt layout;
	private final int headerLenth;
	private final ByteOrder order;
	private final String abbr;
	PcapHeaderABI(String abbr, int secOff, int usecOff, int capOff, int wireOff, ByteOrder bo) {
		this.abbr = abbr;
		this.tvSecOffset = secOff;
		this.tvUsecOffset = usecOff;
		this.captureLengthOffset = capOff;
		this.wireLengthOffset = wireOff;
		this.layout = JAVA_INT.withOrder(bo);
		this.headerLenth = (wireOff == 12) ? 16 : 24;
		this.order = bo;
	}

	public int captureLength(ByteBuffer buffer) {
		return validateLength(buffer.order(order).getInt(captureLengthOffset) & BITMASK16);
	}

	public int captureLength(MemorySegment mseg) {
		return validateLength(mseg.get(layout, captureLengthOffset) & BITMASK16);
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

	public long tvSec(MemorySegment mseg) {
		return Integer.toUnsignedLong(mseg.get(layout, tvSecOffset));
	}

	public void tvSec(MemorySegment mseg, long newTvSec) {
		mseg.set(layout, tvSecOffset, (int) newTvSec);
	}

	public int tvSecOffset() {
		return tvSecOffset;
	}

	public long tvUsec(MemorySegment mseg) {
		return Integer.toUnsignedLong(mseg.get(layout, tvUsecOffset));
	}

	public void tvUsec(MemorySegment mseg, long newTvUsec) {
		mseg.set(layout, tvUsecOffset, (int) newTvUsec);
	}

	public int tvUsecOffset() {
		return tvUsecOffset;
	}

	private int validateLength(int length) throws OutOfRangeException {
		if (disableValidation)
			return length;

		if ((length < MIN_FRAME_SIZE) || (length > MAX_FRAME_SIZE))
			throw new OutOfRangeException(this, length);

		return length;
	}

	public int wireLength(ByteBuffer buffer) {
		return validateLength(buffer.order(order).getInt(wireLengthOffset) & BITMASK16);
	}

	public int wireLength(MemorySegment mseg) {
		return validateLength(mseg.get(layout, wireLengthOffset) & BITMASK16);
	}

	public void wireLength(MemorySegment mseg, int newLength) {
		mseg.set(layout, wireLengthOffset, newLength & BITMASK16);
	}

	public int wireLengthOffset() {
		return wireLengthOffset;
	}

}
