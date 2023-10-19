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
package org.jnetpcap.util;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import org.jnetpcap.constant.PcapConstants;
import org.jnetpcap.internal.ForeignUtils;
import org.jnetpcap.internal.PcapHeaderABI;

/**
 * A utility class which holds references to native pcap header and native pcap
 * packet data. The scope of these addresses is libpcap packet scope and should
 * be used with great care or VM crashes can occur.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 */
public record PcapPacketRef(Object abi, MemorySegment header, MemorySegment data) {

	/**
	 * Returns byte[] representation of the entire packet.
	 *
	 * @return the byte[] containing packet bytes
	 */
	public byte[] toArray() {
		return toArray(0, PcapConstants.MAX_SNAPLEN);
	}

	/**
	 * Calculate the header ABI.
	 *
	 * @return the calculated ABI
	 */
	private PcapHeaderABI getAbi() {
		if (abi instanceof PcapHeaderABI a)
			return a;

		return PcapHeaderABI.nativeAbi();
	}

	/**
	 * Capture length of the packet.
	 *
	 * @return the capture length pcap header field value
	 */
	public int captureLength() {
		return getAbi().captureLength(header);
	}

	/**
	 * Wire length of the packet.
	 *
	 * @return the wire length pcap header field value
	 */
	public int wireLength() {
		return getAbi().wireLength(header);
	}

	/**
	 * The timestamp in seconds in epoch time.
	 *
	 * @return the epoch seconds since Jan 1st, 1970.
	 */
	public long tvSec() {
		return getAbi().tvSec(header);
	}

	/**
	 * The timestamp fraction of a second.
	 *
	 * @return fraction of a second in micros or nanos.
	 */
	public long tvUsec() {
		return getAbi().tvUsec(header);
	}

	/**
	 * Returns an array containing only the packet bytes starting at {@code offset}
	 * and {@code offset + length}.
	 *
	 * @param offset the offset offset into the packet
	 * @param length number of bytes starting at the offset
	 * @return the byte[] containing the selected bytes
	 */
	public byte[] toArray(int offset, int length) {
		int caplen = captureLength();

		if ((length + offset) > caplen)
			length = (caplen - offset);

		if (data instanceof MemorySegment src) {
			return src
					.asSlice(offset, length)
					.toArray(ValueLayout.JAVA_BYTE);
		}

		try (var arena = Arena.openShared()) {
			return ForeignUtils
					.reinterpret(data.address() + offset, length, arena)
					.toArray(ValueLayout.JAVA_BYTE);
		}
	}

}
