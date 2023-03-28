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

import java.lang.foreign.Addressable;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.lang.foreign.ValueLayout;

import org.jnetpcap.PcapHeader;
import org.jnetpcap.constant.PcapConstants;

/**
 * A utility class which holds references to native pcap header and native pcap
 * packet data. The scope of these addresses is libpcap packet scope and should
 * be used with great care or VM crashes can occur.
 * 
 * @param header memory address of the pcap header structure in native memory
 * @param data   memory address of the packet's data in native memory
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 */
public record PcapPacketRef(Addressable header, Addressable data) {

	/**
	 * Returns byte[] representation of the entire packet.
	 *
	 * @return the byte[] containing packet bytes
	 */
	public byte[] toArray() {
		return toArray(0, PcapConstants.MAX_SNAPLEN);
	}

	/**
	 * Returns an array containing only the packet bytes starting at {@code offset}
	 * and {@code offset + length}
	 *
	 * @param offset the offset offset into the packet
	 * @param length number of bytes starting at the offset
	 * @return the byte[] containing the selected bytes
	 */
	public byte[] toArray(int offset, int length) {
		var hdr = new PcapHeader(header.address(), MemorySession.openShared());

		if (length + offset > hdr.captureLength())
			length = hdr.captureLength() - offset;

		try (var scope = MemorySession.openShared()) {

			if (data instanceof MemorySegment src) {
				return src
						.asSlice(offset, length)
						.toArray(ValueLayout.JAVA_BYTE);

			} else {
				return MemorySegment
						.ofAddress(data.address().addOffset(offset), length, scope)
						.toArray(ValueLayout.JAVA_BYTE);
			}
		}
	}

}
