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
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public record PcapPacketRef(Addressable header, Addressable data) {

	public byte[] toArray() {
		return toArray(0, PcapConstants.MAX_SNAPLEN);
	}

	public byte[] toArray(int offset, int snaplen) {
		var hdr = PcapHeader.ofAddress(header);

		if (snaplen + offset > hdr.captureLength())
			snaplen = hdr.captureLength() - offset;

		try (var scope = MemorySession.openShared()) {

			if (data instanceof MemorySegment src) {
				return src
						.asSlice(offset, snaplen)
						.toArray(ValueLayout.JAVA_BYTE);

			} else {
				return MemorySegment
						.ofAddress(data.address().addOffset(offset), snaplen, scope)
						.toArray(ValueLayout.JAVA_BYTE);
			}
		}
	}

}
