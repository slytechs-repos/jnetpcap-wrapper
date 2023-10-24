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

import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public final class ForeignUtils {

	private final static long DEFAULT_MAX_STRING_LEN = 64 * 1024;

	public static String toJavaString(Object memorySegment) {
		return toJavaString(((MemorySegment) memorySegment));
	}

	public static boolean isNullAddress(MemorySegment address) {
		return (address == null) || (address.address() == 0);
	}

	public static String toJavaString(MemorySegment addr) {
		if (ForeignUtils.isNullAddress(addr))
			return null;

		if (addr.byteSize() == 0)
			addr = addr.reinterpret(DEFAULT_MAX_STRING_LEN);

		String str = addr.getUtf8String(0);
		return str;
	}

	public static MemorySegment readAddress(VarHandle handle, MemorySegment addressAt) {
		var read = (MemorySegment) handle.get(addressAt);
		return read;
	}

	private ForeignUtils() {
	}

}
