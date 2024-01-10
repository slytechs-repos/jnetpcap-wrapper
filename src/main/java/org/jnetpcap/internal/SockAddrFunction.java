/*
 * Copyright 2023 Sly Technologies Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jnetpcap.internal;

import java.lang.foreign.MemorySegment;

/**
 * Maps memory segment to where address resides.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public interface SockAddrFunction {
	
	/** The Constant SOCKADDR_STRUCT_MAP_TABLE. INTERNAL API */
	public static final SockAddrFunction[] SOCKADDR_STRUCT_MAP_TABLE = new SockAddrFunction[256];

	/**
	 * Map to address.
	 *
	 * @param segment the segment
	 * @param len     the len
	 * @return the memory segment
	 */
	MemorySegment mapToAddress(MemorySegment segment, long len);
}
