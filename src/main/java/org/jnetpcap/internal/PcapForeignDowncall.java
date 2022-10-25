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
import java.lang.invoke.MethodHandle;

import org.jnetpcap.PcapException;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public class PcapForeignDowncall extends ForeignDowncall<PcapException> {

	public PcapForeignDowncall(String symbolName, MemorySegment symbolAddress, MethodHandle handle) {
		super(symbolName, symbolAddress, handle, PcapException::new);
	}

	public PcapForeignDowncall(String message) {
		super(message);
	}

	public PcapForeignDowncall(String message, Throwable cause) {
		super(message, cause);
	}

}
