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

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.lang.invoke.MethodHandle;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public class ForeignUpcall<T> {

	private static final Linker C_LINKER = Linker.nativeLinker();

	private final String message; // Stub error handler
	private final Throwable cause; // Stub error handler
	private final MethodHandle handle;
	private final FunctionDescriptor descriptor;

	ForeignUpcall(MethodHandle handle, FunctionDescriptor descriptor) {
		this.handle = handle;
		this.descriptor = descriptor;
		this.message = null;
		this.cause = null;
	}

	ForeignUpcall(String message, Throwable cause) {
		this.message = message;
		this.cause = cause;
		this.handle = null;
		this.descriptor = null;
	}

	private void throwIfErrors() {
		if (cause != null)
			throw (cause instanceof RuntimeException e)
					? e
					: new RuntimeException(message, cause);
	}

	public MemorySegment virtualStubPointer(T target) {
		return virtualStubPointer(target, MemorySession.openImplicit());
	}

	public MemorySegment virtualStubPointer(T target, MemorySession scope) {
		throwIfErrors();

		MethodHandle handle = this.handle.bindTo(target);

		return C_LINKER
				.upcallStub(handle, descriptor, scope);

	}

	public MemorySegment staticStubPointer() {
		return staticStubPointer(MemorySession.openImplicit());
	}

	public MemorySegment staticStubPointer(MemorySession scope) {
		throwIfErrors();

		return C_LINKER.upcallStub(handle, descriptor, scope);
	}
}
