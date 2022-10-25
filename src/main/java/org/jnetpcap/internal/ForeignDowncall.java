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

import java.lang.foreign.MemoryAddress;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.IntFunction;
import java.util.function.LongFunction;
import java.util.function.Supplier;

public class ForeignDowncall<E extends Throwable> {

	private final MethodHandle handle;
	private final Throwable cause;
	private final Function<String, E> exceptionFactory;
	private final String symbolName;
	private final MemorySegment symbolAddress;

	public ForeignDowncall(String symbolName) {
		this.handle = null;
		this.cause = null;
		this.exceptionFactory = null;
		this.symbolName = symbolName;
		this.symbolAddress = null;
	}

	public ForeignDowncall(String symbolName, MemorySegment symbolAddress, MethodHandle handle,
			Function<String, E> exceptionFactory) {
		this.symbolName = symbolName;
		this.symbolAddress = symbolAddress;
		this.handle = Objects.requireNonNull(handle, "handle");
		this.exceptionFactory = exceptionFactory;
		this.cause = null;
	}

	public ForeignDowncall(String symbolName, Throwable cause) {
		this.cause = Objects.requireNonNull(cause, "cause");
		this.handle = null;
		this.exceptionFactory = null;
		this.symbolName = symbolName;
		this.symbolAddress = null;
	}

	public MethodHandle handle() {
		if (handle == null)
			throw new IllegalStateException(
					"can not invoke native C function '" + symbolName + "'",
					cause);

		return handle;
	}

	public int invokeInt(IntFunction<String> messageFactory, Object... args) throws E {
		int result;

		try {
			result = (int) handle().invokeWithArguments(args);
		} catch (RuntimeException e) { // VarHandle could throw this
			throw e;

		} catch (Throwable e) { // VarHandle could throw this
			throw new RuntimeException(e);
		}

		validateInt(result, messageFactory);

		return result;
	}

	public int invokeInt(Object... args) {

		try {
			return (int) handle().invokeWithArguments(args);
		} catch (Throwable e) { // VarHandle could throw this
			throw new RuntimeException(e);
		}
	}

	@SuppressWarnings("unchecked")
	public int invokeInt(Supplier<String> messageFactory, Object... args) throws E {
		int result;

		try {
			result = (int) handle().invokeWithArguments(args);
		} catch (RuntimeException e) { // VarHandle could throw this
			throw e;

		} catch (Throwable e) { // VarHandle could throw this
			throw (E) e;
		}

		validateInt(result, messageFactory);

		return result;
	}

	@SuppressWarnings("unchecked")
	public long invokeLong(LongFunction<String> messageFactory, Object... args) throws E {
		long result;

		try {
			result = (long) handle().invokeWithArguments(args);
		} catch (RuntimeException e) { // VarHandle could throw this
			throw e;

		} catch (Throwable e) { // VarHandle could throw this
			throw (E) e;
		}

		validateLong(result, messageFactory);

		return result;
	}

	public long invokeLong(Object... args) {

		try {
			return (long) handle().invokeWithArguments(args);
		} catch (RuntimeException e) { // VarHandle could throw this
			throw e;

		} catch (Throwable e) { // VarHandle could throw this
			throw new RuntimeException(e);
		}
	}

	@SuppressWarnings("unchecked")
	public long invokeLong(Supplier<String> messageFactory, Object... args) throws E {
		long result;

		try {
			result = (long) handle().invokeWithArguments(args);
		} catch (RuntimeException e) { // VarHandle could throw this
			throw e;

		} catch (Throwable e) { // VarHandle could throw this
			throw (E) e;
		}

		validateLong(result, messageFactory);

		return result;
	}

	@SuppressWarnings("unchecked")
	public <U> U invokeObj(Object... args) {
		try {
			return (U) handle().invokeWithArguments(args);
		} catch (Throwable e) { // VarHandle could throw this
			throw new RuntimeException(e);
		}

	}

	@SuppressWarnings("unchecked")
	public <U> U invokeObj(Supplier<String> messageFactory, Object... args) throws E {
		U result;
		try {
			result = (U) handle().invokeWithArguments(args);
		} catch (RuntimeException e) { // VarHandle could throw this
			throw e;

		} catch (Throwable e) { // VarHandle could throw this
			throw new RuntimeException(e);
		}

		validateObj(result, messageFactory);

		return result;
	}

	public String invokeString(Object... args) {

		try {
			MemoryAddress address = (MemoryAddress) handle().invokeWithArguments(args);

			return ForeignUtils.toJavaString(address);
		} catch (RuntimeException e) { // VarHandle could throw this
			throw e;

		} catch (Throwable e) { // VarHandle could throw this
			throw new RuntimeException(e);
		}
	}

	public String invokeString(Supplier<String> messageFactory, Object... args) throws E {

		MemoryAddress address;
		try {
			address = (MemoryAddress) handle().invokeWithArguments(args);

		} catch (RuntimeException e) { // VarHandle could throw this
			throw e;

		} catch (Throwable e) { // VarHandle could throw this
			throw new RuntimeException(e);
		}

		validateObj(address, messageFactory);

		return address.getUtf8String(0);

	}

	public void invokeVoid(Object... args) {

		try {
			handle().invokeWithArguments(args);
		} catch (RuntimeException e) { // VarHandle could throw this
			throw e;

		} catch (Throwable e) { // VarHandle could throw this
			throw new RuntimeException(e);
		}
	}

	public boolean isNativeSymbolResolved() {
		return handle != null;
	}

	public MemoryAddress address() {
		return symbolAddress.address();
	}

	public String symbolName() {
		return symbolName;
	}

	protected void validateInt(int value, IntFunction<String> errorFactory) throws E {
		if (value < 0)
			throw exceptionFactory.apply(errorFactory.apply(value));
	}

	protected void validateInt(int value, Supplier<String> errorFactory) throws E {
		if (value < 0)
			throw exceptionFactory.apply(errorFactory.get());
	}

	protected void validateLong(long value, LongFunction<String> errorFactory) throws E {
		if (value < 0)
			throw exceptionFactory.apply(errorFactory.apply(value));
	}

	protected void validateLong(long value, Supplier<String> errorFactory) throws E {
		if (value < 0)
			throw exceptionFactory.apply(errorFactory.get());
	}

	protected void validateObj(Object obj, Supplier<String> errorFactory) throws E {
		if (obj == null || (obj instanceof MemoryAddress addr) && addr == MemoryAddress.NULL)
			throw exceptionFactory.apply(errorFactory.get());
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		if (handle == null) {
			return "ForeignDowncall"
					+ " [symbolName=" + symbolName
					+ ", cause=" + cause
					+ "]";
		} else {
			return "ForeignDowncall"
					+ " [symbolName=" + symbolName
					+ ", symbolAddress=" + symbolAddress
					+ "]";
		}
	}
}