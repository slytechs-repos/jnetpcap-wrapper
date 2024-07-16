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
import java.lang.invoke.MethodHandle;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.IntFunction;
import java.util.function.LongFunction;
import java.util.function.Supplier;

/**
 * The Class ForeignDowncall.
 *
 * @param <E> the element type
 */
public class ForeignDowncall<E extends Throwable> {

	/** The handle. */
	private final MethodHandle handle;
	
	/** The cause. */
	private final Throwable cause;
	
	/** The exception factory. */
	private final Function<String, E> exceptionFactory;
	
	/** The symbol name. */
	private final String symbolName;
	
	/** The symbol address. */
	private final MemorySegment symbolAddress;

	/**
	 * Instantiates a new foreign downcall.
	 *
	 * @param symbolName the symbol name
	 */
	public ForeignDowncall(String symbolName) {
		this.handle = null;
		this.cause = null;
		this.exceptionFactory = null;
		this.symbolName = symbolName;
		this.symbolAddress = null;
	}

	/**
	 * Instantiates a new foreign downcall.
	 *
	 * @param symbolName       the symbol name
	 * @param symbolAddress    the symbol address
	 * @param handle           the handle
	 * @param exceptionFactory the exception factory
	 */
	public ForeignDowncall(String symbolName, MemorySegment symbolAddress, MethodHandle handle,
			Function<String, E> exceptionFactory) {
		this.symbolName = symbolName;
		this.symbolAddress = symbolAddress;
		this.handle = Objects.requireNonNull(handle, "handle");
		this.exceptionFactory = exceptionFactory;
		this.cause = null;
	}

	/**
	 * Instantiates a new foreign downcall.
	 *
	 * @param symbolName the symbol name
	 * @param cause      the cause
	 */
	public ForeignDowncall(String symbolName, Throwable cause) {
		this.cause = Objects.requireNonNull(cause, "cause");
		this.handle = null;
		this.exceptionFactory = null;
		this.symbolName = symbolName;
		this.symbolAddress = null;
	}

	/**
	 * Handle.
	 *
	 * @return the method handle
	 */
	public MethodHandle handle() {
		if (handle == null)
			throw new IllegalStateException(
					"can not invoke native C function '" + symbolName + "'",
					cause);

		return handle;
	}

	/**
	 * Invoke int.
	 *
	 * @param messageFactory the message factory
	 * @param args           the args
	 * @return the int
	 * @throws E the e
	 */
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

	/**
	 * Invoke int.
	 *
	 * @param args the args
	 * @return the int
	 */
	public int invokeInt(Object... args) {

		try {
			return (int) handle().invokeWithArguments(args);
		} catch (Throwable e) { // VarHandle could throw this
			throw new RuntimeException(e);
		}
	}

	/**
	 * Invoke int.
	 *
	 * @param messageFactory the message factory
	 * @param args           the args
	 * @return the int
	 * @throws E the e
	 */
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

	/**
	 * Invoke long.
	 *
	 * @param messageFactory the message factory
	 * @param args           the args
	 * @return the long
	 * @throws E the e
	 */
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

	/**
	 * Invoke long.
	 *
	 * @param args the args
	 * @return the long
	 */
	public long invokeLong(Object... args) {

		try {
			return (long) handle().invokeWithArguments(args);
		} catch (RuntimeException e) { // VarHandle could throw this
			throw e;

		} catch (Throwable e) { // VarHandle could throw this
			throw new RuntimeException(e);
		}
	}

	/**
	 * Invoke long.
	 *
	 * @param messageFactory the message factory
	 * @param args           the args
	 * @return the long
	 * @throws E the e
	 */
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

	/**
	 * Invoke obj.
	 *
	 * @param <U>  the generic type
	 * @param args the args
	 * @return the u
	 */
	@SuppressWarnings("unchecked")
	public <U> U invokeObj(Object... args) {
		try {
			return (U) handle().invokeWithArguments(args);
		} catch (Throwable e) { // VarHandle could throw this
			throw new RuntimeException(e);
		}

	}

	/**
	 * Invoke obj.
	 *
	 * @param <U>            the generic type
	 * @param messageFactory the message factory
	 * @param args           the args
	 * @return the u
	 * @throws E the e
	 */
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

	/**
	 * Invoke string.
	 *
	 * @param args the args
	 * @return the string
	 */
	public String invokeString(Object... args) {

		try {
			MemorySegment address = (MemorySegment) handle().invokeWithArguments(args);

			return ForeignUtils.toJavaString(address);
		} catch (RuntimeException e) { // VarHandle could throw this
			throw e;

		} catch (Throwable e) { // VarHandle could throw this
			throw new RuntimeException(e);
		}
	}

	/**
	 * Invoke string.
	 *
	 * @param messageFactory the message factory
	 * @param args           the args
	 * @return the string
	 * @throws E the e
	 */
	public String invokeString(Supplier<String> messageFactory, Object... args) throws E {

		MemorySegment address;
		try {
			address = (MemorySegment) handle().invokeWithArguments(args);

		} catch (RuntimeException e) { // VarHandle could throw this
			throw e;

		} catch (Throwable e) { // VarHandle could throw this
			throw new RuntimeException(e);
		}

		validateObj(address, messageFactory);

		return address.getString(0, java.nio.charset.StandardCharsets.UTF_8);

	}

	/**
	 * Invoke void.
	 *
	 * @param args the args
	 */
	public void invokeVoid(Object... args) {

		try {
			handle().invokeWithArguments(args);
		} catch (RuntimeException e) { // VarHandle could throw this
			throw e;

		} catch (Throwable e) { // VarHandle could throw this
			throw new RuntimeException(e);
		}
	}

	/**
	 * Checks if is native symbol resolved.
	 *
	 * @return true, if is native symbol resolved
	 */
	public boolean isNativeSymbolResolved() {
		return handle != null;
	}

	/**
	 * Address.
	 *
	 * @return the memory segment
	 */
	public MemorySegment address() {
		return symbolAddress;
	}

	/**
	 * Symbol name.
	 *
	 * @return the string
	 */
	public String symbolName() {
		return symbolName;
	}

	/**
	 * Validate int.
	 *
	 * @param value        the value
	 * @param errorFactory the error factory
	 * @throws E the e
	 */
	protected void validateInt(int value, IntFunction<String> errorFactory) throws E {
		if (value < 0)
			throw exceptionFactory.apply(errorFactory.apply(value));
	}

	/**
	 * Validate int.
	 *
	 * @param value        the value
	 * @param errorFactory the error factory
	 * @throws E the e
	 */
	protected void validateInt(int value, Supplier<String> errorFactory) throws E {
		if (value < 0)
			throw exceptionFactory.apply(errorFactory.get());
	}

	/**
	 * Validate long.
	 *
	 * @param value        the value
	 * @param errorFactory the error factory
	 * @throws E the e
	 */
	protected void validateLong(long value, LongFunction<String> errorFactory) throws E {
		if (value < 0)
			throw exceptionFactory.apply(errorFactory.apply(value));
	}

	/**
	 * Validate long.
	 *
	 * @param value        the value
	 * @param errorFactory the error factory
	 * @throws E the e
	 */
	protected void validateLong(long value, Supplier<String> errorFactory) throws E {
		if (value < 0)
			throw exceptionFactory.apply(errorFactory.get());
	}

	/**
	 * Validate obj.
	 *
	 * @param obj          the obj
	 * @param errorFactory the error factory
	 * @throws E the e
	 */
	protected void validateObj(Object obj, Supplier<String> errorFactory) throws E {
		if (obj == null || (obj instanceof MemorySegment addr) && ForeignUtils.isNullAddress(addr))
			throw exceptionFactory.apply(errorFactory.get());
	}

	/**
	 * To string.
	 *
	 * @return the string
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