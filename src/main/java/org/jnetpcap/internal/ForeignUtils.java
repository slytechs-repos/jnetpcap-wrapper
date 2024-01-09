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

import java.lang.foreign.MemoryLayout.PathElement;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 * The Class ForeignUtils.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public final class ForeignUtils {

	/**
	 * A functional interface that throws checked exceptions when applied.
	 *
	 * @param <T> the generic input type
	 * @param <R> the generic return type
	 */
	public interface FunctionThrowable<T, R> {

		/**
		 * Apply the function computation and return a result.
		 *
		 * @param t the input value
		 * @return the result value
		 * @throws Throwable any exception which will be rethrown as a RuntimeException
		 */
		R apply(T t) throws Throwable;
	}

	/** The Constant DEFAULT_MAX_STRING_LEN. */
	private final static long DEFAULT_MAX_STRING_LEN = 64 * 1024;

	/**
	 * To java string.
	 *
	 * @param memorySegment the memory segment
	 * @return the string
	 */
	public static String toJavaString(Object memorySegment) {
		return toJavaString(((MemorySegment) memorySegment));
	}

	/**
	 * Checks if is null address.
	 *
	 * @param address the address
	 * @return true, if is null address
	 */
	public static boolean isNullAddress(MemorySegment address) {
		return (address == null) || (address.address() == 0);
	}

	/**
	 * To java string.
	 *
	 * @param addr the addr
	 * @return the string
	 */
	public static String toJavaString(MemorySegment addr) {
		if (ForeignUtils.isNullAddress(addr))
			return null;

		if (addr.byteSize() == 0)
			addr = addr.reinterpret(DEFAULT_MAX_STRING_LEN);

		String str = addr.getUtf8String(0);
		return str;
	}

	/**
	 * Read address.
	 *
	 * @param handle    the handle
	 * @param addressAt the address at
	 * @return the memory segment
	 */
	public static MemorySegment readAddress(VarHandle handle, MemorySegment addressAt) {
		var read = (MemorySegment) handle.get(addressAt);
		return read;
	}

	/**
	 * Generates an element path for MemoryLayouts based on dot-separated
	 * MemoryLayout path.
	 *
	 * @param path the source path to be parsed
	 * @return the generated array of path elements
	 */
	public static PathElement[] path(String path) {
		return Stream.of(path.split("\\."))
				.map(String::trim)
				.map(PathElement::groupElement)
				.toArray(PathElement[]::new);
	}

	/**
	 * Converts a checked function lambda to an unchecked/runtime function
	 * equivalent.
	 *
	 * @param <T>  the generic input type
	 * @param <R>  the generic return type
	 * @param func the func
	 * @return the function
	 */
	public static <T, R> Function<T, R> unchecked(FunctionThrowable<T, R> func) {
		return t -> {
			try {
				return func.apply(t);
			} catch (Throwable e) {
				throw new RuntimeException(e);
			}
		};
	}

	/**
	 * Applies an input value to a checked function and returns the function result.
	 *
	 * @param <T>  the generic input type
	 * @param <R>  the generic return type
	 * @param func the func
	 * @return output of the function
	 */
	public static <T, R> R unchecked(T input, FunctionThrowable<T, R> func) {
		try {
			return func.apply(input);
		} catch (Throwable e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Instantiates a new foreign utils.
	 */
	private ForeignUtils() {
	}

}
