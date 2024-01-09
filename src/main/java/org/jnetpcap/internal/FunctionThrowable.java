/*
 * Sly Technologies Free License
 * 
 * Copyright 2023 Sly Technologies Inc.
 *
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.jnetpcap.internal;

import java.util.function.Function;

/**
 * A functional interface that throws checked exceptions when applied.
 *
 * @param <T> the generic input type
 * @param <R> the generic return type
 */
public interface FunctionThrowable<T, R> {
	
	/**
	 * Converts a checked function lambda to an unchecked/runtime function
	 * equivalent.
	 *
	 * @param <T>  the generic input type
	 * @param <R>  the generic return type
	 * @param func the func
	 * @return the function
	 */
	static <T, R> Function<T, R> unchecked(FunctionThrowable<T, R> func) {
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
	static <T, R> R applyUnchecked(T input, FunctionThrowable<T, R> func) {
		try {
			return func.apply(input);
		} catch (Throwable e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Apply the function computation and return a result.
	 *
	 * @param t the input value
	 * @return the result value
	 * @throws Throwable any exception which will be rethrown as a RuntimeException
	 */
	R apply(T t) throws Throwable;
}