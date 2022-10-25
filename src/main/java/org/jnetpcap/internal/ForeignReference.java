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
import java.lang.foreign.MemorySession;
import java.util.ArrayList;
import java.util.Objects;
import java.util.Random;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public class ForeignReference<T> {

	private static final Random RANDOM = new Random();
	private static final int EXPAND_CAPACITY_SIZE = 10;

	public static <T> ForeignReference<T> emulate() {
		return new ForeignReference<>();
	}

	public static <T> ForeignReference<T> emulate(int maxCapacity) {
		if (maxCapacity <= 0)
			throw new IllegalArgumentException("max capacity must be greater than 0 (%d)"
					.formatted(maxCapacity));

		return new ForeignReference<>(maxCapacity);
	}

	private final long id = Integer.toUnsignedLong(RANDOM.nextInt());
	private final ArrayList<T> references = new ArrayList<>(10);
	private int limit = EXPAND_CAPACITY_SIZE;
	private int maxCapacity;

	public ForeignReference() {
		this(Integer.MAX_VALUE);
	}

	private ForeignReference(int maxCapacity) {
		this.maxCapacity = maxCapacity;

		for (int i = 0; i < limit; i++)
			references.add(null);
	}

	private synchronized int add(T obj, int hashCode) {

		/* Check for quick empty slot */
		int hint = hashCode % limit;
		if (references.get(hint) == null) {
			references.set(hint, obj);

			return hint;
		}

		/* Search entire list for an empty slot */
		for (int i = 0; i < limit; i++) {
			if (references.get(i) == null) {
				references.set(i, obj);

				return i;
			}
		}

		/* if list is full expand it */
		int index = limit;

		expandCapacity(limit + EXPAND_CAPACITY_SIZE);
		references.set(index, obj);

		return index;
	}

	private void expandCapacity(int newLimit) {
		if (newLimit > maxCapacity)
			throw new IllegalArgumentException("maximum capacity reached (%d)"
					.formatted(maxCapacity));

		references.ensureCapacity(newLimit);

		for (int i = limit; i < newLimit; i++)
			references.add(null);

		limit = newLimit;
	}

	private long store(T obj) {
		int hashCode = obj.hashCode();
		long hash = id ^ hashCode;
		long index = id ^ add(obj, hashCode);

		return (hash << 32) | index;
	}

	@SuppressWarnings("unchecked")
	private synchronized T remove(MemoryAddress address) throws IllegalArgumentException {
		long raw = address.toRawLongValue();
		int hash = (int) (id ^ ((raw >> 32) & 0xFFFFFFFFl));
		int index = (int) (id ^ ((raw >> 0) & 0xFFFFFFFFl));

		if (index < 0 || index >= references.size())
			throw new IllegalArgumentException("Invalid memory address [ix=%d mx=%d]"
					.formatted(index, references.size()));

		Object obj = references.get(index);
		if (obj == null || hash != obj.hashCode())
			throw new IllegalArgumentException("Invalid memory address [real=%08x addr=%08x]"
					.formatted(obj.hashCode(), hash));

		references.set(index, null);

		return (T) obj;
	}

	@SuppressWarnings("unchecked")
	private synchronized T lookup(MemoryAddress address) throws IllegalArgumentException {
		long raw = address.toRawLongValue();
		int hash = (int) (id ^ ((raw >> 32) & 0xFFFFFFFFl));
		int index = (int) (id ^ ((raw >> 0) & 0xFFFFFFFFl));

		if (index < 0 || index >= references.size())
			throw new IllegalArgumentException("Invalid memory address [index=%d size=%d]"
					.formatted(index, references.size()));

		Object obj = references.get(index);
		if (obj == null || hash != obj.hashCode())
			throw new IllegalArgumentException("Invalid memory address [obj.hash=%08x hash=%08x]"
					.formatted(obj.hashCode(), hash));

		return (T) obj;
	}

	public MemoryAddress reference(T obj, MemorySession scope) {
		Objects.requireNonNull(obj, "obj");

		long hash = store(obj);

		MemoryAddress ref = MemoryAddress.ofLong(hash);

		if (scope.isCloseable())
			scope.addCloseAction(() -> remove(ref));

		return ref;
	}

	public T dereference(MemoryAddress objReference) {
		return lookup(objReference);
	}

}
