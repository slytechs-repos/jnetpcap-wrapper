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
import java.lang.foreign.ValueLayout;
import java.util.function.IntFunction;

/**
 * Arena array block allocator utility. 
 */
public class ArrayAllocator {
	public static final int DEFAULT_BLOCK_SIZE = 1024 * 1024;

	private final IntFunction<byte[]> blockAllocator;
	private int blockSize = DEFAULT_BLOCK_SIZE; // 1MB

	private byte[] array;
	private int offset;
	private int length;

	public ArrayAllocator() {
		this(byte[]::new);
	}

	ArrayAllocator(IntFunction<byte[]> blockAllocator) {
		this(blockAllocator, DEFAULT_BLOCK_SIZE);
	}

	ArrayAllocator(IntFunction<byte[]> blockAllocator, int blockSize) {
		this.blockAllocator = blockAllocator;
		this.blockSize = blockSize;
	}

	public int allocate(int len) {
		offset += len; // advance

		if (array == null || offset + len >= array.length) {
			offset = 0;
			array = blockAllocator.apply(len > blockSize ? len : blockSize);
			assert array.length >= len;
		}

		int allocatedOffset = offset;

		offset += len;
		length = len;

		return allocatedOffset;
	}

	public byte[] array() {
		return array;
	}

	public void copy(MemorySegment mseg) {
		MemorySegment.copy(mseg, ValueLayout.JAVA_BYTE, 0, array, offset, length);
	}

	public int length() {
		return length;
	}

	public int offset() {
		return offset;
	}
}