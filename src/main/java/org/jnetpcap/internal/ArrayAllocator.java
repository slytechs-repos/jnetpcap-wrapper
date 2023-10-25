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
import java.lang.foreign.ValueLayout;
import java.util.function.IntFunction;

/**
 * Arena array block allocator utility. 
 */
public class ArrayAllocator {
	
	/** The Constant DEFAULT_BLOCK_SIZE. */
	public static final int DEFAULT_BLOCK_SIZE = 1024 * 1024;

	/** The block allocator. */
	private final IntFunction<byte[]> blockAllocator;
	
	/** The block size. */
	private int blockSize = DEFAULT_BLOCK_SIZE; // 1MB

	/** The array. */
	private byte[] array;
	
	/** The offset. */
	private int offset;
	
	/** The length. */
	private int length;

	/**
	 * Instantiates a new array allocator.
	 */
	public ArrayAllocator() {
		this(byte[]::new);
	}

	/**
	 * Instantiates a new array allocator.
	 *
	 * @param blockAllocator the block allocator
	 */
	ArrayAllocator(IntFunction<byte[]> blockAllocator) {
		this(blockAllocator, DEFAULT_BLOCK_SIZE);
	}

	/**
	 * Instantiates a new array allocator.
	 *
	 * @param blockAllocator the block allocator
	 * @param blockSize      the block size
	 */
	ArrayAllocator(IntFunction<byte[]> blockAllocator, int blockSize) {
		this.blockAllocator = blockAllocator;
		this.blockSize = blockSize;
	}

	/**
	 * Allocate.
	 *
	 * @param len the len
	 * @return the int
	 */
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

	/**
	 * Array.
	 *
	 * @return the byte[]
	 */
	public byte[] array() {
		return array;
	}

	/**
	 * Copy.
	 *
	 * @param mseg the mseg
	 */
	public void copy(MemorySegment mseg) {
		MemorySegment.copy(mseg, ValueLayout.JAVA_BYTE, 0, array, offset, length);
	}

	/**
	 * Length.
	 *
	 * @return the int
	 */
	public int length() {
		return length;
	}

	/**
	 * Offset.
	 *
	 * @return the int
	 */
	public int offset() {
		return offset;
	}
}