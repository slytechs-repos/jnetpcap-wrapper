/*
 * Copyright 2024 Sly Technologies Inc
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
package org.jnetpcap;

import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;
import static java.lang.foreign.ValueLayout.*;

/**
 * Represents a BPF (Berkeley Packet Filter) program instruction. Instructions
 * are processed in binary mode, but for text formatting purposes or program
 * analysis, this class decodes each instruction.
 *
 * <p>
 * Each 64-bit instruction is the long int representation of the following BPF
 * structure found in the C header file "pcap/bpf.h":
 * </p>
 * 
 * <pre>
 * struct bpf_insn {
 *     u_short code;
 *     u_char jt;
 *     u_char jf;
 *     bpf_u_int32 k;
 * };
 * </pre>
 */
record BpFilterInstruction(int code, int jt, int jf, long k) {

	/** The Constant LAYOUT defining the memory layout of the BPF instruction. */
	private static final MemoryLayout LAYOUT = MemoryLayout.sequenceLayout(-1,
			structLayout(
					JAVA_SHORT.withName("code"),
					JAVA_BYTE.withName("jt"),
					JAVA_BYTE.withName("jf"),
					JAVA_INT.withName("k")));

	/** The Constant CODE representing the opcode. */
	private static final VarHandle CODE = LAYOUT.varHandle(sequenceElement(), groupElement("code"));

	/** The Constant JT representing the jump true offset. */
	private static final VarHandle JT = LAYOUT.varHandle(sequenceElement(), groupElement("jt"));

	/** The Constant JF representing the jump false offset. */
	private static final VarHandle JF = LAYOUT.varHandle(sequenceElement(), groupElement("jf"));

	/** The Constant K representing the generic field k. */
	private static final VarHandle K = LAYOUT.varHandle(sequenceElement(), groupElement("k"));

	/**
	 * Returns the BpFilterInstruction at a given index within the provided memory
	 * segment.
	 *
	 * @param seg   the memory segment containing the BPF instructions
	 * @param index the index of the instruction within the segment
	 * @return the BpFilterInstruction at the specified index
	 */
	static BpFilterInstruction instructionAt(MemorySegment seg, int index) {
		return new BpFilterInstruction(
				Short.toUnsignedInt((short) CODE.get(seg, 0L, index)),
				Byte.toUnsignedInt((byte) JT.get(seg, 0L, index)),
				Byte.toUnsignedInt((byte) JF.get(seg, 0L, index)),
				Integer.toUnsignedLong((int) K.get(seg, 0L, index)));
	}

	/**
	 * Returns a string representation of the BpFilterInstruction.
	 *
	 * @return the string representation of the BpFilterInstruction
	 */
	@Override
	public String toString() {
		return "BpFilterInstruction"
				+ " [opcode=%04x".formatted(code)
				+ ", jt=" + jt
				+ ", jf=" + jf
				+ ", k=" + k
				+ "]";
	}
}
