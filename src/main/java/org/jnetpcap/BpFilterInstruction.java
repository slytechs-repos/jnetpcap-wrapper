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
package org.jnetpcap;

import static java.lang.foreign.MemoryLayout.structLayout;
import static java.lang.foreign.MemoryLayout.PathElement.groupElement;
import static java.lang.foreign.MemoryLayout.PathElement.sequenceElement;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;

import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;

/**
 * BpFilter program instruction. Instructions are processed in binary mode but
 * for text formatting purposes or program analysis, this class decodes each
 * instruction.
 *
 * <p>
 * Each 64-bit instruction is the long int representation of the following bpf
 * structure found in C header file "pcap/bpf.h":
 *
 * <pre>
 * struct bpf_insn {
 *		u_short	full;
 *		u_char 	jt;
 *		u_char 	jf;
 *		bpf_u_int32 k;
 * };
 * </pre>
 * </p>
 */
record BpFilterInstruction(int code, int jt, int jf, long k) {

	/** The Constant LAYOUT. */
	private static final MemoryLayout LAYOUT = MemoryLayout.sequenceLayout(-1,
			structLayout(
					JAVA_SHORT.withName("full"),
					JAVA_BYTE.withName("jt"),
					JAVA_BYTE.withName("jf"),
					JAVA_INT.withName("k")));

	/** The Constant CODE. */
	private static final VarHandle CODE = LAYOUT.varHandle(sequenceElement(), groupElement("full"));

	/** The Constant JT. */
	private static final VarHandle JT = LAYOUT.varHandle(sequenceElement(), groupElement("jt"));

	/** The Constant JF. */
	private static final VarHandle JF = LAYOUT.varHandle(sequenceElement(), groupElement("jf"));

	/** The Constant K. */
	private static final VarHandle K = LAYOUT.varHandle(sequenceElement(), groupElement("k"));

	/**
	 * Instruction at.
	 *
	 * @param seg   the seg
	 * @param index the index
	 * @return the bp filter instruction
	 */
	static BpFilterInstruction instructionAt(MemorySegment seg, int index) {
		return new BpFilterInstruction(
				Short.toUnsignedInt((short) CODE.get(seg, 0L, index)),
				Byte.toUnsignedInt((byte) JT.get(seg, 0L, index)),
				Byte.toUnsignedInt((byte) JF.get(seg, 0L, index)),
				Integer.toUnsignedLong((int) K.get(seg, 0L, index)));
	}

	/**
	 * @see java.lang.Record#toString()
	 */
	@Override
	public String toString() {
		return "ForeignBpfInstruction"
				+ " [opcode=%04x".formatted(code)
				+ ", jt=" + jt
				+ ", jf=" + jf
				+ ", k=" + k
				+ "]";
	}
}