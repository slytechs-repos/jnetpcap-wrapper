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
package org.jnetpcap;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.VarHandle;
import java.util.Objects;

import org.jnetpcap.internal.ForeignUtils;

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;
import static java.lang.foreign.ValueLayout.*;

/**
 * A Berkley Packet Filter program. BpFilter is applied to captured packets and
 * only the packets that match the filter program are reported.
 * 
 * <p>
 * Each 64-bit instruction is the long int representation of the following bpf
 * structure found in C header file "pcap/bpf.h":
 * </p>
 * 
 * <pre>
 * struct bpf_insn {
 *		u_short	full;
 *		u_char 	jt;
 *		u_char 	jf;
 *		bpf_u_int32 k;
 * };
 * </pre>
 * 
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
public final class BpFilter implements AutoCloseable {

	/**
	 * <pre>
		struct bpf_program {
		     unsigned int bf_len;
		     struct bpf_insn *bf_insns;
		 };
	 * </pre>
	 */
	private class StructBpfProgram {
		private static final MemoryLayout LAYOUT = structLayout(

				JAVA_INT.withName("bf_len"),
				JAVA_INT, // Padded on 64-bit ABIs
				ADDRESS.withName("bf_insns")

		).withBitAlignment(JAVA_LONG.bitSize());

		private static final VarHandle BF_LEN = LAYOUT.varHandle(groupElement("bf_len"));
		private static final VarHandle BF_INSNS = LAYOUT.varHandle(groupElement("bf_insns"));

		private final MemorySegment mseg;

		StructBpfProgram(Arena arena) {
			mseg = arena.allocate(
					LAYOUT.byteSize(),
					LAYOUT.bitAlignment());
			mseg.fill((byte) 0);
		}

		public MemorySegment address() {
			return mseg;
		}

		public MemorySegment bf_insns() {
			return (MemorySegment) BF_INSNS.get(ValueLayout.ADDRESS);
		}

		public int bf_len() {
			return (int) BF_LEN.get(mseg);
		}

		@SuppressWarnings("unused")
		public long[] toArray() {
			try (var arena = Arena.openShared()) {

				MemorySegment insns_mseg = ForeignUtils.reinterpret(
						bf_insns(),
						bf_len() * JAVA_LONG.byteSize());

				return insns_mseg.toArray(JAVA_LONG);
			}
		}
	}

	private final String filterString;

	private final StructBpfProgram program;
	private final Arena arena;

	/**
	 * Instantiates a new Berkley Packet filter with the given filter string.
	 *
	 * @param filterString the filter string that makes up this BP filter program
	 */
	BpFilter(String filterString) {
		this.filterString = Objects.requireNonNull(filterString, "filterString");
		this.arena = Arena.openShared();
		this.program = new StructBpfProgram(arena);
	}

	MemorySegment address() {
		if (!arena.scope().isAlive())
			throw new IllegalStateException("filter not allocated");

		return program.address();
	}

	/**
	 * Close and deallocate native BPF program.
	 *
	 * @throws IllegalStateException thrown if already closed
	 * @see java.lang.AutoCloseable#close()
	 */
	@Override
	public void close() throws IllegalStateException {
		if (!arena.scope().isAlive())
			throw new IllegalStateException("already closed");

		Pcap0_6.freecode(program.address());

		arena.close();
	}

	/**
	 * number of 64-bit long instructions.
	 *
	 * @return number count of instructions
	 */
	public int length() {
		return program.bf_len();
	}

	@Override
	public String toString() {
		return filterString;
	}

	/**
	 * Deallocates a native BPF program.
	 *
	 * @param bpFilter the bpf
	 * @since libpcap 0.6
	 * @see Pcap#compile(String, boolean, int)
	 * @see <a href=
	 *      "https://man7.org/linux/man-pages/man3/pcap_freecode.3pcap.html">pcap_freecode</a>
	 */
	public static void freeCode(BpFilter bpFilter) {
		bpFilter.close();
	}
}