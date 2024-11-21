/*
 * Copyright 2023-2024 Sly Technologies Inc
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

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;
import java.util.Objects;

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;
import static java.lang.foreign.ValueLayout.*;

/**
 * A Berkeley Packet Filter (BPF) program. BpFilter is applied to captured
 * packets and only the packets that match the filter program are reported.
 *
 * <p>
 * Each 64-bit instruction is the long int representation of the following BPF
 * structure found in the C header file "pcap/bpf.h":
 * </p>
 *
 * <pre>
 * struct bpf_insn {
 *   u_short  code;
 *   u_char   jt;
 *   u_char   jf;
 *   bpf_u_int32 k;

 * };
 * </pre>
 *
 * @see <a href="https://www.tcpdump.org/manpages/pcap.3pcap.html">pcap(3pcap)
 *      man page</a>
 * @see <a href=
 *      "https://man7.org/linux/man-pages/man7/pcap-filter.7.html">pcap-filter(7)
 *      man page</a>
 * @see <a href=
 *      "https://man7.org/linux/man-pages/man3/pcap_freecode.3pcap.html">pcap_freecode(3pcap)
 *      man page</a>
 * @see <a href=
 *      "https://www.kernel.org/doc/html/latest/networking/filter.html">Linux
 *      Packet Filtering</a>
 * @see Pcap#compile(String, boolean, int)
 * @see Pcap#setFilter(BpFilter)
 * @see java.lang.AutoCloseable
 * @see java.util.Objects
 * 
 * @since libpcap 0.6
 * @since libpcap 0.8 (padded on 64-bit ABIs)
 * @since libpcap 1.0 (64-bit instructions)
 */
public final class BpFilter implements AutoCloseable {

	/**
	 * Structure representing a BPF program.
	 *
	 * <pre>
	 * struct bpf_program {
	 *   unsigned int bf_len;
	 *   struct bpf_insn *bf_insns;
	 * };
	 * </pre>
	 *
	 * The bf_len field contains the number of instructions in the program. The
	 * bf_insns field points to the first instruction of the program.
	 */
	private class StructBpfProgram {

		/** The memory layout of the bpf_program structure. */
		private static final MemoryLayout LAYOUT = structLayout(
				JAVA_INT.withName("bf_len"),
				JAVA_INT, // Padding on 64-bit ABIs
				ADDRESS.withName("bf_insns")).withByteAlignment(JAVA_LONG.byteSize());

		/** VarHandle to access the bf_len field. */
		private static final VarHandle BF_LEN = LAYOUT.varHandle(groupElement("bf_len"));

		/** VarHandle to access the bf_insns field. */
		private static final VarHandle BF_INSNS = LAYOUT.varHandle(groupElement("bf_insns"));

		/** The memory segment representing the bpf_program structure. */
		private final MemorySegment mseg;

		/**
		 * Instantiates a new bpf_program structure.
		 *
		 * @param arena the memory arena for allocation
		 */
		StructBpfProgram(Arena arena) {
			mseg = arena.allocate(LAYOUT.byteSize(), LAYOUT.byteAlignment());
			mseg.fill((byte) 0);
		}

		/**
		 * Returns the memory segment representing the structure.
		 *
		 * @return the memory segment
		 */
		public MemorySegment address() {
			return mseg;
		}

		/**
		 * Returns the memory segment pointing to the instructions.
		 *
		 * @return the memory segment for instructions
		 */
		public MemorySegment bf_insns() {
			return (MemorySegment) BF_INSNS.get(this.mseg);
		}

		/**
		 * Returns the number of instructions in the program.
		 *
		 * @return the number of instructions
		 */
		public int bf_len() {
			return (int) BF_LEN.get(mseg);
		}

		/**
		 * Converts the instructions to an array of longs.
		 *
		 * @return an array of 64-bit instructions
		 */
		@SuppressWarnings("unused")
		public long[] toArray() {
			try (var arena = Arena.ofShared()) {
				MemorySegment insns_mseg = bf_insns().reinterpret(bf_len() * JAVA_LONG.byteSize());
				return insns_mseg.toArray(JAVA_LONG);
			}
		}
	}

	/** The filter string used to compile this BPF program. */
	private final String filterString;

	/** The BPF program structure. */
	private final StructBpfProgram program;

	/** The memory arena for allocation. */
	private final Arena arena;

	/**
	 * Instantiates a new Berkeley Packet Filter with the given filter string.
	 *
	 * @param filterString the filter string that makes up this BPF program
	 * @throws NullPointerException if filterString is null
	 */
	BpFilter(String filterString) {
		this.filterString = Objects.requireNonNull(filterString, "filterString");
		this.arena = Arena.ofShared();
		this.program = new StructBpfProgram(arena);
	}

	/**
	 * Returns the memory segment representing the BPF program.
	 *
	 * @return the memory segment
	 * @throws IllegalStateException if the BPF program is not allocated
	 */
	MemorySegment address() {
		if (!arena.scope().isAlive())
			throw new IllegalStateException("filter not allocated");

		return program.address();
	}

	/**
<<<<<<< HEAD
	 * Closes and deallocates the native BPF program.
=======
	 * Deallocates the native BPF program and associated resources. After calling
	 * this method, the filter can no longer be used.
>>>>>>> refs/remotes/origin/develop
	 *
<<<<<<< HEAD
	 * @throws IllegalStateException if already closed
=======
	 * @throws IllegalStateException if the filter has already been closed
>>>>>>> refs/remotes/origin/develop
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
	 * Returns the number of 64-bit instructions in the BPF program.
	 *
	 * @return the number of instructions
	 */
	public int length() {
		return program.bf_len();
	}

	/**
	 * Returns the filter string used to compile this BPF program.
	 *
	 * @return the filter string

	 */
	@Override
	public String toString() {
		return filterString;
	}

	/**
	 * Deallocates a native BPF program.
	 *
	 * @param bpFilter the BPF program to deallocate
	 * @throws NullPointerException if bpFilter is null
	 * @see Pcap#compile(String, boolean, int)
	 * @see <a href=
	 *      "https://man7.org/linux/man-pages/man3/pcap_freecode.3pcap.html">pcap_freecode</a>
	 */
	public static void freeCode(BpFilter bpFilter) {
		bpFilter.close();
	}
}

