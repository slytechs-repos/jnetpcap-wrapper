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

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;
import java.util.Objects;

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;
import static java.lang.foreign.ValueLayout.*;

/**
 * Berkeley Packet Filter (BPF) program implementation for packet filtering.
 * This class encapsulates a compiled BPF program that can be applied to network
 * packets to determine if they match specific criteria.
 * 
 * <h2>Native Structure</h2> Each filter instruction is represented as a 64-bit
 * value that maps to the following C structure from pcap/bpf.h:
 * 
 * <pre>{@code
 * struct bpf_insn {
 *     u_short     code;     // Operation code
 *     u_char      jt;       // Jump if true
 *     u_char      jf;       // Jump if false
 *     bpf_u_int32 k;       // Generic field
 * };
 * }</pre>
 * 
 * <h2>Usage Example</h2>
 * 
 * <pre>{@code
 * // Create and compile a filter for TCP packets on port 80
 * try (BpFilter filter = new BpFilter("tcp port 80")) {
 *     Pcap pcap = ...;
 *     pcap.compile(filter, true, 0);
 *     pcap.setFilter(filter);
 * }
 * }</pre>
 * 
 * <h2>Memory Management</h2> The class implements AutoCloseable to ensure
 * proper deallocation of native resources. The filter must be explicitly closed
 * when no longer needed to prevent memory leaks.
 * 
 * @see Pcap#compile(String, boolean, int)
 * @see <a href=
 *      "https://www.tcpdump.org/manpages/pcap-filter.7.html">PCap-Filter man
 *      page</a>
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
public final class BpFilter implements AutoCloseable {

	/**
	 * <pre>
	 * 		struct bpf_program {
	 * 		     unsigned int bf_len;
	 * 		     struct bpf_insn *bf_insns;
	 * 		 };
	 * </pre>
	 *
	 * .
	 */
	private class StructBpfProgram {

		/** The Constant LAYOUT. */
		private static final MemoryLayout LAYOUT = structLayout(

				JAVA_INT.withName("bf_len"),
				JAVA_INT, // Padded on 64-bit ABIs
				ADDRESS.withName("bf_insns")

		).withByteAlignment(JAVA_LONG.byteSize());

		/** The Constant BF_LEN. */
		private static final VarHandle BF_LEN = LAYOUT.varHandle(groupElement("bf_len"));

		/** The Constant BF_INSNS. */
		private static final VarHandle BF_INSNS = LAYOUT.varHandle(groupElement("bf_insns"));

		/** The mseg. */
		private final MemorySegment mseg;

		/**
		 * Instantiates a new struct bpf program.
		 *
		 * @param arena the arena
		 */
		StructBpfProgram(Arena arena) {
			mseg = arena.allocate(
					LAYOUT.byteSize(),
					LAYOUT.byteAlignment());
			mseg.fill((byte) 0);
		}

		/**
		 * Address.
		 *
		 * @return the memory segment
		 */
		public MemorySegment address() {
			return mseg;
		}

		/**
		 * Bf insns.
		 *
		 * @return the memory segment
		 */
		public MemorySegment bf_insns() {
			return (MemorySegment) BF_INSNS.get(this.mseg, 0L);
		}

		/**
		 * Bf len.
		 *
		 * @return the int
		 */
		public int bf_len() {
			return (int) BF_LEN.get(mseg, 0L);
		}

		/**
		 * To array.
		 *
		 * @return the long[]
		 */
		@SuppressWarnings("unused")
		public long[] toArray() {
			try (var arena = Arena.ofShared()) {

				MemorySegment insns_mseg = bf_insns().reinterpret(
						bf_len() * JAVA_LONG.byteSize());

				return insns_mseg.toArray(JAVA_LONG);
			}
		}
	}

	/**
	 * Deallocates a native BPF program. This is a convenience method equivalent to
	 * calling {@link #close()} on the filter.
	 *
	 * @param bpFilter The filter to deallocate
	 * @throws IllegalStateException if the filter has already been closed
	 * @see Pcap#compile(String, boolean, int)
	 * @see <a href=
	 *      "https://man7.org/linux/man-pages/man3/pcap_freecode.3pcap.html">pcap_freecode</a>
	 * @since libpcap 0.6
	 */
	public static void freeCode(BpFilter bpFilter) {
		bpFilter.close();
	}

	/** The filter string. */
	private final String filterString;

	/** The program. */
	private final StructBpfProgram program;

	/** The arena. */
	private final Arena arena;

	/**
	 * Creates a new Berkeley Packet Filter with the specified filter expression.
	 * The filter is not compiled until used with {@link Pcap#compile}.
	 *
	 * @param filterString The filter expression in pcap-filter syntax
	 * @throws NullPointerException if filterString is null
	 */
	BpFilter(String filterString) {
		this.filterString = Objects.requireNonNull(filterString, "filterString");
		this.arena = Arena.ofShared();
		this.program = new StructBpfProgram(arena);
	}

	/**
	 * Returns the native memory address of the BPF program structure. This method
	 * is intended for internal use by the JNetPcap library.
	 *
	 * @return A MemorySegment containing the native bpf_program structure
	 * @throws IllegalStateException if the filter has been closed or not properly
	 *                               allocated
	 */
	MemorySegment address() {
		if (!arena.scope().isAlive())
			throw new IllegalStateException("filter not allocated");

		return program.address();
	}

	/**
	 * Deallocates the native BPF program and associated resources. After calling
	 * this method, the filter can no longer be used.
	 *
	 * @throws IllegalStateException if the filter has already been closed
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
	 * Returns the number of instructions in this BPF program. Each instruction is a
	 * 64-bit value containing operation code and parameters.
	 *
	 * @return The number of BPF instructions in this filter
	 */
	public int length() {
		return program.bf_len();
	}

	/**
	 * Returns the original filter expression string used to create this filter.
	 *
	 * @return The filter expression string
	 */
	@Override
	public String toString() {
		return filterString;
	}
}