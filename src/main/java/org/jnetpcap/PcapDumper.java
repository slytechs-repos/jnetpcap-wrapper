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

import java.io.Flushable;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import org.jnetpcap.internal.PcapForeignDowncall;
import org.jnetpcap.internal.PcapForeignInitializer;

/**
 * Dump packets to a capture file.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public class PcapDumper implements AutoCloseable, Flushable {

	/**
	 * The Constant pcap_dump_close.
	 *
	 * @see {@code void	pcap_dump_close(pcap_dumper_t *p)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_dump_close;

	/**
	 * The Constant pcap_dump.
	 *
	 * @see {@code void	pcap_dump(u_char *, const struct pcap_pkthdr *, const u_char *)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_dump;

	/**
	 * The Constant pcap_dump_file.
	 *
	 * @see {@code FILE *pcap_dump_file(pcap_dumper_t *p)}
	 * @since libpcap 0.8
	 */
	private static final PcapForeignDowncall pcap_dump_file;

	/**
	 * The Constant pcap_dump_flush.
	 *
	 * @see {@code int pcap_dump_flush(pcap_dumper_t *p)}
	 * @since libpcap 0.8
	 */
	private static final PcapForeignDowncall pcap_dump_flush;

	static {
		try (var foreign = new PcapForeignInitializer(Pcap0_5.class)) {
			
			// @formatter:off
			pcap_dump_close    = foreign.downcall("pcap_dump_close(A)V"); //$NON-NLS-1$
			pcap_dump          = foreign.downcall("pcap_dump(AAA)V"); //$NON-NLS-1$
			pcap_dump_file     = foreign.downcall("pcap_dump_file(A)A");
			pcap_dump_flush    = foreign.downcall("pcap_dump_flush(A)I");
			// @formatter:on
			
		}
	}

	/**
	 * Already closed error.
	 *
	 * @return the illegal state exception
	 */
	private static IllegalStateException alreadyClosedError() {
		return new IllegalStateException("already closed");
	}

	/** The pcap dumper ptr. */
	private final MemorySegment pcap_dumper_ptr;
	
	/** The arena. */
	private final Arena arena;
	
	/** The fname. */
	private final String fname;

	/**
	 * Instantiates a new pcap dumper.
	 *
	 * @param pcap_dumper MemorySegment pointer to pcap_dumper_t structure
	 * @param fname       the fname
	 */
	PcapDumper(MemorySegment pcap_dumper, String fname) {
		this.pcap_dumper_ptr = pcap_dumper;
		this.fname = fname;
		this.arena = Arena.ofShared();
	}

	/**
	 * Address of pcap_dumper_t object.
	 *
	 * @return the memory address
	 */
	MemorySegment address() {
		if (!arena.scope().isAlive())
			throw alreadyClosedError();

		return pcap_dumper_ptr;
	}

	/**
	 * Function pointer to pcap_dump function.
	 *
	 * @return the memory address
	 */
	MemorySegment addressOfDumpFunction() {
		return pcap_dump.address();
	}

	/**
	 * Close a savefile being written to.
	 * <p>
	 * Closes the ``savefile.''
	 * </p>
	 * 
	 * @see java.lang.AutoCloseable#close()
	 * @since libpcap 0.4
	 */
	@Override
	public void close() {
		if (!arena.scope().isAlive())
			throw alreadyClosedError();

		pcap_dump_close.invokeVoid(pcap_dumper_ptr);

		arena.close();
	}

	/**
	 * Write a packet to a capture file.
	 * <p>
	 * pcap_dump() outputs a packet to the ``savefile'' opened with
	 * pcap_dump_open(3PCAP). Note that its calling arguments are suitable for use
	 * with pcap_dispatch(3PCAP) or pcap_loop(3PCAP). If called directly, the user
	 * parameter is of type pcap_dumper_t as returned by pcap_dump_open().
	 * </p>
	 *
	 * @param header the header
	 * @param packet the packet
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @since libpcap 0.4
	 */
	public void dump(MemorySegment header, MemorySegment packet) throws IOException {
		pcap_dump.invokeVoid(header, packet, pcap_dumper_ptr);
	}

	/**
	 * Get the OS standard I/O stream for a savefile being written.
	 *
	 * @return address to OS's stream I/O handle
	 * @see <a href=
	 *      "https://www.tcpdump.org/manpages/pcap_dump_open.3pcap.html">FILE
	 *      *pcap_dump_file(pcap_dumper_t *p)</a>
	 * @since libpcap 0.8
	 */
	public MemorySegment dumpFile() {
		return pcap_dump_file.invokeObj(pcap_dumper_ptr);
	}

	/**
	 * Flush to a savefile packets dumped.
	 * <p>
	 * pcap_dump_flush() flushes the output buffer to the ``savefile,'' so that any
	 * packets written with pcap_dump(3PCAP) but not yet written to the ``savefile''
	 * will be written.
	 * </p>
	 *
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @see java.io.Flushable#flush()
	 * @since libpcap 0.8
	 */
	@Override
	public void flush() throws IOException {
		try {
			int code = pcap_dump_flush.invokeInt(pcap_dumper_ptr);
			PcapException.throwIfNotOk(code);

		} catch (PcapException e) {
			throw new IOException(e);
		}
	}

	/**
	 * Information about this pcap dumper.
	 *
	 * @return the formatted string
	 */
	@Override
	public String toString() {
		return "PcapDumper [fname=" + fname + "]";
	}
}
