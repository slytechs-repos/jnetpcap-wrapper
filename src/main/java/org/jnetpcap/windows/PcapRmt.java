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
package org.jnetpcap.windows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemoryLayout.PathElement;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;

import org.jnetpcap.constant.PcapSrc;

import static java.lang.foreign.ValueLayout.*;

/**
 * Remote RPCAP authentication and source string marker interface.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public sealed interface PcapRmt permits PcapRmt.Source, PcapRmt.Auth {

	/**
	 * Remote RPCAP source string.
	 *
	 * @param type the type
	 * @param host the host
	 * @param port the port
	 * @param name the name
	 */
	public record Source(int type, String host, String port, String name) implements PcapRmt {

		/**
		 * PcapSrc type as constant..
		 *
		 * @return the pcap src
		 */
		public PcapSrc typeAsPcapSrc() {
			return PcapSrc.valueOf(type);
		}
	}

	/**
	 * Remote RPCAP authentication structure.
	 *
	 * @param type     the type
	 * @param username the username
	 * @param password the password
	 */
	public record Auth(int type, String username, String password) implements PcapRmt {

		/** The layout. */
		private static MemoryLayout LAYOUT = MemoryLayout.structLayout(
				JAVA_INT.withName("type"),
				ADDRESS.withName("username").withByteAlignment(JAVA_INT.byteSize()),
				ADDRESS.withName("password").withByteAlignment(JAVA_INT.byteSize()));

		/** The Constant rmtauth_type. */
		private static final VarHandle rmtauth_type = LAYOUT.varHandle(PathElement.groupElement("type"));

		/** The Constant rmtauth_username. */
		private static final VarHandle rmtauth_username = LAYOUT.varHandle(PathElement.groupElement("username"));

		/** The Constant rmtauth_password. */
		private static final VarHandle rmtauth_password = LAYOUT.varHandle(PathElement.groupElement("password"));

		/**
		 * Instantiates a new RPCAP authentication record using PcapSrc constant.
		 *
		 * @param type     the type
		 * @param username the username
		 * @param password the password
		 */
		public Auth(PcapSrc type, String username, String password) {
			this(type.getAsInt(), username, password);
		}

		/**
		 * Allocate native memory segment and store the record's values in it.
		 *
		 * @param arena the memory arena
		 * @return allocated segment's address
		 */
		MemorySegment allocateNative(Arena arena) {
			MemorySegment mseg = arena.allocate(LAYOUT.byteSize());

			MemorySegment c_username = arena.allocateFrom(username, java.nio.charset.StandardCharsets.UTF_8);
			MemorySegment c_password = arena.allocateFrom(password, java.nio.charset.StandardCharsets.UTF_8);

			rmtauth_type.set(mseg, 0L, type);
			rmtauth_username.set(mseg, 0L, c_username);
			rmtauth_password.set(mseg, 0L, c_password);

			return mseg;
		}

	}
}
