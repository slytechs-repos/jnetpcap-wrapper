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
package org.jnetpcap.windows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemoryLayout.PathElement;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.VarHandle;

import org.jnetpcap.constant.PcapSrc;

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
	 * @param type source string type
	 * @param host host part of the source string
	 * @param port port on the the host to connect to
	 * @param name name part of the source string
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
	 * @param type     authentication type
	 * @param username the credential username
	 * @param password crediential password
	 */
	public record Auth(int type, String username, String password) implements PcapRmt {

		private static MemoryLayout LAYOUT = MemoryLayout.structLayout(
				ValueLayout.JAVA_INT.withName("type"),
				ValueLayout.ADDRESS.withName("username").withBitAlignment(32),
				ValueLayout.ADDRESS.withName("password").withBitAlignment(32));

		private static final VarHandle rmtauth_type = LAYOUT.varHandle(PathElement.groupElement("type"));
		private static final VarHandle rmtauth_username = LAYOUT.varHandle(PathElement.groupElement("username"));
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
		 * @param arena the memory scope
		 * @return allocated segment's address
		 */
		MemorySegment allocateNative(Arena arena) {
			MemorySegment mseg = arena.allocate(LAYOUT.byteSize());

			MemorySegment c_username = arena.allocateUtf8String(username);
			MemorySegment c_password = arena.allocateUtf8String(password);

			rmtauth_type.set(mseg, type);
			rmtauth_username.set(mseg, c_username);
			rmtauth_password.set(mseg, c_password);

			return mseg;
		}

	}
}
