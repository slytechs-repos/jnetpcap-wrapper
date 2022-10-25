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

import java.lang.foreign.MemoryAddress;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemoryLayout.PathElement;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.VarHandle;

import org.jnetpcap.constant.PcapSrc;
import org.jnetpcap.internal.ForeignUtils;

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
		 * @param scope the memory scope
		 * @return allocated segment's address
		 */
		MemoryAddress allocateNative(MemorySession scope) {
			MemorySegment mseg = scope.allocate(LAYOUT.byteSize());

			MemoryAddress c_username = ForeignUtils.toUtf8String(username, scope).address();
			MemoryAddress c_password = ForeignUtils.toUtf8String(password, scope).address();

			rmtauth_type.set(mseg, type);
			rmtauth_username.set(mseg, c_username);
			rmtauth_password.set(mseg, c_password);

			return mseg.address();
		}

	}
}
