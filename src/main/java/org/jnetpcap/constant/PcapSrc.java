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
package org.jnetpcap.constant;

import java.util.function.IntSupplier;

/**
 * Internal representation of the type of source in use (file, remote/local
 * interface).
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 */
public enum PcapSrc implements IntSupplier {

	/**
	 * Internal representation of the type of source in use (file, remote/local
	 * interface).
	 */
	SRC_FILE,

	/** local network interface. */
	SRC_IFLOCAL,

	/** interface on a remote host, using RPCAP. */
	SRC_IFREMOTE;

	/** local savefile. */
	public static final int PCAP_SRC_FILE = 2;

	/** local network interface. */
	public static final int PCAP_SRC_IFLOCAL = 3;

	/** interface on a remote host, using RPCAP. */
	public static final int PCAP_SRC_IFREMOTE = 4;

	/**
	 * Value of int to PcapSrc constant.
	 *
	 * @param value the value
	 * @return the pcap src
	 */
	public static PcapSrc valueOf(int value) {
		return values()[value];
	}

	/**
	 * Get int value of type.
	 *
	 * @return The type of input source, passed to pcap_open
	 * @see java.util.function.IntSupplier#getAsInt()
	 */
	@Override
	public int getAsInt() {
		return ordinal() + 2;
	}
}
