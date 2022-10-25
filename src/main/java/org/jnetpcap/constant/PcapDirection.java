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
package org.jnetpcap.constant;

import java.util.function.IntSupplier;

/**
 * 
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
public enum PcapDirection implements IntSupplier {

	DIRECTION_INOUT,
	DIRECTION_IN,
	DIRECTION_OUT,

	;

	public static final int PCAP_DIRECTION_INOUT = 0;
	public static final int PCAP_DIRECTION_IN = 1;
	public static final int PCAP_DIRECTION_OUT = 2;

	public static PcapDirection valueOf(int intValue) {
		if (intValue < 0 || intValue >= values().length)
			throw new IllegalArgumentException("" + intValue);

		return values()[intValue];
	}

	/**
	 * @see java.util.function.IntSupplier#getAsInt()
	 */
	@Override
	public int getAsInt() {
		return ordinal();
	}
}
