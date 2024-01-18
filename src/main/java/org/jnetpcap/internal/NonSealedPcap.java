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
package org.jnetpcap.internal;

import java.lang.foreign.MemorySegment;

import org.jnetpcap.Pcap1_10;

/**
 * The Class NonSealedPcap.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 */
public non-sealed class NonSealedPcap extends Pcap1_10 {

	/**
	 * Instantiates a new non sealed pcap.
	 *
	 * @param pcapHandle the pcap handle
	 * @param name       the name
	 * @param abi        the abi
	 */
	protected NonSealedPcap(MemorySegment pcapHandle, String name, PcapHeaderABI abi) {
		super(pcapHandle, name, abi);
	}

}
