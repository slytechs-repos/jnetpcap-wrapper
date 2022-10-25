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

import java.util.function.Supplier;

import org.jnetpcap.constant.PcapCode;

/**
 * Checked Pcap errors, warnings and exceptions.
 * 
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
public class PcapException extends Exception {

	private static final long serialVersionUID = -9051453447740494192L;

	public static void throwIfNotOk(int code) throws PcapException {
		PcapCode status = PcapCode.valueOf(code);
		throwIfNotOk(status, status::getMessage);
	}

	public static void throwIfNotOk(int code, Supplier<String> message) throws PcapException {
		throwIfNotOk(PcapCode.valueOf(code), message);
	}

	public static void throwIfNotOk(PcapCode code, Supplier<String> message) throws PcapException {
		if (code.isError()) {
			String msg = message.get();
			throw new PcapException(code.intValue(), msg.isBlank() ? code.getMessage() : msg);
		}
	}

	private final int pcapErrorCode;

	public PcapException(int pcapErrorCode) {
		this(PcapCode.valueOf(pcapErrorCode));
	}

	public PcapException(int pcapErrorCode, String message) {
		super(message);
		this.pcapErrorCode = pcapErrorCode;
	}

	public PcapException(PcapCode pcapErrorCode) {
		this(pcapErrorCode.intValue(), pcapErrorCode.getMessage());
	}

	public PcapException(String message) {
		this(PcapCode.ERROR.intValue(), message);
	}

	public int getCode() {
		return pcapErrorCode;
	}
}
