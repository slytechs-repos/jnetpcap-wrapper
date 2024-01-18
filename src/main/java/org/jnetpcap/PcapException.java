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

import java.util.function.Supplier;

import org.jnetpcap.constant.PcapCode;

/**
 * Checked Pcap errors, warnings and exceptions.
 * 
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
public class PcapException extends Exception {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = -9051453447740494192L;

	/**
	 * Throw if not ok.
	 *
	 * @param code the code
	 * @throws PcapException the pcap exception
	 */
	public static void throwIfNotOk(int code) throws PcapException {
		PcapCode status = PcapCode.valueOf(code);
		throwIfNotOk(status, status::getMessage);
	}

	/**
	 * Throw if not ok.
	 *
	 * @param code    the code
	 * @param message the message
	 * @throws PcapException the pcap exception
	 */
	public static void throwIfNotOk(int code, Supplier<String> message) throws PcapException {
		throwIfNotOk(PcapCode.valueOf(code), message);
	}

	/**
	 * Throw if not ok.
	 *
	 * @param code    the code
	 * @param message the message
	 * @throws PcapException the pcap exception
	 */
	public static void throwIfNotOk(PcapCode code, Supplier<String> message) throws PcapException {
		if (code.isError()) {
			String msg = message.get();
			throw new PcapException(code.getAsInt(), msg.isBlank() ? code.getMessage() : msg);
		}
	}

	/** The pcap error code. */
	private final int pcapErrorCode;

	/**
	 * Instantiates a new pcap exception.
	 *
	 * @param pcapErrorCode the pcap error code
	 */
	public PcapException(int pcapErrorCode) {
		this(PcapCode.valueOf(pcapErrorCode));
	}

	/**
	 * Instantiates a new pcap exception.
	 *
	 * @param pcapErrorCode the pcap error code
	 * @param message       the message
	 */
	public PcapException(int pcapErrorCode, String message) {
		super(message);
		this.pcapErrorCode = pcapErrorCode;
	}

	/**
	 * Instantiates a new pcap exception.
	 *
	 * @param pcapErrorCode the pcap error code
	 */
	public PcapException(PcapCode pcapErrorCode) {
		this(pcapErrorCode.getAsInt(), pcapErrorCode.getMessage());
	}

	/**
	 * Instantiates a new pcap exception.
	 *
	 * @param message the message
	 */
	public PcapException(String message) {
		this(PcapCode.ERROR.getAsInt(), message);
	}

	/**
	 * Gets the code.
	 *
	 * @return the code
	 */
	public int getCode() {
		return pcapErrorCode;
	}
}
