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

import org.jnetpcap.Pcap;

/**
 * Libppcap error and warning status codes.
 * 
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
public enum PcapCode implements IntSupplier {

	OK(PcapCode.PCAP_OK, "Ok"),
	ERROR(PcapCode.PCAP_ERROR),
	ERROR_BREAK(PcapCode.PCAP_ERROR_BREAK),
	ERROR_NOT_ACTIVATED(PcapCode.PCAP_ERROR_NOT_ACTIVATED),
	ERROR_ACTIVATED(PcapCode.PCAP_ERROR_ACTIVATED),
	ERROR_NO_SUCH_DEVICE(PcapCode.PCAP_ERROR_NO_SUCH_DEVICE),
	ERROR_RFMON_NOTSUP(PcapCode.PCAP_ERROR_RFMON_NOTSUP),
	ERROR_NOT_RFMON(PcapCode.PCAP_ERROR_NOT_RFMON),
	ERROR_PERM_DENIED(PcapCode.PCAP_ERROR_PERM_DENIED),
	ERROR_IFACE_NOT_UP(PcapCode.PCAP_ERROR_IFACE_NOT_UP),
	ERROR_CANTSET_TSTAMP_TYPE(PcapCode.PCAP_ERROR_CANTSET_TSTAMP_TYPE),
	ERROR_PROMISC_PERM_DENIED(PcapCode.PCAP_ERROR_PROMISC_PERM_DENIED),
	ERROR_TSTAMP_PRECISION_NOTSUP(PcapCode.PCAP_ERROR_TSTAMP_PRECISION_NOTSUP),

	WARNING(PcapCode.PCAP_WARNING, "generic warning full"),
	WARNING_PROMISC_NOTSUP(PcapCode.PCAP_WARNING_PROMISC_NOTSUP, "this device doesn't support promiscuous mode"),
	WARNING_TSTAMP_TYPE_NOTSUP(PcapCode.PCAP_WARNING_TSTAMP_TYPE_NOTSUP,
			"the requested time stamp type is not supported"),

	;

	/** ok */
	public final static int PCAP_OK = 0;

	/** generic error full */
	public final static int PCAP_ERROR = -1;

	/** loop terminated by pcap_breakloop */
	public final static int PCAP_ERROR_BREAK = -2;

	/** the capture needs to be activated */
	public final static int PCAP_ERROR_NOT_ACTIVATED = -3;

	/** the operation can't be performed on already activated captures */
	public final static int PCAP_ERROR_ACTIVATED = -4;

	/** no such device exists */
	public final static int PCAP_ERROR_NO_SUCH_DEVICE = -5;

	/** this device doesn't support rfmon (monitor) mode */
	public final static int PCAP_ERROR_RFMON_NOTSUP = -6;

	/** operation supported only in monitor mode */
	public final static int PCAP_ERROR_NOT_RFMON = -7;

	/** no permission to open the device */
	public final static int PCAP_ERROR_PERM_DENIED = -8;

	/** interface isn't up */
	public final static int PCAP_ERROR_IFACE_NOT_UP = -9;

	/** this device doesn't support setting the time stamp type */
	public final static int PCAP_ERROR_CANTSET_TSTAMP_TYPE = -10;

	/** you don't have permission to capture in promiscuous mode */
	public final static int PCAP_ERROR_PROMISC_PERM_DENIED = -11;

	/** the requested time stamp precision is not supported */
	public final static int PCAP_ERROR_TSTAMP_PRECISION_NOTSUP = -12;

	/** generic warning full */
	public final static int PCAP_WARNING = 1;

	/** this device doesn't support promiscuous mode */
	public final static int PCAP_WARNING_PROMISC_NOTSUP = 2;

	/** the requested time stamp type is not supported */
	public final static int PCAP_WARNING_TSTAMP_TYPE_NOTSUP = 3;

	public static String toString(int code) {
		if (code < 0)
			return Pcap.statusToStr(valueOf(code));

		return switch (code) {
		case PCAP_OK -> PcapCode.OK.getMessage();
		case PCAP_WARNING -> PcapCode.WARNING.getMessage();
		case PCAP_WARNING_PROMISC_NOTSUP -> PcapCode.WARNING_PROMISC_NOTSUP.getMessage();
		case PCAP_WARNING_TSTAMP_TYPE_NOTSUP -> PcapCode.WARNING_TSTAMP_TYPE_NOTSUP.getMessage();
		default -> "Unknown error: " + code;
		};

	}

	public static String toString(Pcap activePcap) {
		return activePcap.geterr();
	}

	public static PcapCode valueOf(int intValue) {
		PcapCode[] constants = values();
		int len = constants.length;

		for (int i = 0; i < len; i++)
			if (constants[i].code == intValue)
				return constants[i];

		return null;
	}

	private final int code;

	private final String message;

	PcapCode(int code) {
		this.code = code;
		this.message = toString();
	}

	PcapCode(int code, String description) {
		this.code = code;
		this.message = description;
	}

	/**
	 * @see java.util.function.IntSupplier#getAsInt()
	 */
	@Override
	public int getAsInt() {
		return code;
	}

	public String getMessage() {
		return message;
	}

	public static String getMessage(int code) {
		PcapCode pc = PcapCode.valueOf(code);
		return (pc == null) ? "code: " + code : pc.getMessage();
	}

	public int intValue() {
		return code;
	}

	public boolean isError() {
		return (code < 0) && (code != PCAP_ERROR_BREAK); // Break is not really an error
	}

	public boolean isOk() {
		return code == 0;
	}

	public boolean isWarning() {
		return (code > 0);
	}
}
