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

/**
 * Pcap API constants. These constants are natively defined in C header file
 * 'pcap.h'.
 * 
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
public final class PcapConstants {

	/** Maximum snaplen size of 64K. */
	public static final int MAX_SNAPLEN = 64 * 1024;

	/**
	 * Value to pass to pcap_compile() as the netmask if you don't know what the
	 * netmask is.
	 */
	public static final int PCAP_NETMASK_UNKNOWN = 0xffffffff;

	/**
	 * Treat all strings supplied as arguments, and return all strings to the
	 * caller, as being in the local character encoding.
	 */
	public static final int PCAP_CHAR_ENC_LOCAL = 0x00000000;

	/**
	 * Treat all strings supplied as arguments, and return all strings to the
	 * caller, as being in UTF-8.
	 */
	public static final int PCAP_CHAR_ENC_UTF_8 = 0x00000001;

	/** use timestamps with microsecond precision, default. */
	public static final int PCAP_TSTAMP_PRECISION_MICRO = 0;

	/** use timestamps with nanosecond precision. */
	public static final int PCAP_TSTAMP_PRECISION_NANO = 1;

	/** loop terminated by pcap_breakloop. */
	public static final int PCAP_ERROR_BREAK = -2;

	/** generic warning full. */
	public static final int PCAP_WARNING = 1;

	/** this device doesn't support promiscuous mode. */
	public static final int PCAP_WARNING_PROMISC_NOTSUP = 2;

	/** the requested time stamp type is not supported. */
	public static final int PCAP_WARNING_TSTAMP_TYPE_NOTSUP = 3;

	/** interface is loopback. */
	public static final int PCAP_IF_LOOPBACK = 0x00000001;

	/** interface is up. */
	public static final int PCAP_IF_UP = 0x00000002;

	/** interface is running. */
	public static final int PCAP_IF_RUNNING = 0x00000004;

	/** interface is wireless (*NOT* necessarily Wi-Fi!). */
	public static final int PCAP_IF_WIRELESS = 0x00000008;

	/** connection status:. */
	public static final int PCAP_IF_CONNECTION_STATUS = 0x00000030;

	/** unknown. */
	public static final int PCAP_IF_CONNECTION_STATUS_UNKNOWN = 0x00000000;

	/** connected. */
	public static final int PCAP_IF_CONNECTION_STATUS_CONNECTED = 0x00000010;

	/** disconnected. */
	public static final int PCAP_IF_CONNECTION_STATUS_DISCONNECTED = 0x00000020;

	/** not applicable. */
	public static final int PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE = 0x00000030;

	/** The Constant PCAP_ERRBUF_SIZE. */
	public static final int PCAP_ERRBUF_SIZE = 256;

	/** The Constant PCAP_BUF_SIZE. */
	public static final int PCAP_BUF_SIZE = 1024;

	/** The Constant PCAP_STAT_SIZE. */
	public static final int PCAP_STAT_SIZE = 256;

	/** pcap_next_ex() returns 1 if the packet was read without problems. */
	public static final int PCAP_NEXT_EX_OK = 1;

	/**
	 * 0 if packets are being read from a live capture and the packet buffer timeout
	 * expired.
	 */
	public static final int PCAP_NEXT_EX_TIMEOUT = 0;

	/**
	 * Instantiates a new pcap constants.
	 */
	private PcapConstants() {
	}
}
