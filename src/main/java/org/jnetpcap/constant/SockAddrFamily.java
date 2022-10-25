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
 * The socket address protocol family constants. Each protocol family has a
 * different layout for physical addresses in SockAddr structure and is
 * essential to decoding those addresses correctly.
 */
public enum SockAddrFamily implements IntSupplier {
	UNSPEC,
	LOCAL,
	INET,
	AX25,
	IPX,
	APPLETALK,
	NETROM,
	BRIDGE,
	ATMPVC,
	X25,
	INET6,
	ROSE,
	DECNET,
	NETBEUI,
	SECURITY,
	KEY,
	NETLINK,
	PACKET,
	ASH,
	CONNET,
	ATMSVC,
	RDS,
	SNA,
	IRDA,
	PPPOX,
	WANPIPE,
	LLC,
	IB,
	MPLS,
	CAN,
	TIPC,
	BLUETOOTH,
	IUCV,
	RXRPC,
	ISDN,
	PHONET,
	IEEE802154,
	CAIF,
	ALG,
	NFC,
	VSOCK,
	KCM,
	QIPCRTR,
	SMC,
	MAX,
	;

	public static SockAddrFamily valueOf(int family) {
		return values()[family];
	}

	/**
	 * @see java.util.function.IntSupplier#getAsInt()
	 */
	@Override
	public int getAsInt() {
		return ordinal();
	}
}