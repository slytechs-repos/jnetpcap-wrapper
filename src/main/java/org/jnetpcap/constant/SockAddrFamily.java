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
	
	/** The unspec. */
	UNSPEC,
	
	/** The local. */
	LOCAL,
	
	/** The inet. */
	INET,
	
	/** The ax25. */
	AX25,
	
	/** The ipx. */
	IPX,
	
	/** The appletalk. */
	APPLETALK,
	
	/** The netrom. */
	NETROM,
	
	/** The bridge. */
	BRIDGE,
	
	/** The atmpvc. */
	ATMPVC,
	
	/** The x25. */
	X25,
	
	/** The inet6. */
	INET6,
	
	/** The rose. */
	ROSE,
	
	/** The decnet. */
	DECNET,
	
	/** The netbeui. */
	NETBEUI,
	
	/** The security. */
	SECURITY,
	
	/** The key. */
	KEY,
	
	/** The netlink. */
	NETLINK,
	
	/** The packet. */
	PACKET,
	
	/** The ash. */
	ASH,
	
	/** The connet. */
	CONNET,
	
	/** The atmsvc. */
	ATMSVC,
	
	/** The rds. */
	RDS,
	
	/** The sna. */
	SNA,
	
	/** The irda. */
	IRDA,
	
	/** The pppox. */
	PPPOX,
	
	/** The wanpipe. */
	WANPIPE,
	
	/** The llc. */
	LLC,
	
	/** The ib. */
	IB,
	
	/** The mpls. */
	MPLS,
	
	/** The can. */
	CAN,
	
	/** The tipc. */
	TIPC,
	
	/** The bluetooth. */
	BLUETOOTH,
	
	/** The iucv. */
	IUCV,
	
	/** The rxrpc. */
	RXRPC,
	
	/** The isdn. */
	ISDN,
	
	/** The phonet. */
	PHONET,
	
	/** The ieee802154. */
	IEEE802154,
	
	/** The caif. */
	CAIF,
	
	/** The alg. */
	ALG,
	
	/** The nfc. */
	NFC,
	
	/** The vsock. */
	VSOCK,
	
	/** The kcm. */
	KCM,
	
	/** The qipcrtr. */
	QIPCRTR,
	
	/** The smc. */
	SMC,
	
	/** The max. */
	MAX,
	;

	/**
	 * Value of.
	 *
	 * @param family the family
	 * @return the sock addr family
	 */
	public static SockAddrFamily valueOf(int family) {
		return values()[family];
	}

	/**
	 * Gets the as int.
	 *
	 * @return the as int
	 * @see java.util.function.IntSupplier#getAsInt()
	 */
	@Override
	public int getAsInt() {
		return ordinal();
	}
}