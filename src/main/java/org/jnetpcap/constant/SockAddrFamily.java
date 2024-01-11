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

import java.util.Optional;
import java.util.function.IntSupplier;

import org.jnetpcap.internal.NativeABI;

/**
 * The socket address protocol family constants. Each protocol family has a
 * different layout for physical addresses in SockAddr structure and is
 * essential to decoding those addresses correctly.
 */
public enum SockAddrFamily implements IntSupplier {

	/** The unspec. */
	UNSPEC(Linux.AF_UNSPEC, MacOs.AF_UNSPEC),

	/** The local. */
	LOCAL(Linux.AF_LOCAL, MacOs.AF_LOCAL),

	/** The inet. */
	INET(Linux.AF_INET, MacOs.AF_INET),

	/** The ax25. */
	AX25(Linux.AF_AX25, MacOs.UNDEFINED),

	/** The ipx. */
	IPX(Linux.AF_IPX, MacOs.AF_IPX),

	/** The appletalk. */
	APPLETALK(Linux.AF_APPLETALK, MacOs.AF_APPLETALK),

	/** The netrom. */
	NETROM(Linux.AF_NETROM, MacOs.UNDEFINED),

	/** The bridge. */
	BRIDGE(Linux.AF_BRIDGE, MacOs.UNDEFINED),

	/** The atmpvc. */
	ATMPVC(Linux.AF_ATMPVC, MacOs.AF_NATM),

	/** The x25. */
	X25(Linux.AF_AX25, MacOs.UNDEFINED),

	/** The inet6. */
	INET6(Linux.AF_INET6, MacOs.AF_INET6),

	/** The rose. */
	ROSE(Linux.AF_ROSE, MacOs.UNDEFINED),

	/** The decnet. */
	DECNET(Linux.AF_DECnet, MacOs.AF_DECnet),

	/** The netbeui. */
	NETBEUI(Linux.AF_NETBEUI, MacOs.UNDEFINED),

	/** The security. */
	SECURITY(Linux.AF_SECURITY, MacOs.UNDEFINED),

	/** The key. */
	KEY(Linux.AF_KEY, MacOs.pseudo_AF_KEY),

	/** The netlink. */
	NETLINK(Linux.AF_NETLINK, MacOs.UNDEFINED),

	/** The packet. */
	PACKET(Linux.AF_PACKET, MacOs.UNDEFINED),

	/** The ash. */
	ASH(Linux.AF_ASH, MacOs.UNDEFINED),

	/** The atmsvc. */
	ATMSVC(Linux.AF_ATMSVC, MacOs.AF_NATM),

	/** The rds. */
	RDS(Linux.AF_RDS, MacOs.UNDEFINED),

	/** The sna. */
	SNA(Linux.AF_SNA, MacOs.AF_SNA),

	/** The irda. */
	IRDA(Linux.AF_IRDA, MacOs.UNDEFINED),

	/** The pppox. */
	PPPOX(Linux.AF_PPPOX, MacOs.UNDEFINED),

	/** The wanpipe. */
	WANPIPE(Linux.AF_WANPIPE, MacOs.UNDEFINED),

	/** The llc. */
	LLC(Linux.AF_LLC, MacOs.UNDEFINED),

	/** The mpls. */
	MPLS(Linux.AF_MPLS, MacOs.UNDEFINED),

	/** The can. */
	CAN(Linux.AF_CAN, MacOs.UNDEFINED),

	/** The tipc. */
	TIPC(Linux.AF_TIPC, MacOs.UNDEFINED),

	/** The bluetooth. */
	BLUETOOTH(Linux.AF_BLUETOOTH, MacOs.UNDEFINED),

	/** The rxrpc. */
	RXRPC(Linux.AF_RXRPC, MacOs.UNDEFINED),

	/** The isdn. */
	ISDN(Linux.AF_ISDN, MacOs.AF_ISDN),

	/** The phonet. */
	PHONET(Linux.AF_PHONET, MacOs.UNDEFINED),

	/** The ieee802154. */
	IEEE802154(Linux.AF_IEEE802154, MacOs.UNDEFINED),

	/** The caif. */
	CAIF(Linux.AF_CAIF, MacOs.UNDEFINED),

	/** The alg. */
	ALG(Linux.AF_ALG, MacOs.UNDEFINED),

	/** The nfc. */
	NFC(Linux.AF_NFC, MacOs.UNDEFINED),

	/** The vsock. */
	VSOCK(Linux.AF_VSOCK, MacOs.UNDEFINED),

	/** The kcm. */
	KCM(Linux.AF_KCM, MacOs.UNDEFINED),

	/** The qipcrtr. */
	QIPCRTR(Linux.AF_QIPCRTR, MacOs.UNDEFINED),

	/** The smc. */
	SMC(Linux.AF_SMC, MacOs.UNDEFINED),

	/** Arpanet imp addresses. */
	IMPLINK(Linux.UNDEFINED, MacOs.AF_IMPLINK),

	/** PUP protocols: e.g. BSP. */
	PUP(Linux.UNDEFINED, MacOs.AF_PUP),

	/** MIT CHAOS protocols. */
	CHAOS(Linux.UNDEFINED, MacOs.AF_CHAOS),

	/** XEROX NS protocols. */
	NS(Linux.UNDEFINED, MacOs.AF_NS),

	/** ISO protocols. */
	ISO(Linux.UNDEFINED, MacOs.AF_ISO),

	/** ISO protocols. */
	OSI(Linux.UNDEFINED, MacOs.AF_OSI),

	/** European computer manufacturers. */
	ECMA(Linux.UNDEFINED, MacOs.AF_ECMA),

	/** Datakit protocols. */
	DATAKIT(Linux.UNDEFINED, MacOs.AF_DATAKIT),

	/** CCITT protocols, X.25 etc. */
	CCITT(Linux.UNDEFINED, MacOs.AF_CCITT),

	/** DECnet. */
	DECnet(Linux.UNDEFINED, MacOs.AF_DECnet),

	/** DEC Direct data link interface. */
	DLI(Linux.UNDEFINED, MacOs.AF_DLI),

	/** LAT. */
	LAT(Linux.UNDEFINED, MacOs.AF_LAT),

	/** NSC Hyperchannel. */
	HYLINK(Linux.UNDEFINED, MacOs.AF_HYLINK),

	/** Internal Routing Protocol. */
	ROUTE(Linux.UNDEFINED, MacOs.AF_ROUTE),

	/** Link layer interface. */
	LINK(Linux.UNDEFINED, MacOs.AF_LINK),

	/** eXpress Transfer Protocol (no AF). */
	PSEUDO_XTP(Linux.UNDEFINED, MacOs.pseudo_AF_XTP),

	/** connection-oriented IP, aka ST II. */
	COIP(Linux.UNDEFINED, MacOs.AF_COIP),

	/** Computer Network Technology. */
	CNT(Linux.UNDEFINED, MacOs.AF_CNT),

	/** Help Identify RTIP packets. */
	PSEUDO_RTIP(Linux.UNDEFINED, MacOs.pseudo_AF_RTIP),

	/** Simple Internet Protocol. */
	SIP(Linux.UNDEFINED, MacOs.AF_SIP),

	/** Help Identify PIP packets. */
	PSEUDO_PIP(Linux.UNDEFINED, MacOs.pseudo_AF_PIP),

	/** Identify packets for Blue Box. */
	PSEUDO_BLUE(Linux.UNDEFINED, MacOs.pseudo_AF_BLUE),

	/** Network Driver 'raw' access. */
	NDRV(Linux.UNDEFINED, MacOs.AF_NDRV),

	/** Integrated Services Digital Network. */
	E164(Linux.UNDEFINED, MacOs.AF_E164),

	/** Internal key-management function. */
	PSEUDO_KEY(Linux.UNDEFINED, MacOs.pseudo_AF_KEY),

	/** Native ATM access. */
	NATM(Linux.UNDEFINED, MacOs.AF_NATM),

	/** Kernel event messages. */
	SYSTEM(Linux.UNDEFINED, MacOs.AF_SYSTEM),

	;

	/** The linux AF value. */
	private final int linux;

	/** The MacOs/BSD AF value. */
	private final int macOs;

	/**
	 * MacOS socket.h AF constants.
	 */
	private final class MacOs {

		/** Undefined AF. */
		public static final int UNDEFINED = -1;

		/** unspecified. */
		public static final int AF_UNSPEC = 0;

		/** local to host (pipes, portals). */
		public static final int AF_LOCAL = 1;

		/** backward compatibility. */
		public static final int AF_UNIX = 1;
		/** internetwork: UDP, TCP, etc. */
		public static final int AF_INET = 2;

		/** arpanet imp addresses. */
		public static final int AF_IMPLINK = 3;
		/** pup protocols: e.g. BSP */
		public static final int AF_PUP = 4;

		/** mit CHAOS protocols. */
		public static final int AF_CHAOS = 5;

		/** XEROX NS protocols. */
		public static final int AF_NS = 6;

		/** ISO protocols. */
		public static final int AF_ISO = 7;

		/** The af osi. */
		public static final int AF_OSI = 7;

		/** european computer manufacturers. */
		public static final int AF_ECMA = 8;

		/** datakit protocols. */
		public static final int AF_DATAKIT = 9;
		/** CCITT protocols, X.25 etc */
		public static final int AF_CCITT = 10;

		/** IBM SNA. */
		public static final int AF_SNA = 11;

		/** DECnet. */
		public static final int AF_DECnet = 12;

		/** DEC Direct data link interface. */
		public static final int AF_DLI = 13;

		/** LAT. */
		public static final int AF_LAT = 14;

		/** NSC Hyperchannel. */
		public static final int AF_HYLINK = 15;

		/** Apple Talk. */
		public static final int AF_APPLETALK = 16;

		/** Internal Routing Protocol. */
		public static final int AF_ROUTE = 17;

		/** Link layer interface. */
		public static final int AF_LINK = 18;

		/** eXpress Transfer Protocol (no AF). */
		public static final int pseudo_AF_XTP = 19;

		/** connection-oriented IP, aka ST II. */
		public static final int AF_COIP = 20;

		/** Computer Network Technology. */
		public static final int AF_CNT = 21;

		/** Help Identify RTIP packets. */
		public static final int pseudo_AF_RTIP = 22;

		/** Novell Internet Protocol. */
		public static final int AF_IPX = 23;

		/** Simple Internet Protocol. */
		public static final int AF_SIP = 24;

		/** Help Identify PIP packets. */
		public static final int pseudo_AF_PIP = 25;

		/** Identify packets for Blue Box. */
		public static final int pseudo_AF_BLUE = 26;

		/** Network Driver 'raw' access. */
		public static final int AF_NDRV = 27;

		/** Integrated Services Digital Network. */
		public static final int AF_ISDN = 28;
		/** CCITT E.164 recommendation */
		public static final int AF_E164 = 28;

		/** Internal key-management function. */
		public static final int pseudo_AF_KEY = 29;

		/** IPv6. */
		public static final int AF_INET6 = 30;

		/** native ATM access. */
		public static final int AF_NATM = 31;

		/** Kernel event messages. */
		public static final int AF_SYSTEM = 32;

		/** NetBIOS. */
		public static final int AF_NETBIOS = 33;

		/** PPP communication protocol. */
		public static final int AF_PPP = 34;;
	}

	/**
	 * Linux socket.h AF constants.
	 */
	private final class Linux {

		/** Undefined AF. */
		public static final int UNDEFINED = -1;

		/** unspecified. */
		public static final int AF_UNSPEC = 0;

		/** Unix domain sockets. */
		public static final int AF_UNIX = 1;

		/** POSIX name for AF_UNIX. */
		public static final int AF_LOCAL = 1;

		/** Internet IP Protocol. */
		public static final int AF_INET = 2;
		/** Amateur Radio AX.25 */
		public static final int AF_AX25 = 3;

		/** Novell IPX. */
		public static final int AF_IPX = 4;

		/** AppleTalk DDP. */
		public static final int AF_APPLETALK = 5;

		/** Amateur Radio NET/ROM. */
		public static final int AF_NETROM = 6;

		/** Multiprotocol bridge. */
		public static final int AF_BRIDGE = 7;

		/** ATM PVCs. */
		public static final int AF_ATMPVC = 8;
		/** Reserved for X.25 project */
		public static final int AF_X25 = 9;

		/** IP version 6. */
		public static final int AF_INET6 = 10;
		/** Amateur Radio X.25 PLP */
		public static final int AF_ROSE = 11;

		/** Reserved for DECnet project. */
		public static final int AF_DECnet = 12;
		/** Reserved for 802.2LLC project */
		public static final int AF_NETBEUI = 13;

		/** Security callback pseudo AF. */
		public static final int AF_SECURITY = 14;

		/** PF_KEY key management API. */
		public static final int AF_KEY = 15;

		/** The af netlink. */
		public static final int AF_NETLINK = 16;
		/** Alias to emulate 4.4BSD */
		public static final int AF_ROUTE = 16;

		/** Packet family. */
		public static final int AF_PACKET = 17;

		/** Ash. */
		public static final int AF_ASH = 18;

		/** Acorn Econet. */
		public static final int AF_ECONET = 19;

		/** ATM SVCs. */
		public static final int AF_ATMSVC = 20;

		/** RDS sockets. */
		public static final int AF_RDS = 21;

		/** Linux SNA Project (nutters!). */
		public static final int AF_SNA = 22;

		/** IRDA sockets. */
		public static final int AF_IRDA = 23;

		/** PPPoX sockets. */
		public static final int AF_PPPOX = 24;

		/** Wanpipe API Sockets. */
		public static final int AF_WANPIPE = 25;

		/** Linux LLC. */
		public static final int AF_LLC = 26;

		/** Native InfiniBand address. */
		public static final int AF_IB = 27;

		/** MPLS. */
		public static final int AF_MPLS = 28;

		/** Controller Area Network. */
		public static final int AF_CAN = 29;

		/** TIPC sockets. */
		public static final int AF_TIPC = 30;

		/** Bluetooth sockets. */
		public static final int AF_BLUETOOTH = 31;

		/** IUCV sockets. */
		public static final int AF_IUCV = 32;

		/** RxRPC sockets. */
		public static final int AF_RXRPC = 33;

		/** mISDN sockets. */
		public static final int AF_ISDN = 34;

		/** Phonet sockets. */
		public static final int AF_PHONET = 35;

		/** IEEE802154 sockets. */
		public static final int AF_IEEE802154 = 36;

		/** CAIF sockets. */
		public static final int AF_CAIF = 37;

		/** Algorithm sockets. */
		public static final int AF_ALG = 38;

		/** NFC sockets. */
		public static final int AF_NFC = 39;

		/** vSockets. */
		public static final int AF_VSOCK = 40;

		/** Kernel Connection Multiplexor. */
		public static final int AF_KCM = 41;

		/** Qualcomm IPC Router. */
		public static final int AF_QIPCRTR = 42;

		/** The af smc. */
		public static final int AF_SMC = 43;

		/** XDP sockets. */
		public static final int AF_XDP = 44;

		/** The af mctp. */
		public static final int AF_MCTP = 45;
	}

	/**
	 * Instantiates a new sock addr family.
	 *
	 * @param linux the linux
	 * @param macOs the mac os
	 */
	SockAddrFamily(int linux, int macOs) {
		this.linux = linux;
		this.macOs = macOs;
	}

	/**
	 * Lookup a constant AF using numerical, platform dependent value.
	 *
	 * @param family the AF value
	 * @return optional constant
	 */
	public static Optional<SockAddrFamily> lookup(int family) {
		return mapUsingAbi(family, NativeABI.current());
	}

	/**
	 * Map for platforms specific AF using ABI.
	 *
	 * @param family the family
	 * @param abi    the abi
	 * @return the optional
	 */
	private static Optional<SockAddrFamily> mapUsingAbi(int family, NativeABI abi) {
		boolean isBsd = NativeABI.isBsdAbi();

		for (SockAddrFamily s : values()) {
			if (isBsd && (s.macOs == family)) {
				return Optional.of(s);

			} else if (!isBsd && (s.linux == family)) {
				return Optional.of(s);
			}

		}

		return Optional.empty();
	}

	/**
	 * Gets the as int.
	 *
	 * @return the as int
	 * @see java.util.function.IntSupplier#getAsInt()
	 */
	@Override
	public int getAsInt() {
		boolean isBsd = NativeABI.isBsdAbi();
		return isBsd 
			? macOs 
			: linux;
	}
}