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
	UNSPEC(OsSpecific.Linux.AF_UNSPEC, OsSpecific.MacOs.AF_UNSPEC),

	/** The local. */
	LOCAL(OsSpecific.Linux.AF_LOCAL, OsSpecific.MacOs.AF_LOCAL),

	/** The inet. */
	INET(OsSpecific.Linux.AF_INET, OsSpecific.MacOs.AF_INET),

	/** The ax25. */
	AX25(OsSpecific.Linux.AF_AX25, null),

	/** The ipx. */
	IPX(OsSpecific.Linux.AF_IPX, OsSpecific.MacOs.AF_IPX),

	/** The appletalk. */
	APPLETALK(OsSpecific.Linux.AF_APPLETALK, OsSpecific.MacOs.AF_APPLETALK),

	/** The netrom. */
	NETROM(OsSpecific.Linux.AF_NETROM, null),

	/** The bridge. */
	BRIDGE(OsSpecific.Linux.AF_BRIDGE, null),

	/** The atmpvc. */
	ATMPVC(OsSpecific.Linux.AF_ATMPVC, OsSpecific.MacOs.AF_NATM),

	/** The x25. */
	X25(OsSpecific.Linux.AF_AX25, null),

	/** The inet6. */
	INET6(OsSpecific.Linux.AF_INET6, OsSpecific.MacOs.AF_INET6),

	/** The rose. */
	ROSE(OsSpecific.Linux.AF_ROSE, null),

	/** The decnet. */
	DECNET(OsSpecific.Linux.AF_DECnet, OsSpecific.MacOs.AF_DECnet),

	/** The netbeui. */
	NETBEUI(OsSpecific.Linux.AF_NETBEUI, null),

	/** The security. */
	SECURITY(OsSpecific.Linux.AF_SECURITY, null),

	/** The key. */
	KEY(OsSpecific.Linux.AF_KEY, OsSpecific.MacOs.pseudo_AF_KEY),

	/** The netlink. */
	NETLINK(OsSpecific.Linux.AF_NETLINK, null),

	/** The packet. */
	PACKET(OsSpecific.Linux.AF_PACKET, null),

	/** The ash. */
	ASH(OsSpecific.Linux.AF_ASH, null),

	/** The atmsvc. */
	ATMSVC(OsSpecific.Linux.AF_ATMSVC, OsSpecific.MacOs.AF_NATM),

	/** The rds. */
	RDS(OsSpecific.Linux.AF_RDS, null),

	/** The sna. */
	SNA(OsSpecific.Linux.AF_SNA, OsSpecific.MacOs.AF_SNA),

	/** The irda. */
	IRDA(OsSpecific.Linux.AF_IRDA, null),

	/** The pppox. */
	PPPOX(OsSpecific.Linux.AF_PPPOX, null),

	/** The wanpipe. */
	WANPIPE(OsSpecific.Linux.AF_WANPIPE, null),

	/** The llc. */
	LLC(OsSpecific.Linux.AF_LLC, null),

	/** The mpls. */
	MPLS(OsSpecific.Linux.AF_MPLS, null),

	/** The can. */
	CAN(OsSpecific.Linux.AF_CAN, null),

	/** The tipc. */
	TIPC(OsSpecific.Linux.AF_TIPC, null),

	/** The bluetooth. */
	BLUETOOTH(OsSpecific.Linux.AF_BLUETOOTH, null),

	/** The rxrpc. */
	RXRPC(OsSpecific.Linux.AF_RXRPC, null),

	/** The isdn. */
	ISDN(OsSpecific.Linux.AF_ISDN, OsSpecific.MacOs.AF_ISDN),

	/** The phonet. */
	PHONET(OsSpecific.Linux.AF_PHONET, null),

	/** The ieee802154. */
	IEEE802154(OsSpecific.Linux.AF_IEEE802154, null),

	/** The caif. */
	CAIF(OsSpecific.Linux.AF_CAIF, null),

	/** The alg. */
	ALG(OsSpecific.Linux.AF_ALG, null),

	/** The nfc. */
	NFC(OsSpecific.Linux.AF_NFC, null),

	/** The vsock. */
	VSOCK(OsSpecific.Linux.AF_VSOCK, null),

	/** The kcm. */
	KCM(OsSpecific.Linux.AF_KCM, null),

	/** The qipcrtr. */
	QIPCRTR(OsSpecific.Linux.AF_QIPCRTR, null),

	/** The smc. */
	SMC(OsSpecific.Linux.AF_SMC, null),

	/** Arpanet imp addresses. */
	IMPLINK(null, OsSpecific.MacOs.AF_IMPLINK),

	/** PUP protocols: e.g. BSP. */
	PUP(null, OsSpecific.MacOs.AF_PUP),

	/** MIT CHAOS protocols. */
	CHAOS(null, OsSpecific.MacOs.AF_CHAOS),

	/** XEROX NS protocols. */
	NS(null, OsSpecific.MacOs.AF_NS),

	/** ISO protocols. */
	ISO(null, OsSpecific.MacOs.AF_ISO),

	/** ISO protocols. */
	OSI(null, OsSpecific.MacOs.AF_OSI),

	/** European computer manufacturers. */
	ECMA(null, OsSpecific.MacOs.AF_ECMA),

	/** Datakit protocols. */
	DATAKIT(null, OsSpecific.MacOs.AF_DATAKIT),

	/** CCITT protocols, X.25 etc. */
	CCITT(null, OsSpecific.MacOs.AF_CCITT),

	/** DECnet. */
	DECnet(null, OsSpecific.MacOs.AF_DECnet),

	/** DEC Direct data link interface. */
	DLI(null, OsSpecific.MacOs.AF_DLI),

	/** LAT. */
	LAT(null, OsSpecific.MacOs.AF_LAT),

	/** NSC Hyperchannel. */
	HYLINK(null, OsSpecific.MacOs.AF_HYLINK),

	/** Internal Routing Protocol. */
	ROUTE(null, OsSpecific.MacOs.AF_ROUTE),

	/** Link layer interface. */
	LINK(null, OsSpecific.MacOs.AF_LINK),

	/** eXpress Transfer Protocol (no AF). */
	PSEUDO_XTP(null, OsSpecific.MacOs.pseudo_AF_XTP),

	/** connection-oriented IP, aka ST II. */
	COIP(null, OsSpecific.MacOs.AF_COIP),

	/** Computer Network Technology. */
	CNT(null, OsSpecific.MacOs.AF_CNT),

	/** Help Identify RTIP packets. */
	PSEUDO_RTIP(null, OsSpecific.MacOs.pseudo_AF_RTIP),

	/** Simple Internet Protocol. */
	SIP(null, OsSpecific.MacOs.AF_SIP),

	/** Help Identify PIP packets. */
	PSEUDO_PIP(null, OsSpecific.MacOs.pseudo_AF_PIP),

	/** Identify packets for Blue Box. */
	PSEUDO_BLUE(null, OsSpecific.MacOs.pseudo_AF_BLUE),

	/** Network Driver 'raw' access. */
	NDRV(null, OsSpecific.MacOs.AF_NDRV),

	/** Integrated Services Digital Network. */
	E164(null, OsSpecific.MacOs.AF_E164),

	/** Internal key-management function. */
	PSEUDO_KEY(null, OsSpecific.MacOs.pseudo_AF_KEY),

	/** native ATM access. */
	NATM(null, OsSpecific.MacOs.AF_NATM),

	/** Kernel event messages. */
	SYSTEM(null, OsSpecific.MacOs.AF_SYSTEM),

	;

	private final OsSpecific.Linux linux;
	private final OsSpecific.MacOs macOs;

	/**
	 * The Class OsSpecific.
	 */
	private interface OsSpecific extends IntSupplier {

		/**
		 * The Enum MacOs.
		 */
		enum MacOs implements OsSpecific {

			/** unspecified. */
			AF_UNSPEC(0),

			/** local to host (pipes, portals). */
			AF_LOCAL(1),

			/** backward compatibility. */
			AF_UNIX(1),
			/** internetwork: UDP, TCP, etc. */
			AF_INET(2),

			/** arpanet imp addresses. */
			AF_IMPLINK(3),
			/** pup protocols: e.g. BSP */
			AF_PUP(4),

			/** mit CHAOS protocols. */
			AF_CHAOS(5),

			/** XEROX NS protocols. */
			AF_NS(6),

			/** ISO protocols. */
			AF_ISO(7),

			/** The af osi. */
			AF_OSI(7),

			/** european computer manufacturers. */
			AF_ECMA(8),

			/** datakit protocols. */
			AF_DATAKIT(9),
			/** CCITT protocols, X.25 etc */
			AF_CCITT(10),

			/** IBM SNA. */
			AF_SNA(11),

			/** DECnet. */
			AF_DECnet(12),

			/** DEC Direct data link interface. */
			AF_DLI(13),

			/** LAT. */
			AF_LAT(14),

			/** NSC Hyperchannel. */
			AF_HYLINK(15),

			/** Apple Talk. */
			AF_APPLETALK(16),

			/** Internal Routing Protocol. */
			AF_ROUTE(17),

			/** Link layer interface. */
			AF_LINK(18),

			/** eXpress Transfer Protocol (no AF). */
			pseudo_AF_XTP(19),

			/** connection-oriented IP, aka ST II. */
			AF_COIP(20),

			/** Computer Network Technology. */
			AF_CNT(21),

			/** Help Identify RTIP packets. */
			pseudo_AF_RTIP(22),

			/** Novell Internet Protocol. */
			AF_IPX(23),

			/** Simple Internet Protocol. */
			AF_SIP(24),

			/** Help Identify PIP packets. */
			pseudo_AF_PIP(25),

			/** Identify packets for Blue Box. */
			pseudo_AF_BLUE(26),

			/** Network Driver 'raw' access. */
			AF_NDRV(27),

			/** Integrated Services Digital Network. */
			AF_ISDN(28),
			/** CCITT E.164 recommendation */
			AF_E164(28),

			/** Internal key-management function. */
			pseudo_AF_KEY(29),

			/** IPv6. */
			AF_INET6(30),

			/** native ATM access. */
			AF_NATM(31),

			/** Kernel event messages. */
			AF_SYSTEM(32),

			/** NetBIOS. */
			AF_NETBIOS(33),

			/** PPP communication protocol. */
			AF_PPP(34),;

			/** The family. */
			private final int family;

			/**
			 * Instantiates a new mac os.
			 *
			 * @param family the family
			 */
			MacOs(int family) {
				this.family = family;
			}

			/**
			 * Gets the as int.
			 *
			 * @return the as int
			 * @see java.util.function.IntSupplier#getAsInt()
			 */
			@Override
			public int getAsInt() {
				return family;
			}
		}

		/**
		 * The Enum Linux.
		 */
		enum Linux implements OsSpecific {

			/** unspecified. */
			AF_UNSPEC(0),

			/** Unix domain sockets. */
			AF_UNIX(1),

			/** POSIX name for AF_UNIX. */
			AF_LOCAL(1),

			/** Internet IP Protocol. */
			AF_INET(2),
			/** Amateur Radio AX.25 */
			AF_AX25(3),

			/** Novell IPX. */
			AF_IPX(4),

			/** AppleTalk DDP. */
			AF_APPLETALK(5),

			/** Amateur Radio NET/ROM. */
			AF_NETROM(6),

			/** Multiprotocol bridge. */
			AF_BRIDGE(7),

			/** ATM PVCs. */
			AF_ATMPVC(8),
			/** Reserved for X.25 project */
			AF_X25(9),

			/** IP version 6. */
			AF_INET6(10),
			/** Amateur Radio X.25 PLP */
			AF_ROSE(11),

			/** Reserved for DECnet project. */
			AF_DECnet(12),
			/** Reserved for 802.2LLC project */
			AF_NETBEUI(13),

			/** Security callback pseudo AF. */
			AF_SECURITY(14),

			/** PF_KEY key management API. */
			AF_KEY(15),

			/** The af netlink. */
			AF_NETLINK(16),
			/** Alias to emulate 4.4BSD */
			AF_ROUTE(16),

			/** Packet family. */
			AF_PACKET(17),

			/** Ash. */
			AF_ASH(18),

			/** Acorn Econet. */
			AF_ECONET(19),

			/** ATM SVCs. */
			AF_ATMSVC(20),

			/** RDS sockets. */
			AF_RDS(21),

			/** Linux SNA Project (nutters!). */
			AF_SNA(22),

			/** IRDA sockets. */
			AF_IRDA(23),

			/** PPPoX sockets. */
			AF_PPPOX(24),

			/** Wanpipe API Sockets. */
			AF_WANPIPE(25),

			/** Linux LLC. */
			AF_LLC(26),

			/** Native InfiniBand address. */
			AF_IB(27),

			/** MPLS. */
			AF_MPLS(28),

			/** Controller Area Network. */
			AF_CAN(29),

			/** TIPC sockets. */
			AF_TIPC(30),

			/** Bluetooth sockets. */
			AF_BLUETOOTH(31),

			/** IUCV sockets. */
			AF_IUCV(32),

			/** RxRPC sockets. */
			AF_RXRPC(33),

			/** mISDN sockets. */
			AF_ISDN(34),

			/** Phonet sockets. */
			AF_PHONET(35),

			/** IEEE802154 sockets. */
			AF_IEEE802154(36),

			/** CAIF sockets. */
			AF_CAIF(37),

			/** Algorithm sockets. */
			AF_ALG(38),

			/** NFC sockets. */
			AF_NFC(39),

			/** vSockets. */
			AF_VSOCK(40),

			/** Kernel Connection Multiplexor. */
			AF_KCM(41),

			/** Qualcomm IPC Router. */
			AF_QIPCRTR(42),

			/** The af smc. */
			AF_SMC(43),

			/** XDP sockets. */
			AF_XDP(44),

			/** The af mctp. */
			AF_MCTP(45)

			;

			/** The family. */
			private final int family;

			/**
			 * Instantiates a new linux.
			 *
			 * @param family the family
			 */
			Linux(int family) {
				this.family = family;
			}

			/**
			 * Gets the as int.
			 *
			 * @return the as int
			 * @see java.util.function.IntSupplier#getAsInt()
			 */
			@Override
			public int getAsInt() {
				return family;
			}
		}
	}

	/**
	 * Instantiates a new sock addr family.
	 *
	 * @param linux the linux
	 * @param macOs the mac os
	 */
	SockAddrFamily(OsSpecific.Linux linux, OsSpecific.MacOs macOs) {
		this.linux = linux;
		this.macOs = macOs;
	}

	/**
	 * Value of.
	 *
	 * @param family the family
	 * @return the sock addr family
	 */
	public static SockAddrFamily valueOf(int family) {
		return mapUsingAbi(family, NativeABI.current())
				.orElse(null);
	}

	/**
	 * Map using abi.
	 *
	 * @param family the family
	 * @param abi    the abi
	 * @return the optional
	 */
	private static Optional<SockAddrFamily> mapUsingAbi(int family, NativeABI abi) {
		boolean isBsd = NativeABI.isBsdAbi();

		for (SockAddrFamily s : values()) {
			if (isBsd && s.macOs != null && s.macOs.family == family) {
				return Optional.of(s);

			} else if (s.linux != null && s.linux.family == family) {
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
		return ordinal();
	}
}