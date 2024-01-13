/*
 * Copyright 2023-2024 Sly Technologies Inc
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
import java.util.OptionalInt;
import java.util.function.IntSupplier;

import org.jnetpcap.PcapIf;
import org.jnetpcap.internal.NativeABI;

/**
 * The socket address protocol family constants. Each protocol family has a
 * different layout for physical addresses in SockAddr structure and is
 * essential to decoding those addresses correctly.
 */
public enum SockAddrFamily implements IntSupplier {

	/** The unspec. */
	UNSPEC(Posix.AF_UNSPEC, Bsd.AF_UNSPEC),

	/** The local. */
	LOCAL(Posix.AF_LOCAL, Bsd.AF_LOCAL, Sizeof.LOCAL),

	/** The inet. */
	INET(Posix.AF_INET, Bsd.AF_INET, Sizeof.INET),

	/** The ax25. */
	AX25(Posix.AF_AX25, Bsd.UNDEFINED),

	/** The ipx. */
	IPX(Posix.AF_IPX, Bsd.AF_IPX, Sizeof.IPX),

	/** The appletalk. */
	APPLETALK(Posix.AF_APPLETALK, Bsd.AF_APPLETALK),

	/** The netrom. */
	NETROM(Posix.AF_NETROM, Bsd.UNDEFINED),

	/** The bridge. */
	BRIDGE(Posix.AF_BRIDGE, Bsd.UNDEFINED),

	/** The atmpvc. */
	ATMPVC(Posix.AF_ATMPVC, Bsd.AF_NATM),

	/** The x25. */
	X25(Posix.AF_AX25, Bsd.UNDEFINED),

	/** The inet6. */
	INET6(Posix.AF_INET6, Bsd.AF_INET6, Sizeof.INET6),

	/** The rose. */
	ROSE(Posix.AF_ROSE, Bsd.UNDEFINED),

	/** The decnet. */
	DECNET(Posix.AF_DECnet, Bsd.AF_DECnet),

	/** The netbeui. */
	NETBEUI(Posix.AF_NETBEUI, Bsd.UNDEFINED),

	/** The security. */
	SECURITY(Posix.AF_SECURITY, Bsd.UNDEFINED),

	/** The key. */
	KEY(Posix.AF_KEY, Bsd.pseudo_AF_KEY),

	/** The netlink. */
	NETLINK(Posix.AF_NETLINK, Bsd.UNDEFINED),

	/** The packet. */
	PACKET(Posix.AF_PACKET, Bsd.UNDEFINED, Sizeof.PACKET),

	/** The ash. */
	ASH(Posix.AF_ASH, Bsd.UNDEFINED),

	/** The atmsvc. */
	ATMSVC(Posix.AF_ATMSVC, Bsd.AF_NATM),

	/** The rds. */
	RDS(Posix.AF_RDS, Bsd.UNDEFINED),

	/** The sna. */
	SNA(Posix.AF_SNA, Bsd.AF_SNA),

	/** The irda. */
	IRDA(Posix.AF_IRDA, Bsd.UNDEFINED),

	/** The pppox. */
	PPPOX(Posix.AF_PPPOX, Bsd.UNDEFINED),

	/** The wanpipe. */
	WANPIPE(Posix.AF_WANPIPE, Bsd.UNDEFINED),

	/** The llc. */
	LLC(Posix.AF_LLC, Bsd.UNDEFINED),

	/** The mpls. */
	MPLS(Posix.AF_MPLS, Bsd.UNDEFINED),

	/** The can. */
	CAN(Posix.AF_CAN, Bsd.UNDEFINED),

	/** The tipc. */
	TIPC(Posix.AF_TIPC, Bsd.UNDEFINED),

	/** The bluetooth. */
	BLUETOOTH(Posix.AF_BLUETOOTH, Bsd.UNDEFINED),

	/** The rxrpc. */
	RXRPC(Posix.AF_RXRPC, Bsd.UNDEFINED),

	/** The isdn. */
	ISDN(Posix.AF_ISDN, Bsd.AF_ISDN),

	/** The phonet. */
	PHONET(Posix.AF_PHONET, Bsd.UNDEFINED),

	/** The ieee802154. */
	IEEE802154(Posix.AF_IEEE802154, Bsd.UNDEFINED),

	/** The caif. */
	CAIF(Posix.AF_CAIF, Bsd.UNDEFINED),

	/** The alg. */
	ALG(Posix.AF_ALG, Bsd.UNDEFINED),

	/** The nfc. */
	NFC(Posix.AF_NFC, Bsd.UNDEFINED),

	/** The vsock. */
	VSOCK(Posix.AF_VSOCK, Bsd.UNDEFINED),

	/** The kcm. */
	KCM(Posix.AF_KCM, Bsd.UNDEFINED),

	/** The qipcrtr. */
	QIPCRTR(Posix.AF_QIPCRTR, Bsd.UNDEFINED),

	/** The smc. */
	SMC(Posix.AF_SMC, Bsd.UNDEFINED),

	/** Arpanet imp addresses. */
	IMPLINK(Posix.UNDEFINED, Bsd.AF_IMPLINK),

	/** PUP protocols: e.g. BSP. */
	PUP(Posix.UNDEFINED, Bsd.AF_PUP),

	/** MIT CHAOS protocols. */
	CHAOS(Posix.UNDEFINED, Bsd.AF_CHAOS),

	/** XEROX NS protocols. */
	NS(Posix.UNDEFINED, Bsd.AF_NS),

	/** ISO protocols. */
	ISO(Posix.UNDEFINED, Bsd.AF_ISO),

	/** ISO protocols. */
	OSI(Posix.UNDEFINED, Bsd.AF_OSI),

	/** European computer manufacturers. */
	ECMA(Posix.UNDEFINED, Bsd.AF_ECMA),

	/** Datakit protocols. */
	DATAKIT(Posix.UNDEFINED, Bsd.AF_DATAKIT),

	/** CCITT protocols, X.25 etc. */
	CCITT(Posix.UNDEFINED, Bsd.AF_CCITT),

	/** DECnet. */
	DECnet(Posix.UNDEFINED, Bsd.AF_DECnet),

	/** DEC Direct data link interface. */
	DLI(Posix.UNDEFINED, Bsd.AF_DLI),

	/** LAT. */
	LAT(Posix.UNDEFINED, Bsd.AF_LAT),

	/** NSC Hyperchannel. */
	HYLINK(Posix.UNDEFINED, Bsd.AF_HYLINK),

	/** Internal Routing Protocol. */
	ROUTE(Posix.UNDEFINED, Bsd.AF_ROUTE),

	/** Link layer interface. */
	LINK(Posix.UNDEFINED, Bsd.AF_LINK),

	/** eXpress Transfer Protocol (no AF). */
	PSEUDO_XTP(Posix.UNDEFINED, Bsd.pseudo_AF_XTP),

	/** connection-oriented IP, aka ST II. */
	COIP(Posix.UNDEFINED, Bsd.AF_COIP),

	/** Computer Network Technology. */
	CNT(Posix.UNDEFINED, Bsd.AF_CNT),

	/** Help Identify RTIP packets. */
	PSEUDO_RTIP(Posix.UNDEFINED, Bsd.pseudo_AF_RTIP),

	/** Simple Internet Protocol. */
	SIP(Posix.UNDEFINED, Bsd.AF_SIP),

	/** Help Identify PIP packets. */
	PSEUDO_PIP(Posix.UNDEFINED, Bsd.pseudo_AF_PIP),

	/** Identify packets for Blue Box. */
	PSEUDO_BLUE(Posix.UNDEFINED, Bsd.pseudo_AF_BLUE),

	/** Network Driver 'raw' access. */
	NDRV(Posix.UNDEFINED, Bsd.AF_NDRV),

	/** Integrated Services Digital Network. */
	E164(Posix.UNDEFINED, Bsd.AF_E164),

	/** Internal key-management function. */
	PSEUDO_KEY(Posix.UNDEFINED, Bsd.pseudo_AF_KEY),

	/** Native ATM access. */
	NATM(Posix.UNDEFINED, Bsd.AF_NATM),

	/** Kernel event messages. */
	SYSTEM(Posix.UNDEFINED, Bsd.AF_SYSTEM),

	;

	/**
	 * Sizeof/total_length/sa_len of native structures.
	 */
	private final class Sizeof {

		/** Sizeof AF INET sockaddr. */
		public static final int INET = 16;

		/** Sizeof AF INET6 sockaddr. */
		public static final int INET6 = 28;

		/** Sizeof AF LOCAL sockaddr. */
		public static final int LOCAL = 110;

		/** Sizeof AF IPX sockaddr. */
		public static final int IPX = 12;

		/** Sizeof AF PACKET sockaddr. */
		public static final int PACKET = 20;
	}

	/**
	 * MacOS socket.h AF constants.
	 */
	private final class Bsd {

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
	 * POSIX socket.h AF constants.
	 */
	private final class Posix {

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
			if (isBsd && (s.bsdId == family)) {
				return Optional.of(s);

			} else if (!isBsd && (s.posixId == family)) {
				return Optional.of(s);
			}

		}

		return Optional.empty();
	}

	/** The linux AF value. */
	private final int posixId;

	/** The MacOs/BSD AF value. */
	private final int bsdId;

	/**
	 * Optional native sa_len field value available on BSD systems or specified in
	 * manually in this table.
	 */
	private final OptionalInt saLen;

	/**
	 * Instantiates a new sock addr family.
	 *
	 * @param posixFamilyId the AF constant assigned for POSIX style sockets
	 * @param bsdFamilyId   the AF constant assigned for BSD style sockets
	 */
	SockAddrFamily(int posixFamilyId, int bsdFamilyId) {
		this.posixId = posixFamilyId;
		this.bsdId = bsdFamilyId;
		this.saLen = OptionalInt.empty();
	}

	/**
	 * Instantiates a new sock addr family.
	 *
	 * @param posixFamilyId the linux
	 * @param bsdFamilyId   the mac os
	 * @param saLen         the sa len
	 */
	SockAddrFamily(int posixFamilyId, int bsdFamilyId, int saLen) {
		this.posixId = posixFamilyId;
		this.bsdId = bsdFamilyId;
		this.saLen = OptionalInt.of(saLen);
	}

	/**
	 * Check if a PcapIf (pcap device) contains this specific socket AF type.
	 *
	 * @param dev the pcap dev
	 * @return true, if successful
	 */
	public boolean checkIfContains(PcapIf dev) {
		return dev.findAddressOfFamily(this).isPresent();
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
				? bsdId
				: posixId;
	}

	/**
	 * Checks if is match.
	 *
	 * @param family the family
	 * @return true, if is match
	 */
	public boolean isMatch(int family) {
		boolean isBsd = NativeABI.isBsdAbi();

		for (SockAddrFamily s : values()) {
			if (isBsd && (s.bsdId == family)) {
				return true;

			} else if (!isBsd && (s.posixId == family)) {
				return true;
			}

		}

		return false;
	}

	/**
	 * The total length of the socket address structure in bytes. The value is only
	 * returned on certain platforms (BSD style sockets)..
	 *
	 * @return the length of the address structure if available on this particular
	 *         platform
	 */
	public OptionalInt totalLength() {
		return saLen;
	}
}