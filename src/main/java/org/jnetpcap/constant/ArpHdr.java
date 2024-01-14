/*
 * Copyright 2024 Sly Technologies Inc
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

/**
 * ARP protocol HARDWARE identifiers
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public enum ArpHdr implements IntSupplier {
	/* ARP protocol HARDWARE identifiers. */

	/** From KA9Q: NET/ROM pseudo */
	ARPHDR_NETROM(0, "NETROM"),

	/** Ethernet 10/100Mbps. */
	ARPHDR_ETHER(1, "ETHER"),

	/** Experimental Ethernet. */
	ARPHDR_EETHER(2, "EETHER"),

	/** AX.25 Level 2. */
	ARPHDR_AX25(3, "AX25"),

	/** PROnet token ring. */
	ARPHDR_PRONET(4, "PRONET"),

	/** Chaosnet. */
	ARPHDR_CHAOS(5, "CHAOS"),

	/** IEEE 802.2 Ethernet/TR/TB. */
	ARPHDR_IEEE802(6, "IEEE802"),

	/** ARCnet. */
	ARPHDR_ARCNET(7, "ARCNET"),

	/** APPLEtalk. */
	ARPHDR_APPLETLK(8, "APPLETLK"),

	/** Frame Relay DLCI. */
	ARPHDR_DLCI(15, "DLCI"),

	/** ATM. */
	ARPHDR_ATM(19, "ATM"),

	/** Metricom STRIP (new IANA id). */
	ARPHDR_METRICOM(23, "METRICOM"),

	/** IEEE 1394 IPv4 - RFC 2734. */
	ARPHDR_IEEE1394(24, "IEEE1394"),

	/** EUI-64. */
	ARPHDR_EUI64(27, "EUI64"),

	/** InfiniBand. */
	ARPHDR_INFINIBAND(32, "INFINIBAND"),

	/* Dummy types for non ARP hardware */

	/** SLIP */
	ARPHDR_SLIP(256, "SLIP"),
	/** CSLIP */

	ARPHDR_CSLIP(257, "CSLIP"),

	/** SLIP6 */
	ARPHDR_SLIP6(258, "SLIP6"),

	/** CSLIP6 */
	ARPHDR_CSLIP6(259, "CSLIP6"),

	/** Notional KISS type. */
	ARPHDR_RSRVD(260, "RSRVD"),

	/** COMMENT */
	ARPHDR_ADAPT(264, "ADAPT"),

	/** COMMENT */
	ARPHDR_ROSE(270, "ROSE"),

	/** CCITT X.25. */
	ARPHDR_X25(271, "X25"),

	/** Boards with X.25 in firmware. */
	ARPHDR_HWX25(272, "HWX25"),

	/** Controller Area Network. */
	ARPHDR_CAN(280, "CAN"),

	/** COMMENT */
	ARPHDR_MCTP(290, "MCTP"),

	/** COMMENT */
	ARPHDR_PPP(512, "PPP"),

	/** Cisco HDLC. */
	ARPHDR_CISCO(513, "CISCO"),

	/** */
	ARPHRD_HDLC(513, "CISCO"),

	/** LAPB. */
	ARPHDR_LAPB(516, "LAPB"),

	/** Digital's DDCMP. */
	ARPHDR_DDCMP(517, "DDCMP"),

	/** Raw HDLC. */
	ARPHDR_RAWHDLC(518, "RAWHDLC"),

	/** Raw IP. */
	ARPHDR_RAWIP(519, "RAWIP"),

	/** IPIP tunnel. */
	ARPHDR_TUNNEL(768, "TUNNEL"),

	/** IPIP6 tunnel. */
	ARPHDR_TUNNEL6(769, "TUNNEL6"),

	/** Frame Relay Access Device. */
	ARPHDR_FRAD(770, "FRAD"),

	/** SKIP vif. */
	ARPHDR_SKIP(771, "SKIP"),
	/** Loopback device. */

	ARPHDR_LOOPBACK(772, "LOOPBACK"),

	/** Localtalk device. */
	ARPHDR_LOCALTLK(773, "LOCALTLK"),

	/** Fiber Distributed Data Interface */
	ARPHDR_FDDI(774, "FDDI"),

	/** AP1000 BIF. */
	ARPHDR_BIF(775, "BIF"),

	/** sit0 device - IPv6-in-IPv4. */
	ARPHDR_SIT(776, "SIT"),

	/** IP-in-DDP tunnel. */
	ARPHDR_IPDDP(777, "IPDDP"),

	/** GRE over IP. */
	ARPHDR_IPGRE(778, "IPGRE"),

	/** PIMSM register interface. */
	ARPHDR_PIMREG(779, "PIMREG"),

	/** High Performance Parallel Interface */
	ARPHDR_HIPPI(780, "HIPPI"),

	/** (Nexus Electronics) Ash. */
	ARPHDR_ASH(781, "ASH"),

	/** Acorn Econet. */
	ARPHDR_ECONET(782, "ECONET"),

	/** Linux-IrDA. */
	ARPHDR_IRDA(783, "IRDA"),

	/** Point to point fibrechanel. */
	ARPHDR_FCPP(784, "FCPP"),

	/** Fibrechanel arbitrated loop. */
	ARPHDR_FCAL(785, "FCAL"),

	/** Fibrechanel public loop. */
	ARPHDR_FCPL(786, "FCPL"),

	/** Fibrechanel fabric. */
	ARPHDR_FCFABRIC(787, "FCFABRIC"),

	/** Magic type ident for TR. */
	ARPHDR_IEEE802_TR(800, "IEEE802_TR"),

	/** IEEE 802.11. */
	ARPHDR_IEEE80211(801, "IEEE80211"),

	/** IEEE 802.11 + Prism2 header. */
	ARPHDR_IEEE80211_PRISM(802, "IEEE80211_PRISM"),

	/** IEEE 802.11 + radiotap header. */
	ARPHDR_IEEE80211_RADIOTAP(803, "IEEE80211_RADIOTAP"),

	/** IEEE 802.15.4 header. */
	ARPHDR_IEEE802154(804, "IEEE802154"),

	/** IEEE 802.15.4 PHY header. */
	ARPHDR_IEEE802154_PHY(805, "IEEE802154_PHY"),

	/** Void type, nothing is known */
	ARPHDR_VOID(0xFFFF, "VOID"),

	/** Zero header length */
	ARPHDR_NONE(0xFFFE, "NONN"),

	;

	private final int id;
	private final String label;

	/**
	 * Instantiates a new arp hdr identifier.
	 *
	 * @param id    the id
	 * @param label the label
	 */
	ArpHdr(int id, String label) {
		this.id = id;
		this.label = label;

	}

	/**
	 * Converts the supplied id to an ArpHdr enum constant.
	 *
	 * @param id the id to search for
	 * @return the constant, if found
	 */
	public static Optional<ArpHdr> toEnum(int id) {
		for (var c : values()) {
			if (c.id == id)
				return Optional.of(c);
		}

		return Optional.empty();
	}

	/**
	 * Searches for a constant matching the supplied id parameter and returns its
	 * label.
	 *
	 * @param id the id to search for
	 * @return the constant's label, if found
	 */
	public static Optional<String> toLabel(int id) {
		return toEnum(id).map(ArpHdr::label);
	}

	/**
	 * @see java.util.function.IntSupplier#getAsInt()
	 */
	@Override
	public int getAsInt() {
		return id;
	}

	/**
	 * Human readable label.
	 *
	 * @return the label
	 */
	public String label() {
		return label;
	}
}
