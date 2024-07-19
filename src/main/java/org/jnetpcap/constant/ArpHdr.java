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
 * <p>
 * This enum lists the various hardware types defined for the ARP protocol. Each
 * hardware type is identified by a unique integer ID and a human-readable
 * label.
 * </p>
 * 
 * <p>
 * Example usage:
 * </p>
 * 
 * <h2>Converting an integer ID to an ArpHdr enum constant</h2>
 * 
 * <pre>
 * int id = 1;
 * ArpHdr arpHdr = ArpHdr.toEnum(id).orElse(null);
 * System.out.println("ARP Hardware Type: " + (arpHdr != null ? arpHdr.label() : "Unknown"));
 * </pre>
 * 
 * @see java.util.function.IntSupplier
 * 
 *      Author: Sly Technologies Inc repos@slytechs.com
 */
public enum ArpHdr implements IntSupplier {
	/* ARP protocol HARDWARE identifiers. */

	/**
	 * From KA9Q: NET/ROM pseudo
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/NET/ROM">NET/ROM</a>
	 */
	ARPHDR_NETROM(0, "NETROM"),

	/**
	 * Ethernet 10/100Mbps.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/Ethernet">Ethernet</a>
	 */
	ARPHDR_ETHER(1, "ETHER"),

	/**
	 * Experimental Ethernet.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/Ethernet">Ethernet</a>
	 */
	ARPHDR_EETHER(2, "EETHER"),

	/**
	 * AX.25 Level 2.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/AX.25">AX.25</a>
	 */
	ARPHDR_AX25(3, "AX25"),

	/**
	 * PROnet token ring.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/Token_Ring">Token Ring</a>
	 */
	ARPHDR_PRONET(4, "PRONET"),

	/**
	 * Chaosnet.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/Chaosnet">Chaosnet</a>
	 */
	ARPHDR_CHAOS(5, "CHAOS"),

	/**
	 * IEEE 802.2 Ethernet/TR/TB.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/IEEE_802.2">IEEE 802.2</a>
	 */
	ARPHDR_IEEE802(6, "IEEE802"),

	/**
	 * ARCnet.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/ARCNET">ARCNET</a>
	 */
	ARPHDR_ARCNET(7, "ARCNET"),

	/**
	 * APPLEtalk.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/AppleTalk">AppleTalk</a>
	 */
	ARPHDR_APPLETLK(8, "APPLETLK"),

	/**
	 * Frame Relay DLCI.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/Frame_Relay">Frame Relay</a>
	 */
	ARPHDR_DLCI(15, "DLCI"),

	/**
	 * ATM.
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/Asynchronous_Transfer_Mode">Asynchronous
	 *      Transfer Mode (ATM)</a>
	 */
	ARPHDR_ATM(19, "ATM"),

	/**
	 * Metricom STRIP (new IANA id).
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/Metricom">Metricom</a>
	 */
	ARPHDR_METRICOM(23, "METRICOM"),

	/**
	 * IEEE 1394 IPv4 - RFC 2734.
	 * 
	 * @see <a href="https://tools.ietf.org/html/rfc2734">RFC 2734</a>
	 */
	ARPHDR_IEEE1394(24, "IEEE1394"),

	/**
	 * EUI-64.
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/Extended_Unique_Identifier">EUI-64</a>
	 */
	ARPHDR_EUI64(27, "EUI64"),

	/**
	 * InfiniBand.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/InfiniBand">InfiniBand</a>
	 */
	ARPHDR_INFINIBAND(32, "INFINIBAND"),

	/* Dummy types for non ARP hardware */

	/**
	 * SLIP
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/Serial_Line_Internet_Protocol">SLIP</a>
	 */
	ARPHDR_SLIP(256, "SLIP"),

	/**
	 * CSLIP
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/Serial_Line_Internet_Protocol">SLIP</a>
	 */
	ARPHDR_CSLIP(257, "CSLIP"),

	/**
	 * SLIP6
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/Serial_Line_Internet_Protocol">SLIP</a>
	 */
	ARPHDR_SLIP6(258, "SLIP6"),

	/**
	 * CSLIP6
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/Serial_Line_Internet_Protocol">SLIP</a>
	 */
	ARPHDR_CSLIP6(259, "CSLIP6"),

	/**
	 * Notional KISS type.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/KISS_(TNC)">KISS</a>
	 */
	ARPHDR_RSRVD(260, "RSRVD"),

	/**
	 * Adaptive HDLC.
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/High-Level_Data_Link_Control">HDLC</a>
	 */
	ARPHDR_ADAPT(264, "ADAPT"),

	/**
	 * ROSE.
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/RATS_on_Software_Engineering">ROSE</a>
	 */
	ARPHDR_ROSE(270, "ROSE"),

	/**
	 * CCITT X.25.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/X.25">X.25</a>
	 */
	ARPHDR_X25(271, "X25"),

	/**
	 * Boards with X.25 in firmware.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/X.25">X.25</a>
	 */
	ARPHDR_HWX25(272, "HWX25"),

	/**
	 * Controller Area Network.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/CAN_bus">CAN bus</a>
	 */
	ARPHDR_CAN(280, "CAN"),

	/**
	 * Management Component Transport Protocol.
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/Management_Component_Transport_Protocol">MCTP</a>
	 */
	ARPHDR_MCTP(290, "MCTP"),

	/**
	 * Point-to-Point Protocol (PPP).
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/Point-to-Point_Protocol">PPP</a>
	 */
	ARPHDR_PPP(512, "PPP"),

	/**
	 * Cisco HDLC.
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/High-Level_Data_Link_Control">HDLC</a>
	 */
	ARPHDR_CISCO(513, "CISCO"),

	/**
	 * HDLC
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/High-Level_Data_Link_Control">HDLC</a>
	 */
	ARPHRD_HDLC(513, "HDLC"),

	/**
	 * LAPB.
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/Link_Access_Procedure,_Balanced">LAPB</a>
	 */
	ARPHDR_LAPB(516, "LAPB"),

	/**
	 * Digital's DDCMP.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/DDCMP">DDCMP</a>
	 */
	ARPHDR_DDCMP(517, "DDCMP"),

	/**
	 * Raw HDLC.
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/High-Level_Data_Link_Control">HDLC</a>
	 */
	ARPHDR_RAWHDLC(518, "RAWHDLC"),

	/**
	 * Raw IP.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/Internet_Protocol">IP</a>
	 */
	ARPHDR_RAWIP(519, "RAWIP"),

	/**
	 * IPIP tunnel.
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/Generic_Routing_Encapsulation">GRE</a>
	 */
	ARPHDR_TUNNEL(768, "TUNNEL"),

	/**
	 * IPIP6 tunnel.
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/Generic_Routing_Encapsulation">GRE</a>
	 */
	ARPHDR_TUNNEL6(769, "TUNNEL6"),

	/**
	 * Frame Relay Access Device.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/Frame_Relay">Frame Relay</a>
	 */
	ARPHDR_FRAD(770, "FRAD"),

	/**
	 * SKIP vif.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/SKIP_protocol">SKIP</a>
	 */
	ARPHDR_SKIP(771, "SKIP"),

	/**
	 * Loopback device.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/Loopback">Loopback</a>
	 */
	ARPHDR_LOOPBACK(772, "LOOPBACK"),

	/**
	 * Localtalk device.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/LocalTalk">LocalTalk</a>
	 */
	ARPHDR_LOCALTLK(773, "LOCALTLK"),

	/**
	 * Fiber Distributed Data Interface
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/Fiber_Distributed_Data_Interface">FDDI</a>
	 */
	ARPHDR_FDDI(774, "FDDI"),

	/**
	 * AP1000 BIF.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/AP1000">AP1000</a>
	 */
	ARPHDR_BIF(775, "BIF"),

	/**
	 * sit0 device - IPv6-in-IPv4.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/IPv6">IPv6</a>
	 */
	ARPHDR_SIT(776, "SIT"),

	/**
	 * IP-in-DDP tunnel.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/Data_Delivery_Protocol">DDP</a>
	 */
	ARPHDR_IPDDP(777, "IPDDP"),

	/**
	 * GRE over IP.
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/Generic_Routing_Encapsulation">GRE</a>
	 */
	ARPHDR_IPGRE(778, "IPGRE"),

	/**
	 * PIMSM register interface.
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/Protocol_Independent_Multicast">PIM</a>
	 */
	ARPHDR_PIMREG(779, "PIMREG"),

	/**
	 * High Performance Parallel Interface
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/High_Performance_Parallel_Interface">HIPPI</a>
	 */
	ARPHDR_HIPPI(780, "HIPPI"),

	/**
	 * (Nexus Electronics) Ash.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/ASH_protocol">ASH</a>
	 */
	ARPHDR_ASH(781, "ASH"),

	/**
	 * Acorn Econet.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/Econet">Econet</a>
	 */
	ARPHDR_ECONET(782, "ECONET"),

	/**
	 * Linux-IrDA.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/IrDA">IrDA</a>
	 */
	ARPHDR_IRDA(783, "IRDA"),

	/**
	 * Point to point fibrechanel.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/Fibre_Channel">Fibre Channel</a>
	 */
	ARPHDR_FCPP(784, "FCPP"),

	/**
	 * Fibrechanel arbitrated loop.
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/Fibre_Channel_arbitrated_loop">FCAL</a>
	 */
	ARPHDR_FCAL(785, "FCAL"),

	/**
	 * Fibrechanel public loop.
	 * 
	 * @see <a href=
	 *      "https://en.wikipedia.org/wiki/Fibre_Channel_arbitrated_loop">FCPL</a>
	 */
	ARPHDR_FCPL(786, "FCPL"),

	/**
	 * Fibrechanel fabric.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/Fibre_Channel">Fibre Channel</a>
	 */
	ARPHDR_FCFABRIC(787, "FCFABRIC"),

	/**
	 * Magic type ident for TR.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/Token_Ring">Token Ring</a>
	 */
	ARPHDR_IEEE802_TR(800, "IEEE802_TR"),

	/**
	 * IEEE 802.11.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/IEEE_802.11">IEEE 802.11</a>
	 */
	ARPHDR_IEEE80211(801, "IEEE80211"),

	/**
	 * IEEE 802.11 + Prism2 header.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/IEEE_802.11">IEEE 802.11</a>
	 */
	ARPHDR_IEEE80211_PRISM(802, "IEEE80211_PRISM"),

	/**
	 * IEEE 802.11 + radiotap header.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/IEEE_802.11">IEEE 802.11</a>
	 */
	ARPHDR_IEEE80211_RADIOTAP(803, "IEEE80211_RADIOTAP"),

	/**
	 * IEEE 802.15.4 header.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/IEEE_802.15.4">IEEE 802.15.4</a>
	 */
	ARPHDR_IEEE802154(804, "IEEE802154"),

	/**
	 * IEEE 802.15.4 PHY header.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/IEEE_802.15.4">IEEE 802.15.4</a>
	 */
	ARPHDR_IEEE802154_PHY(805, "IEEE802154_PHY"),

	/** Void type, nothing is known */
	ARPHDR_VOID(0xFFFF, "VOID"),

	/** Zero header length */
	ARPHDR_NONE(0xFFFE, "NONE");

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
