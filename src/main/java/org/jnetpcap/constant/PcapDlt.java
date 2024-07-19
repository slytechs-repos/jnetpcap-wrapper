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

import org.jnetpcap.Pcap;
import org.jnetpcap.Pcap0_8;

/**
 * Enumeration of Data Link Type (DLT) constants used by the Pcap library.
 *
 * <p>
 * The most popular constant is {@link #EN10MB} (also available as
 * {@link #EN10MB}) which represents Ethernet-based physical media,
 * including 10, 100, and 1000 megabit Ethernet. This enumeration provides both
 * integer constants and enum constants for various DLT values.
 * </p>
 *
 * <p>
 * Example usages:
 * </p>
 *
 * <h2>Accessing the int DLT value using an enum constant</h2>
 * 
 * <pre>
 * int dlt = pcap.datalink(); // Get DLT value from open Pcap capture
 * if (dlt == PcapDlt.EN10MB.value) {
 * 	// Do something
 * }
 * 
 * // Also can use this more formal approach
 * 
 * if (PcapDlt.EN10MB.equals(dlt)) {
 * 	// Do something
 * }
 * </pre>
 * 
 * <h2>Accessing the int DLT value from integer constants table</h2>
 * 
 * <pre>
 * int dlt = pcap.datalink(); // Get DLT value from open Pcap capture
 * if (dlt == PcapDlt.EN10MB) {
 * 	// Do something
 * }
 * </pre>
 * 
 * <h2>Converting integer DLT value into a constant</h2>
 * 
 * <pre>
 * int dlt = pcap.datalink(); // Get DLT value from open Pcap capture
 * PcapDlt enumConst = PcapDlt.valueOf(dlt);
 * System.out.println("The Data Link Type is " + enumConst + " described as " +
 * 		enumConst.getDescription());
 * </pre>
 * 
 * <h2>Converting string DLT name into a constant</h2>
 * 
 * <pre>
 * PcapDlt enumConst = PcapDlt.valueOf("EN10MB");
 * System.out.println("The Data Link Type value is " + enumConst.value);
 * </pre>
 * 
 */
@SuppressWarnings("all")
public enum PcapDlt implements IntSupplier {

	/** No link-layer encapsulation. */
	NULL(0),

	/**
	 * Ethernet (10Mb) - IEEE 802.3
	 * 
	 * Represents Ethernet, the most common type of local area network (LAN) in use
	 * today.
	 */
	EN10MB(1),

	/**
	 * Experimental Ethernet (3Mb).
	 * 
	 * An older and less common version of Ethernet.
	 */
	EN3MB(2),

	/**
	 * Amateur Radio AX.25 - X.25 Protocols
	 * 
	 * Used in amateur radio networks.
	 */
	AX25(3),

	/**
	 * Proteon ProNET Token Ring.
	 * 
	 * An older token ring network technology.
	 */
	PRONET(4),

	/**
	 * Chaos.
	 * 
	 * An older networking protocol developed at MIT.
	 */
	CHAOS(5),

	/**
	 * IEEE 802 Networks - IEEE 802.5 Token Ring
	 * 
	 * Token ring local area network protocol.
	 */
	IEEE802(6),

	/**
	 * ARCNET - ANSI ARCNET Standard 878.1
	 * 
	 * An early networking technology used primarily in industrial applications.
	 */
	ARCNET(7),

	/**
	 * Serial Line IP (SLIP) - RFC 1055
	 * 
	 * A protocol used to run IP over serial lines such as RS-232.
	 */
	SLIP(8),

	/**
	 * Point-to-Point Protocol (PPP) - RFC 1661
	 * 
	 * A data link protocol commonly used in establishing a direct connection
	 * between two networking nodes.
	 */
	PPP(9),

	/**
	 * Fiber Distributed Data Interface (FDDI) - ANSI X3.139
	 * 
	 * A standard for data transmission in a local area network.
	 */
	FDDI(10),

	/**
	 * ATM_RFC1483 - RFC 1483
	 * 
	 * Multiprotocol Encapsulation over ATM Adaptation Layer 5.
	 */
	ATM_RFC1483(11),

	/**
	 * Raw IP.
	 * 
	 * Represents raw IP packets.
	 */
	RAW(12),

	/** SLIP BSDOS. */
	SLIP_BSDOS(15),

	/** PPP BSDOS. */
	PPP_BSDOS(16),

	/** ATM CLIP. */
	ATM_CLIP(19),

	/** PPP Serial. */
	PPP_SERIAL(50),

	/** PPP over Ethernet. */
	PPP_ETHER(51),

	/** Symantec Firewall. */
	SYMANTEC_FIREWALL(99),

	/** Cisco HDLC. */
	C_HDLC(104),

	/** IEEE 802.11 wireless. */
	IEEE802_11(105),

	/** Frame Relay. */
	FRELAY(107),

	/** Loopback. */
	LOOP(108),

	/** Encapsulated packets. */
	ENC(109),

	/** Linux cooked capture. */
	LINUX_SLL(113),

	/** LocalTalk. */
	LTALK(114),

	/** Econet. */
	ECONET(115),

	/** IPFilter. */
	IPFILTER(116),

	/** Packet Filter Log. */
	PFLOG(117),

	/** Cisco IOS. */
	CISCO_IOS(118),

	/** Prism monitor mode header. */
	PRISM_HEADER(119),

	/** Aironet monitor mode header. */
	AIRONET_HEADER(120),

	/** Packet Filter Synchronization. */
	PFSYNC(121),

	/** IP over Fibre Channel. */
	IP_OVER_FC(122),

	/** Sun ATM. */
	SUNATM(123),

	/** RapidIO. */
	RIO(124),

	/** PCI Express. */
	PCI_EXP(125),

	/** Xilinx Aurora link layer. */
	AURORA(126),

	/** IEEE 802.11 plus radiotap header. */
	IEEE802_11_RADIO(127),

	/** Tazmen Sniffer Protocol. */
	TZSP(128),

	/** ARCNET with Linux headers. */
	ARCNET_LINUX(129),

	/** Juniper MLPPP. */
	JUNIPER_MLPPP(130),

	/** Apple IP-over-IEEE 1394. */
	APPLE_IP_OVER_IEEE1394(138),

	/** Juniper MLFR. */
	JUNIPER_MLFR(131),

	/** Juniper ES. */
	JUNIPER_ES(132),

	/** Juniper GGSN. */
	JUNIPER_GGSN(133),

	/** Juniper MFR. */
	JUNIPER_MFR(134),

	/** Juniper ATM2. */
	JUNIPER_ATM2(135),

	/** Juniper Services. */
	JUNIPER_SERVICES(136),

	/** Juniper ATM1. */
	JUNIPER_ATM1(137),

	/** MTP2 with Pseudo-header. */
	MTP2_WITH_PHDR(139),

	/** MTP2. */
	MTP2(140),

	/** MTP3. */
	MTP3(141),

	/** Signaling Connection Control Part (SCCP). */
	SCCP(142),

	/** DOCSIS - Data Over Cable Service Interface Specification */
	DOCSIS(143),

	/** Linux IrDA. */
	LINUX_IRDA(144),

	/** IBM SP. */
	IBM_SP(145),

	/** IBM SN. */
	IBM_SN(146),

	/** Reserved for user use. */
	USER0(147),

	/** Reserved for user use. */
	USER1(148),

	/** Reserved for user use. */
	USER2(149),

	/** Reserved for user use. */
	USER3(150),

	/** Reserved for user use. */
	USER4(151),

	/** Reserved for user use. */
	USER5(152),

	/** Reserved for user use. */
	USER6(153),

	/** Reserved for user use. */
	USER7(154),

	/** Reserved for user use. */
	USER8(155),

	/** Reserved for user use. */
	USER9(156),

	/** Reserved for user use. */
	USER10(157),

	/** Reserved for user use. */
	USER11(158),

	/** Reserved for user use. */
	USER12(159),

	/** Reserved for user use. */
	USER13(160),

	/** Reserved for user use. */
	USER14(161),

	/** Reserved for user use. */
	USER15(162),

	/** AVS monitor mode header. */
	IEEE802_11_RADIO_AVS(163),

	/** Juniper monitor mode. */
	JUNIPER_MONITOR(164),

	/** BACnet MS/TP. */
	BACNET_MS_TP(165),

	/** PPP for PPPD. */
	PPP_PPPD(166),

	/** Juniper PPPoE. */
	JUNIPER_PPPOE(167),

	/** Juniper PPPoE ATM. */
	JUNIPER_PPPOE_ATM(168),

	/** GPRS LLC. */
	GPRS_LLC(169),

	/** GPF-T. */
	GPF_T(170),

	/** GPF-F. */
	GPF_F(171),

	/** Gcom T1/E1. */
	GCOM_T1E1(172),

	/** Gcom Serial. */
	GCOM_SERIAL(173),

	/** Juniper PIC Peer. */
	JUNIPER_PIC_PEER(174),

	/** ERF Ethernet. */
	ERF_ETH(175),

	/** ERF POS. */
	ERF_POS(176),

	/** Linux LAPD. */
	LINUX_LAPD(177),

	/** Event Tracing for Windows messages. */
	ETW(290),

	/** Hilscher netANALYZER NG. */
	NETANALYZER_NG(291),

	/** ZBOSS NCP. */
	ZBOSS_NCP(292),

	/** USB 2.0 low speed. */
	USB_2_0_LOW_SPEED(293),

	/** USB 2.0 full speed. */
	USB_2_0_FULL_SPEED(294),

	/** USB 2.0 high speed. */
	USB_2_0_HIGH_SPEED(295),

	/** Auerswald Logger Protocol. */
	AUERSWALD_LOG(296),

	/** Z-Wave with TAP meta-data header. */
	ZWAVE_TAP(297),

	/** Silicon Labs debug channel. */
	SILABS_DEBUG_CHANNEL(298),

	/** FIRA UWB controller interface protocol. */
	FIRA_UCI(299),

	/** MDB protocol. */
	MDB(300);

	/** The integer DLT value assigned by libpcap. */
	public final int intDlt;

	/** The description of the DLT. */
	public String description;

	/**
	 * Instantiates a new PcapDlt enum constant.
	 *
	 * @param pcapDlt the integer DLT value assigned by libpcap
	 */
	private PcapDlt(int pcapDlt) {
		this.intDlt = pcapDlt;
	}

	/**
	 * Converts an integer value into a PcapDlt constant.
	 *
	 * @param dlt Pcap DLT integer value to convert
	 * @return the constant assigned to the DLT integer, or null if not found
	 * @throws IllegalArgumentException if the value is not found
	 */
	public static PcapDlt valueOf(int dlt) throws IllegalArgumentException {
		for (PcapDlt value : values()) {
			if (value.intDlt == dlt) {
				return value;
			}
		}
		throw new IllegalArgumentException(Integer.toString(dlt));
	}

	/**
	 * Converts the supplied id to a PcapDlt enum constant.
	 *
	 * @param dlt the pcap DLT integer constant
	 * @return the corresponding enum if found
	 */
	public static Optional<PcapDlt> toEnum(int dlt) {
		for (PcapDlt value : values()) {
			if (value.intDlt == dlt) {
				return Optional.of(value);
			}
		}
		return Optional.empty();
	}

	/**
	 * Compares the supplied value with the constant's assigned DLT value.
	 * 
	 * @param value the value to compare
	 * @return true if the supplied value matches the value of the constant,
	 *         otherwise false
	 */
	public boolean equals(int value) {
		return this.intDlt == value;
	}

	/**
	 * Returns the integer DLT value assigned by libpcap.
	 * 
	 * @return the integer DLT value assigned by libpcap
	 * @see java.util.function.IntSupplier#getAsInt()
	 */
	@Override
	public int getAsInt() {
		return this.intDlt;
	}

	/**
	 * Returns the description of the DLT retrieved by querying the native pcap
	 * library.
	 * 
	 * @return the description of the DLT retrieved by querying the native pcap
	 *         library
	 */
	public String getDescription() {
		if (description == null && Pcap0_8.isSupported()) {
			description = Pcap.datalinkValToDescription(this);
			if (description == null)
				description = name();
		}
		return this.description;
	}
}
