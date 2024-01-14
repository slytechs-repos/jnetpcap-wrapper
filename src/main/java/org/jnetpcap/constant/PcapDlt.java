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

// TODO: Auto-generated Javadoc
/**
 * <p>
 * Constants that represent the Pcap's Payload Link Type assignments. The most
 * popular constant is the {@link #EN10MB} (alternatively {@link #DLT_EN10MB})
 * which represents <em>Ethernet2</em> based physical medium. This includes 10,
 * 100, and 1000 mega-bit ethernets.
 * </p>
 * <p>
 * There are 2 tables within PcapDLT enum structure. First is the full table of
 * enum constants, and then there is a duplicate table containing <code>public
 * final static int</code> of contants, prefixed with <code>DLT_</code>. Also
 * the enum constant's field <code>value</code> is public which means that
 * integer DLT constant can also be access using the field directly.
 * </p>
 * Here are 4 basic of how you can use DLT constants in various ways.
 * 
 * <h2>Accessing the int DLT value using an enum constant</h2>
 * 
 * <pre>
 * int dlt = pcap.datalink(); // Get DLT value from open Pcap capture
 * if (dlt == PcapDLT.EN10MB.value) {
 * 	// Do something
 * }
 * 
 * // Also can use this more formal approach
 * 
 * if (PcapDLT.EN10MB.equals(dlt)) {
 * 	// Do something
 * }
 * </pre>
 * 
 * <h2>Accessing the int DLT value from integer constants table</h2>
 * 
 * <pre>
 * int dlt = pcap.datalink(); // Get DLT value from open Pcap capture
 * if (dlt == PcapDLT.DLT_EN10MB) {
 * 	// Do something
 * }
 * </pre>
 * 
 * <h2>Converting integer DLT value into a constant</h2>
 * 
 * <pre>
 * int dlt = pcap.datalink(); // Get DLT value from open Pcap capture
 * PcapDLT enumConst = PcapDLT.valueOf(dlt);
 * System.out.println("The Payload Link Type is " + enumConst + " described as " +
 * 		enumConst.description);
 * </pre>
 * 
 * <h2>Converting string DLT name into a constant</h2>
 * 
 * <pre>
 * PcapDLT enumConst = PcapDLT.valueOf("EN10MB");
 * System.out.println("The Payload Link Type value is " + enumConst.value);
 * </pre>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("all")
public enum PcapDlt implements IntSupplier {

	/** The NULL. */
	NULL(0),

	/** Ethernet link-type. */
	EN10MB(1),

	/** Lagacy 3MB ethernet link-type. */
	EN3MB(2),

	/** The A x25. */
	AX25(3),

	/** The PRONET. */
	PRONET(4),

	/** The CHAOS. */
	CHAOS(5),

	/** The IEE e802. */
	IEEE802(6),

	/** The ARCNET. */
	ARCNET(7),

	/** The SLIP. */
	SLIP(8),

	/** The PPP. */
	PPP(9),

	/** The FDDI. */
	FDDI(10),

	/** The AT m_ rf c1483. */
	ATM_RFC1483(11),

	/** The RAW. */
	RAW(12),

	/** The SLI p_ bsdos. */
	SLIP_BSDOS(15),

	/** The PP p_ bsdos. */
	PPP_BSDOS(16),

	/** The AT m_ clip. */
	ATM_CLIP(19),

	/** The PP p_ serial. */
	PPP_SERIAL(50),

	/** The PP p_ ether. */
	PPP_ETHER(51),

	/** The SYMANTE c_ firewall. */
	SYMANTEC_FIREWALL(99),

	/** The C_ hdlc. */
	C_HDLC(104),

	/** The IEE e802_11. */
	IEEE802_11(105),

	/** The FRELAY. */
	FRELAY(107),

	/** The LOOP. */
	LOOP(108),

	/** The ENC. */
	ENC(109),

	/** The LINU x_ sll. */
	LINUX_SLL(113),

	/** The LTALK. */
	LTALK(114),

	/** The ECONET. */
	ECONET(115),

	/** The IPFILTER. */
	IPFILTER(116),

	/** The PFLOG. */
	PFLOG(117),

	/** The CISC o_ ios. */
	CISCO_IOS(118),

	/** The PRIS m_ header. */
	PRISM_HEADER(119),

	/** The AIRONE t_ header. */
	AIRONET_HEADER(120),

	/** The PFSYNC. */
	PFSYNC(121),

	/** The I p_ ove r_ fc. */
	IP_OVER_FC(122),

	/** The SUNATM. */
	SUNATM(123),

	/** The RIO. */
	RIO(124),

	/** The PC i_ exp. */
	PCI_EXP(125),

	/** The AURORA. */
	AURORA(126),

	/** The IEE e802_11_ radio. */
	IEEE802_11_RADIO(127),

	/** The TZSP. */
	TZSP(128),

	/** The ARCNE t_ linux. */
	ARCNET_LINUX(129),

	/** The JUNIPE r_ mlppp. */
	JUNIPER_MLPPP(130),

	/** The JUNIPE r_ mlfr. */
	JUNIPER_MLFR(131),

	/** The JUNIPE r_ es. */
	JUNIPER_ES(132),

	/** The JUNIPE r_ ggsn. */
	JUNIPER_GGSN(133),

	/** The JUNIPE r_ mfr. */
	JUNIPER_MFR(134),

	/** The JUNIPE r_ at m2. */
	JUNIPER_ATM2(135),

	/** The JUNIPE r_ services. */
	JUNIPER_SERVICES(136),

	/** The JUNIPE r_ at m1. */
	JUNIPER_ATM1(137),

	/** The APPL e_ i p_ ove r_ iee e1394. */
	APPLE_IP_OVER_IEEE1394(138),

	/** The MT p2_ wit h_ phdr. */
	MTP2_WITH_PHDR(139),

	/** The MT p2. */
	MTP2(140),

	/** The MT p3. */
	MTP3(141),

	/** The SCCP. */
	SCCP(142),

	/** The DOCSIS. */
	DOCSIS(143),

	/** The LINU x_ irda. */
	LINUX_IRDA(144),

	/** The IB m_ sp. */
	IBM_SP(145),

	/** The IB m_ sn. */
	IBM_SN(146),

	/** The USE r0. */
	USER0(147),

	/** The USE r1. */
	USER1(148),

	/** The USE r2. */
	USER2(149),

	/** The USE r3. */
	USER3(150),

	/** The USE r4. */
	USER4(151),

	/** The USE r5. */
	USER5(152),

	/** The USE r6. */
	USER6(153),

	/** The USE r7. */
	USER7(154),

	/** The USE r8. */
	USER8(155),

	/** The USE r9. */
	USER9(156),

	/** The USE r10. */
	USER10(157),

	/** The USE r11. */
	USER11(158),

	/** The USE r12. */
	USER12(159),

	/** The USE r13. */
	USER13(160),

	/** The USE r14. */
	USER14(161),

	/** The USE r15. */
	USER15(162),

	/** The IEE e802_11_ radi o_ avs. */
	IEEE802_11_RADIO_AVS(163),

	/** The JUNIPE r_ monitor. */
	JUNIPER_MONITOR(164),

	/** The BACNE t_ m s_ tp. */
	BACNET_MS_TP(165),

	/** The PP p_ pppd. */
	PPP_PPPD(166),

	/** The JUNIPE r_ pppoe. */
	JUNIPER_PPPOE(167),

	/** The JUNIPE r_ pppo e_ atm. */
	JUNIPER_PPPOE_ATM(168),

	/** The GPR s_ llc. */
	GPRS_LLC(169),

	/** The GP f_ t. */
	GPF_T(170),

	/** The GP f_ f. */
	GPF_F(171),

	/** The GCO m_ t1 e1. */
	GCOM_T1E1(172),

	/** The GCO m_ serial. */
	GCOM_SERIAL(173),

	/** The JUNIPE r_ pi c_ peer. */
	JUNIPER_PIC_PEER(174),

	/** The ER f_ eth. */
	ERF_ETH(175),

	/** The ER f_ pos. */
	ERF_POS(176),

	/** The LINU x_ lapd. */
	LINUX_LAPD(177),

	/** Event Tracing for Windows messages. */
	ETW(290),

	/**
	 * Hilscher Gesellschaft fuer Systemautomation mbH netANALYZER NG hardware and
	 * software.
	 *
	 * The specification for this footer can be found at:
	 * https://kb.hilscher.com/x/brDJBw
	 *
	 * Requested by Jan Adam jadam@hilscher.com
	 */
	NETANALYZER_NG(291),

	/**
	 * Serial NCP (Network Co-Processor) protocol for Zigbee stack ZBOSS by DSR.
	 * ZBOSS NCP protocol description:
	 * https://cloud.dsr-corporation.com/index.php/s/3isHzaNTTgtJebn Header in pcap
	 * file: https://cloud.dsr-corporation.com/index.php/s/fiqSDorAAAZrsYB
	 *
	 * Requested by Eugene Exarevsky eugene.exarevsky@dsr-corporation.com
	 * 
	 */
	ZBOSS_NCP(292),

	/** USB 1.0 packets as transmitted over the cable */
	USB_2_0_LOW_SPEED(293),

	/** USB 1.1 packets as transmitted over the cable */
	USB_2_0_FULL_SPEED(294),

	/** USB 2.0 packets as transmitted over the cable */
	USB_2_0_HIGH_SPEED(295),

	/**
	 * Auerswald Logger Protocol description is provided on
	 * https://github.com/Auerswald-GmbH/auerlog/blob/master/auerlog.txt
	 */
	AUERSWALD_LOG(296),

	/**
	 * Z-Wave packets with a TAP meta-data header
	 * https://gitlab.com/exegin/zwave-g9959-tap requested on tcpdump-workers@
	 */
	ZWAVE_TAP(297),

	/** Silicon Labs debug channel protocol. */
	SILABS_DEBUG_CHANNEL(298),

	/**
	 * Ultra-wideband (UWB) controller interface protocol (UCI). requested by Henri
	 * Chataing henrichataing@google.com
	 */
	FIRA_UCI(299),

	/**
	 * MDB (Multi-Drop Bus) protocol between a vending machine controller and
	 * peripherals inside the vending machine. See
	 *
	 * https://www.kaiser.cx/pcap-mdb.html
	 *
	 * for the specification.
	 *
	 * Requested by Martin Kaiser martin@kaiser.cx
	 */
	MDB(300),

	;

	/** The Constant DLT_NULL. */
	public final static int DLT_NULL = 0;

	/** The Constant DLT_EN10MB. */
	public final static int DLT_EN10MB = 1;

	/** The Constant DLT_EN3MB. */
	public final static int DLT_EN3MB = 2;

	/** The Constant DLT_AX25. */
	public final static int DLT_AX25 = 3;

	/** The Constant DLT_PRONET. */
	public final static int DLT_PRONET = 4;

	/** The Constant DLT_CHAOS. */
	public final static int DLT_CHAOS = 5;

	/** The Constant DLT_IEEE802. */
	public final static int DLT_IEEE802 = 6;

	/** The Constant DLT_ARCNET. */
	public final static int DLT_ARCNET = 7;

	/** The Constant DLT_SLIP. */
	public final static int DLT_SLIP = 8;

	/** The Constant DLT_PPP. */
	public final static int DLT_PPP = 9;

	/** The Constant DLT_FDDI. */
	public final static int DLT_FDDI = 10;

	/** The Constant DLT_ATM_RFC1483. */
	public final static int DLT_ATM_RFC1483 = 11;

	/** The Constant DLT_RAW. */
	public final static int DLT_RAW = 12;

	/** The Constant DLT_SLIP_BSDOS. */
	public final static int DLT_SLIP_BSDOS = 15;

	/** The Constant DLT_PPP_BSDOS. */
	public final static int DLT_PPP_BSDOS = 16;

	/** The Constant DLT_ATM_CLIP. */
	public final static int DLT_ATM_CLIP = 19;

	/** The Constant DLT_PPP_SERIAL. */
	public final static int DLT_PPP_SERIAL = 50;

	/** The Constant DLT_PPP_ETHER. */
	public final static int DLT_PPP_ETHER = 51;

	/** The Constant DLT_SYMANTEC_FIREWALL. */
	public final static int DLT_SYMANTEC_FIREWALL = 99;

	/** The Constant DLT_C_HDLC. */
	public final static int DLT_C_HDLC = 104;

	/** The Constant DLT_IEEE802_11. */
	public final static int DLT_IEEE802_11 = 105;

	/** The Constant DLT_FRELAY. */
	public final static int DLT_FRELAY = 107;

	/** The Constant DLT_LOOP. */
	public final static int DLT_LOOP = 108;

	/** The Constant DLT_ENC. */
	public final static int DLT_ENC = 109;

	/** The Constant DLT_LINUX_SLL. */
	public final static int DLT_LINUX_SLL = 113;

	/** The Constant DLT_LTALK. */
	public final static int DLT_LTALK = 114;

	/** The Constant DLT_ECONET. */
	public final static int DLT_ECONET = 115;

	/** The Constant DLT_IPFILTER. */
	public final static int DLT_IPFILTER = 116;

	/** The Constant DLT_PFLOG. */
	public final static int DLT_PFLOG = 117;

	/** The Constant DLT_CISCO_IOS. */
	public final static int DLT_CISCO_IOS = 118;

	/** The Constant DLT_PRISM_HEADER. */
	public final static int DLT_PRISM_HEADER = 119;

	/** The Constant DLT_AIRONET_HEADER. */
	public final static int DLT_AIRONET_HEADER = 120;

	/** The Constant DLT_PFSYNC. */
	public final static int DLT_PFSYNC = 121;

	/** The Constant DLT_IP_OVER_FC. */
	public final static int DLT_IP_OVER_FC = 122;

	/** The Constant DLT_SUNATM. */
	public final static int DLT_SUNATM = 123;

	/** The Constant DLT_RIO. */
	public final static int DLT_RIO = 124;

	/** The Constant DLT_PCI_EXP. */
	public final static int DLT_PCI_EXP = 125;

	/** The Constant DLT_AURORA. */
	public final static int DLT_AURORA = 126;

	/** The Constant DLT_IEEE802_11_RADIO. */
	public final static int DLT_IEEE802_11_RADIO = 127;

	/** The Constant DLT_TZSP. */
	public final static int DLT_TZSP = 128;

	/** The Constant DLT_ARCNET_LINUX. */
	public final static int DLT_ARCNET_LINUX = 129;

	/** The Constant DLT_JUNIPER_MLPPP. */
	public final static int DLT_JUNIPER_MLPPP = 130;

	/** The Constant DLT_APPLE_IP_OVER_IEEE1394. */
	public final static int DLT_APPLE_IP_OVER_IEEE1394 = 138;

	/** The Constant DLT_JUNIPER_MLFR. */
	public final static int DLT_JUNIPER_MLFR = 131;

	/** The Constant DLT_JUNIPER_ES. */
	public final static int DLT_JUNIPER_ES = 132;

	/** The Constant DLT_JUNIPER_GGSN. */
	public final static int DLT_JUNIPER_GGSN = 133;

	/** The Constant DLT_JUNIPER_MFR. */
	public final static int DLT_JUNIPER_MFR = 134;

	/** The Constant DLT_JUNIPER_ATM2. */
	public final static int DLT_JUNIPER_ATM2 = 135;

	/** The Constant DLT_JUNIPER_SERVICES. */
	public final static int DLT_JUNIPER_SERVICES = 136;

	/** The Constant DLT_JUNIPER_ATM1. */
	public final static int DLT_JUNIPER_ATM1 = 137;

	/** The Constant DLT_MTP2_WITH_PHDR. */
	public final static int DLT_MTP2_WITH_PHDR = 139;

	/** The Constant DLT_MTP2. */
	public final static int DLT_MTP2 = 140;

	/** The Constant DLT_MTP3. */
	public final static int DLT_MTP3 = 141;

	/** The Constant DLT_SCCP. */
	public final static int DLT_SCCP = 142;

	/** The Constant DLT_DOCSIS. */
	public final static int DLT_DOCSIS = 143;

	/** The Constant DLT_LINUX_IRDA. */
	public final static int DLT_LINUX_IRDA = 144;

	/** The Constant DLT_IBM_SP. */
	public final static int DLT_IBM_SP = 145;

	/** The Constant DLT_IBM_SN. */
	public final static int DLT_IBM_SN = 146;

	/** The Constant DLT_USER0. */
	public final static int DLT_USER0 = 147;

	/** The Constant DLT_USER1. */
	public final static int DLT_USER1 = 148;

	/** The Constant DLT_USER2. */
	public final static int DLT_USER2 = 149;

	/** The Constant DLT_USER3. */
	public final static int DLT_USER3 = 150;

	/** The Constant DLT_USER4. */
	public final static int DLT_USER4 = 151;

	/** The Constant DLT_USER5. */
	public final static int DLT_USER5 = 152;

	/** The Constant DLT_USER6. */
	public final static int DLT_USER6 = 153;

	/** The Constant DLT_USER7. */
	public final static int DLT_USER7 = 154;

	/** The Constant DLT_USER8. */
	public final static int DLT_USER8 = 155;

	/** The Constant DLT_USER9. */
	public final static int DLT_USER9 = 156;

	/** The Constant DLT_USER10. */
	public final static int DLT_USER10 = 157;

	/** The Constant DLT_USER11. */
	public final static int DLT_USER11 = 158;

	/** The Constant DLT_USER12. */
	public final static int DLT_USER12 = 159;

	/** The Constant DLT_USER13. */
	public final static int DLT_USER13 = 160;

	/** The Constant DLT_USER14. */
	public final static int DLT_USER14 = 161;

	/** The Constant DLT_USER15. */
	public final static int DLT_USER15 = 162;

	/** The Constant DLT_IEEE802_11_RADIO_AVS. */
	public final static int DLT_IEEE802_11_RADIO_AVS = 163;

	/** The Constant DLT_JUNIPER_MONITOR. */
	public final static int DLT_JUNIPER_MONITOR = 164;

	/** The Constant DLT_BACNET_MS_TP. */
	public final static int DLT_BACNET_MS_TP = 165;

	/** The Constant DLT_PPP_PPPD. */
	public final static int DLT_PPP_PPPD = 166;

	/** The Constant DLT_JUNIPER_PPPOE. */
	public final static int DLT_JUNIPER_PPPOE = 167;

	/** The Constant DLT_JUNIPER_PPPOE_ATM. */
	public final static int DLT_JUNIPER_PPPOE_ATM = 168;

	/** The Constant DLT_GPRS_LLC. */
	public final static int DLT_GPRS_LLC = 169;

	/** The Constant DLT_GPF_T. */
	public final static int DLT_GPF_T = 170;

	/** The Constant DLT_GPF_F. */
	public final static int DLT_GPF_F = 171;

	/** The Constant DLT_GCOM_T1E1. */
	public final static int DLT_GCOM_T1E1 = 172;

	/** The Constant DLT_GCOM_SERIAL. */
	public final static int DLT_GCOM_SERIAL = 173;

	/** The Constant DLT_JUNIPER_PIC_PEER. */
	public final static int DLT_JUNIPER_PIC_PEER = 174;

	/** The Constant DLT_ERF_ETH. */
	public final static int DLT_ERF_ETH = 175;

	/** The Constant DLT_ERF_POS. */
	public final static int DLT_ERF_POS = 176;

	/** The Constant DLT_LINUX_LAPD. */
	public final static int DLT_LINUX_LAPD = 177;

	/** Event Tracing for Windows messages. */
	public final static int DLT_ETW = 290;

	/**
	 * Hilscher Gesellschaft fuer Systemautomation mbH netANALYZER NG hardware and
	 * software.
	 *
	 * The specification for this footer can be found at:
	 * https://kb.hilscher.com/x/brDJBw
	 *
	 * Requested by Jan Adam jadam@hilscher.com
	 */
	public final static int DLT_NETANALYZER_NG = 291;

	/**
	 * Serial NCP (Network Co-Processor) protocol for Zigbee stack ZBOSS by DSR.
	 * ZBOSS NCP protocol description:
	 * https://cloud.dsr-corporation.com/index.php/s/3isHzaNTTgtJebn Header in pcap
	 * file: https://cloud.dsr-corporation.com/index.php/s/fiqSDorAAAZrsYB
	 *
	 * Requested by Eugene Exarevsky eugene.exarevsky@dsr-corporation.com
	 * 
	 */
	public final static int DLT_ZBOSS_NCP = 292;

	/** USB 1.0 packets as transmitted over the cable */
	public final static int DLT_USB_2_0_LOW_SPEED = 293;

	/** USB 1.1 packets as transmitted over the cable */
	public final static int DLT_USB_2_0_FULL_SPEED = 294;

	/** USB 2.0 packets as transmitted over the cable */
	public final static int DLT_USB_2_0_HIGH_SPEED = 295;

	/**
	 * Auerswald Logger Protocol description is provided on
	 * https://github.com/Auerswald-GmbH/auerlog/blob/master/auerlog.txt
	 */
	public final static int DLT_AUERSWALD_LOG = 296;

	/**
	 * Z-Wave packets with a TAP meta-data header
	 * https://gitlab.com/exegin/zwave-g9959-tap requested on tcpdump-workers@
	 */
	public final static int DLT_ZWAVE_TAP = 297;

	/** Silicon Labs debug channel protocol. */
	public final static int DLT_SILABS_DEBUG_CHANNEL = 298;

	/**
	 * Ultra-wideband (UWB) controller interface protocol (UCI). requested by Henri
	 * Chataing henrichataing@google.com
	 */
	public final static int DLT_FIRA_UCI = 299;

	/**
	 * MDB (Multi-Drop Bus) protocol between a vending machine controller and
	 * peripherals inside the vending machine. See
	 *
	 * https://www.kaiser.cx/pcap-mdb.html
	 *
	 * for the specification.
	 *
	 * Requested by Martin Kaiser martin@kaiser.cx.
	 */
	public final static int DLT_MDB = 300;

	/**
	 * Converts an integer value into a PcapDLT constant.
	 *
	 * @param dlt Pcap DLT integer value to convert
	 * @return constant assigned to the DLT integer, or null if not found
	 * @throws IllegalArgumentException thrown if not found
	 */
	public static PcapDlt valueOf(int dlt) throws IllegalArgumentException {
		final PcapDlt[] values = values();
		final int length = values.length;

		for (int i = 0; i < length; i++) {
			if (values[i].intDlt == dlt) {
				return values[i];
			}

		}

		throw new IllegalArgumentException(Integer.toString(dlt));
	}

	/**
	 * Converts the supplied id to an ArpHdr enum constant.
	 *
	 * @param dlt the pcap DLT integer constant
	 * @return the corresponding enum if found
	 */
	public static Optional<PcapDlt> toEnum(int dlt) {
		for (var c : values()) {
			if (c.intDlt == dlt)
				return Optional.of(c);
		}

		return Optional.empty();
	}

	/** Integer dlt value assigned by libpcap to this constant. */
	public final int intDlt;

	/**
	 * Description of the dlt retrieved by quering the native pcap library. The
	 * description is not a static constant part of the API and may change from
	 * native libpcap implementation to implementation.
	 */
	public String description;

	/**
	 * Instantiates a new pcap dlt.
	 *
	 * @param pcapDlt the pcap dlt
	 */
	private PcapDlt(int pcapDlt) {
		this.intDlt = pcapDlt;
	}

	/**
	 * Compares the supplied value with the constant's assigned DLT value.
	 * 
	 * @param value the value
	 * @return true if the supplied value matches the value of the constant,
	 *         otherwise false value value to check against this constant
	 */
	public boolean equals(int value) {
		return this.intDlt == value;
	}

	/**
	 * Gets the integer dlt value assigned by libpcap to this constant.
	 * 
	 * @return the integer dlt value assigned by libpcap to this constant
	 * @see java.util.function.IntSupplier#getAsInt()
	 */
	@Override
	public int getAsInt() {
		return this.intDlt;
	}

	/**
	 * Gets the description of the dlt retrieved by quering the native pcap library.
	 * 
	 * @return the description of the dlt retrieved by quering the native pcap
	 *         library
	 * @see PcapDlt#getDescription()
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
