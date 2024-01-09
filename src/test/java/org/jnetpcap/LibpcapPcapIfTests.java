/*
 * MIT License
 * 
 * Copyright (c) 2020 Sly Technologies Inc.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package org.jnetpcap;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.jnetpcap.PcapIf.PcapAddr;
import org.jnetpcap.constant.SockAddrFamily;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Main PcapIf, pcap interface structure specific unit tests.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
@Tag("libpcap-api")
class LibpcapPcapIfTests extends AbstractTestBase {

	private static final int INET4_ADDR_LEN = 4;
	private static final int INET6_ADDR_LEN = 16;
	private static final int MAC_ADDR_LEN = 6;

	/**
	 * Test method for {@link org.jnetpcap.Pcap#findAllDevs()}.
	 *
	 * @throws PcapException the pcap exception
	 */
	@Test
	@Tag("sudo-permission")
	void testFindAllDevs() throws PcapException {
		assertFalse(Pcap.findAllDevs().isEmpty());
	}

	/**
	 * Test pcap if to string.
	 *
	 * @throws PcapException the pcap exception
	 */
	@Test
	@Tag("sudo-permission")
	void testPcapIfToString() throws PcapException {
		List<PcapIf> list = Pcap.findAllDevs();

		assertDoesNotThrow(() -> list.toString(), "Unable to ");
	}

	/**
	 * Test PcapIf socket address INET (v4) family type field is valid.
	 *
	 * @throws PcapException the pcap exception
	 */
	@Test
	@Tag("sudo-permission")
	void PcapIfInetFamily() throws PcapException {
		List<PcapIf> list = Pcap.findAllDevs();

		PcapIf device = list.stream()
				.filter(i -> i.addressOfFamily(SockAddrFamily.INET).isPresent())
				.findAny()
				.orElseThrow();

		PcapAddr addr = device.addressOfFamily(SockAddrFamily.INET).orElseThrow();

		assertEquals(SockAddrFamily.INET.getAsInt(), addr.socketAddress().family(),
				"expecting INET family socket address type");
	}

	/**
	 * Test PcapIf socket address INET (v4) address length field is valid.
	 *
	 * @throws PcapException the pcap exception
	 */
	@Test
	@Tag("sudo-permission")
	void PcapIfInetAddrLen() throws PcapException {
		List<PcapIf> list = Pcap.findAllDevs();

		PcapIf device = list.stream()
				.filter(i -> i.addressOfFamily(SockAddrFamily.INET).isPresent())
				.findAny()
				.orElseThrow();

		PcapAddr addr = device.addressOfFamily(SockAddrFamily.INET).orElseThrow();
		int addrLen = addr.socketAddress().addressLength().orElseThrow();

		assertEquals(INET4_ADDR_LEN, addrLen, "invalid INET family socket address length");
	}

	/**
	 * Test PcapIf socket address INET6 family type field is valid.
	 *
	 * @throws PcapException the pcap exception
	 */
	@Test
	@Tag("sudo-permission")
	void PcapIfInet6Family() throws PcapException {
		List<PcapIf> list = Pcap.findAllDevs();

		PcapIf device = list.stream()
				.filter(i -> i.addressOfFamily(SockAddrFamily.INET6).isPresent())
				.findAny()
				.orElseThrow();

		PcapAddr addr = device.addressOfFamily(SockAddrFamily.INET6).orElseThrow();

		assertEquals(SockAddrFamily.INET6.getAsInt(), addr.socketAddress().family(),
				"expecting INET6 family socket address type");
	}

	/**
	 * Test PcapIf socket address INET6 address length field is valid.
	 *
	 * @throws PcapException the pcap exception
	 */
	@Test
	@Tag("sudo-permission")
	void PcapIfInet6AddrLen() throws PcapException {
		List<PcapIf> list = Pcap.findAllDevs();

		PcapIf device = list.stream()
				.filter(i -> i.addressOfFamily(SockAddrFamily.INET6).isPresent())
				.findAny()
				.orElseThrow();

		PcapAddr addr = device.addressOfFamily(SockAddrFamily.INET6).orElseThrow();
		int addrLen = addr.socketAddress().addressLength().orElseThrow();

		assertEquals(INET6_ADDR_LEN, addrLen, "invalid INET6 family socket address length");
	}

	/**
	 * Test PcapIf has a hardware/Mac address and if the address is of valid length
	 * (6 bytes).
	 *
	 * @throws PcapException the pcap exception
	 */
	@Test
	@Tag("sudo-permission")
	void PcapIfInet4GetHardwareAddress() throws PcapException {
		List<PcapIf> list = Pcap.findAllDevs();

		PcapIf device = list.stream()
				.filter(i -> i.addressOfFamily(SockAddrFamily.INET).isPresent())
				.findAny()
				.orElseThrow();

		assertTrue(device.hardwareAddress().isPresent(), "expected a MAC address for pcap interface");
		assertEquals(MAC_ADDR_LEN, device.hardwareAddress().get().length, "invalid MAC address length");
	}
}
