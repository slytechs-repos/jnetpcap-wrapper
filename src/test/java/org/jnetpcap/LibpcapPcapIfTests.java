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
package org.jnetpcap;

import static org.jnetpcap.constant.SockAddrFamily.*;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;

import org.jnetpcap.PcapIf.PcapAddr;
import org.jnetpcap.SockAddr.Inet6SockAddr;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Disabled;
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

	/** The Constant MAC_ADDR_LEN. */
	private static final int MAC_ADDR_LEN = 6;

	@Test
	@Tag("sudo-permission")
	@Disabled
	void printAllPcapInterfaces() throws PcapException {
		Pcap.findAllDevs().forEach(System.out::println);
	}

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
				.filter(INET::checkIfContains)
				.findAny()
				.orElseThrow();

		PcapAddr<?> addr = device.findAddressOfFamily(INET).orElseThrow();

		assertEquals(Optional.of(INET), addr.socketAddress().familyConstant(),
				"expecting INET family socket address type");
	}

	/**
	 * Test PcapIf socket address INET (v4) address length field is valid.
	 *
	 * @throws PcapException the pcap exception
	 */
	@Test
	@Tag("sudo-permission")
	void PcapIfInetTotalLen() throws PcapException {
		List<PcapIf> list = Pcap.findAllDevs();

		PcapIf device = list.stream()
				.filter(INET::checkIfContains)
				.findAny()
				.orElseThrow();

		PcapAddr<?> addr = device.findAddressOfFamily(INET).orElseThrow();
		OptionalInt addrLen = addr.socketAddress().totalLength();

		if (addrLen.isPresent())
			assertEquals(OptionalInt.of(16), addrLen, "invalid INET family socket address length");

		Assumptions.assumeFalse(addrLen.isPresent(), "totalLen is not available on this platform");
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
				.filter(INET6::checkIfContains)
				.findAny()
				.orElseThrow();

		PcapAddr<?> addr = device.findAddressOfFamily(INET6).orElseThrow();

		assertEquals(Optional.of(INET6), addr.socketAddress().familyConstant(),
				"expecting INET6 family socket address type");
	}

	/**
	 * Pcap if inet 6 subclass.
	 *
	 * @throws PcapException the pcap exception
	 */
	@Test
	@Tag("sudo-permission")
	void PcapIfInet6Subclass() throws PcapException {
		List<PcapIf> list = Pcap.findAllDevs();

		PcapIf device = list.stream()
				.filter(INET6::checkIfContains)
				.findAny()
				.orElseThrow();

		PcapAddr<Inet6SockAddr> addr = device.findAddressOfType(Inet6SockAddr.class)
				.orElseThrow();

		assertEquals(Optional.of(INET6), addr.socketAddress().familyConstant(),
				"expecting INET6 family socket address type");
	}

	/**
	 * Test PcapIf socket address INET6 address length field is valid.
	 *
	 * @throws PcapException the pcap exception
	 */
	@Test
	@Tag("sudo-permission")
	void PcapIfInet6TotalLen() throws PcapException {
		List<PcapIf> list = Pcap.findAllDevs();

		PcapIf device = list.stream()
				.filter(INET6::checkIfContains)
				.findAny()
				.orElseThrow();

		PcapAddr<?> addr = device.findAddressOfFamily(INET6).orElseThrow();
		OptionalInt addrLen = addr.socketAddress().totalLength();

		if (addrLen.isPresent())
			assertEquals(28, addrLen.getAsInt(), "invalid INET6 family socket address length");

		Assumptions.assumeFalse(addrLen.isPresent(), "totalLen is not available on this platform");
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
				.filter(INET::checkIfContains)
				.findAny()
				.orElseThrow();

		assertTrue(device.hardwareAddress().isPresent(), "expected a MAC address for pcap interface");
		assertEquals(MAC_ADDR_LEN, device.hardwareAddress().get().length, "invalid MAC address length");
	}
}
