/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
 * 
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.jnetpcap.integration.bugs;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapIf;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

/**
 * Test class for GitHub issue #63: ERROR_NO_SUCH_DEVICE when running
 * pcap.activate() on macOS Sonoma.
 * 
 * <p>
 * This test suite verifies various aspects of device detection and activation
 * on macOS systems, specifically addressing the ERROR_NO_SUCH_DEVICE issue. It
 * includes tests for:
 * <ul>
 * <li>Device enumeration</li>
 * <li>Specific interface activation</li>
 * <li>Permission-related scenarios</li>
 * </ul>
 * </p>
 * 
 * <p>
 * Related GitHub issue: https://github.com/slytechs-repos/jnetpcap/issues/63
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see org.jnetpcap.Pcap#create(PcapIf)
 * @see org.jnetpcap.Pcap#activate()
 */
@Tag("bugfix")
@Tag("gh-63")
public class GH63NoSuchDeviceTest {

	/**
	 * Verifies that at least one network device is available on the system.
	 * 
	 * <p>
	 * This test checks if Pcap can detect any network interfaces on the system. A
	 * failure here might indicate permission issues or problems with the network
	 * configuration.
	 * </p>
	 * @throws PcapException 
	 */
	@Test
	@EnabledOnOs(OS.MAC)
	void testDeviceListNotEmpty() throws PcapException {
		List<PcapIf> devices = Pcap.findAllDevs();
		assertFalse(devices.isEmpty(), "No network devices found. Ensure proper permissions are set.");
	}

	/**
	 * Tests the ability to activate specific common network interfaces on macOS.
	 * 
	 * <p>
	 * This test attempts to activate common macOS network interfaces (en0, en1,
	 * lo0). It verifies that at least one of these interfaces:
	 * <ul>
	 * <li>Can be found in the device list</li>
	 * <li>Can be opened with Pcap.create()</li>
	 * <li>Can be activated successfully</li>
	 * </ul>
	 * </p>
	 * 
	 * @throws PcapException
	 */
	@Test
	@EnabledOnOs(OS.MAC)
	void testSpecificInterface() throws PcapException {
		List<PcapIf> devices = Pcap.findAllDevs();
		assumeFalse(devices.isEmpty(), "Skip test if no devices available");

		String[] commonInterfaces = { "en0",
				"en1",
				"lo0"
		};
		boolean foundInterface = false;

		for (String ifName : commonInterfaces) {
			PcapIf device = devices.stream()
					.filter(dev -> dev.name().equals(ifName))
					.findFirst()
					.orElse(null);

			if (device != null) {
				foundInterface = true;
				try (Pcap pcap = Pcap.create(device)) {
					pcap.setSnaplen(65536);
					pcap.setTimeout(1000);
					pcap.setPromisc(foundInterface);
					assertDoesNotThrow(() -> pcap.activate(),
							"Device activation failed for " + ifName);
				}
				break;
			}
		}

		assertTrue(foundInterface, "No common network interfaces found");
	}

	/**
	 * Tests error handling when attempting to activate a device without proper
	 * permissions.
	 * 
	 * <p>
	 * This test verifies that appropriate errors are thrown when attempting to
	 * activate a network interface without the necessary permissions. It expects
	 * either:
	 * <ul>
	 * <li>ERROR_NO_SUCH_DEVICE: When the device cannot be accessed</li>
	 * <li>ERROR_PERM_DENIED: When permission is explicitly denied</li>
	 * </ul>
	 * </p>
	 * @throws PcapException 
	 */
	@Test
	@EnabledOnOs(OS.MAC)
	void testDevicePermissions() throws PcapException {
		List<PcapIf> devices = Pcap.findAllDevs();
		assumeFalse(devices.isEmpty(), "Skip test if no devices available");

		PcapIf device = devices.get(0);
		try (Pcap pcap = Pcap.create(device)) {
			pcap.setSnaplen(65536);
			pcap.setTimeout(1000);
			pcap.setPromisc(true);

			PcapException exception = assertThrows(PcapException.class,
					() -> {
						// Run without proper permissions
						pcap.activate();
					},
					"Expected activation to fail due to permissions");

			assertTrue(
					exception.getMessage().contains("ERROR_NO_SUCH_DEVICE") ||
							exception.getMessage().contains("ERROR_PERM_DENIED"),
					"Expected permission or device error");
		}
	}
}