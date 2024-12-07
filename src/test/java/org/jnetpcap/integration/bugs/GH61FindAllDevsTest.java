/*
 * Copyright 2024 Sly Technologies Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jnetpcap.integration.bugs;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapIf;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

/**
 * Test class for GitHub issue #61: IndexOutOfBoundsException in
 * Pcap.findAllDevs() on macOS 15.1.1 with JDK 23.0.1.
 * 
 * <p>
 * This test verifies the fix for an issue where Pcap.findAllDevs() would throw
 * an IndexOutOfBoundsException when accessing memory segments on newer JDK
 * versions. The issue was specifically reported on macOS but the fix applies to
 * all platforms.
 * </p>
 * 
 * <p>
 * Related GitHub issue: https://github.com/slytechs-repos/jnetpcap/issues/61
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see org.jnetpcap.Pcap#findAllDevs()
 */
@Tag("bugfix")
@Tag("gh-61")
public class GH61FindAllDevsTest {

	/**
	 * Tests that Pcap.findAllDevs() no longer throws IndexOutOfBoundsException on
	 * macOS systems. This test verifies that:
	 * <ul>
	 * <li>The method executes without throwing any exceptions</li>
	 * <li>The returned list is not null</li>
	 * <li>The list size is valid (>= 0)</li>
	 * </ul>
	 * 
	 * <p>
	 * This test is only enabled on macOS systems since the original issue was
	 * specific to that platform, though the fix benefits all platforms.
	 * </p>
	 * 
	 * @throws PcapException if there is an error finding network devices
	 */
	@Test
	@EnabledOnOs(OS.MAC)
	void testFindAllDevsOnMacOS() throws PcapException {
		List<PcapIf> devices = Pcap.findAllDevs();
		assertNotNull(devices, "Device list should not be null");
		assertTrue(devices.size() >= 0, "Device list size should be non-negative");
	}
}