/*
 * Apache License, Version 2.0
 * 
 * Copyright 2013-2022 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 *   
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jnetpcap;

import static org.junit.jupiter.api.Assertions.*;

import org.jnetpcap.constant.PcapConstants;
import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.constant.PcapSrc;
import org.jnetpcap.windows.PcapSendQueue;
import org.jnetpcap.windows.WinPcap;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

/**
 * Test suite for Windows-specific WinPcap functionality. This class tests the
 * extended features available only on Windows platforms through the
 * WinPcap/NPCap implementations.
 * 
 * <p>
 * The test suite verifies:
 * <ul>
 * <li>Windows-specific device enumeration and configuration</li>
 * <li>Packet capture and transmission capabilities</li>
 * <li>Buffer management and statistics collection</li>
 * <li>Advanced features like packet injection and kernel-level dump</li>
 * </ul>
 * </p>
 * 
 * <p>
 * Test categories include:
 * <dl>
 * <dt>windows-api</dt>
 * <dd>Windows platform specific API tests</dd>
 * <dt>user-permission</dt>
 * <dd>Tests that can run with standard user permissions</dd>
 * <dt>sudo-permission</dt>
 * <dd>Tests that require elevated/administrator permissions</dd>
 * <dt>live-capture</dt>
 * <dd>Tests involving live network capture</dd>
 * <dt>offline-capture</dt>
 * <dd>Tests using saved capture files</dd>
 * </dl>
 * </p>
 */
@Tag("windows-api")
class WinPcapTest extends AbstractTestBase {

	/**
	 * Tests parsing of source strings for remote capture configuration. Verifies
	 * that WinPcap properly interprets different source string formats.
	 */
	@Test
	@Tag("user-permission")
	@EnabledOnOs(OS.WINDOWS)
	void testParseSrcStr() throws PcapException {
		String srcStr = "rpcap://192.168.1.1/eth0";
		var result = WinPcap.parseSrcStr(srcStr);

		assertNotNull(result);
		assertEquals("eth0", result.name());
	}

	/**
	 * Tests creation of source strings for various capture types. Validates proper
	 * formatting of source strings for local and remote captures.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("user-permission")
	@EnabledOnOs(OS.WINDOWS)
	void testCreateSrcStr() throws PcapException {
		String srcStr = WinPcap.createSrcStr(PcapSrc.SRC_IFLOCAL, "eth0", null, null);

		assertNotNull(srcStr);
		assertTrue(srcStr.contains("eth0"));
	}

	/**
	 * Tests enumeration of network devices using extended WinPcap capabilities.
	 * Verifies discovery of both local and remote capture devices.
	 */
	@Test
	@Tag("user-permission")
	@EnabledOnOs(OS.WINDOWS)
	void testFindAllDevsEx() throws PcapException {
		var devices = WinPcap.findAllDevsEx("rpcap://", PcapSrc.SRC_IFLOCAL, "", "");

		assertFalse(devices.isEmpty());
		assertTrue(devices.get(0).name().length() > 0);
	}

	/**
	 * Tests WinPcap support detection. Verifies that WinPcap/NPCap services are
	 * properly installed and accessible.
	 */
	@Test
	@Tag("user-permission")
	@EnabledOnOs(OS.WINDOWS)
	void testWinPcapIsSupported() {
		assertTrue(WinPcap.isSupported());
	}

	/**
	 * Tests creation of dead capture handle for offline packet analysis.
	 */
	@Test
	@Tag("user-permission")
	@Tag("offline-capture")
	@EnabledOnOs(OS.WINDOWS)
	void testOpenDeadPcapDltInt() throws PcapException {
		try (var pcap = WinPcap.openDead(PcapDlt.EN10MB, PcapConstants.MAX_SNAPLEN)) {
			assertNotNull(pcap);
			assertTrue(WinPcap.isSupported());
		}
	}

	/**
	 * Tests Windows socket initialization required for some capture operations.
	 */
	@Test
	@Tag("user-permission")
	@EnabledOnOs(OS.WINDOWS)
	void testWsockInit() {
		assertDoesNotThrow(() -> WinPcap.wsockInit());
	}

	/**
	 * Tests buffer size configuration for capture handles.
	 */
	@Test
	@Tag("user-permission")
	@EnabledOnOs(OS.WINDOWS)
	void testSetBuff() throws PcapException {
		try (var pcap = pcapOpenDeadTestHandle()) {
			assertDoesNotThrow(() -> ((WinPcap) pcap).setBuff(65536));
		}
	}

	/**
	 * Tests configuration of minimum bytes to copy in kernel buffer operations.
	 */
	@Test
	@Tag("user-permission")
	@EnabledOnOs(OS.WINDOWS)
	void testSetMinToCopy() throws PcapException {
		try (var pcap = pcapOpenDeadTestHandle()) {
			assertDoesNotThrow(() -> ((WinPcap) pcap).setMinToCopy(64));
		}
	}

	/**
	 * Tests packet queue transmission capabilities. Verifies proper handling of
	 * queued packets for transmission.
	 */
	@Test
	@Tag("sudo-permission")
	@Tag("live-capture")
	@EnabledOnOs(OS.WINDOWS)
	void testSendQueueTransmit() throws PcapException {
		try (var pcap = pcapOpenLiveTestHandle()) {
			PcapSendQueue queue = new PcapSendQueue(1024);
			// Add test packet to queue
			byte[] testPacket = templates.tcpArray();
			queue.queue(new PcapHeader(0, 0, testPacket.length, testPacket.length), testPacket, 0);

			// Transmit queue
			int sent = ((WinPcap) pcap).sendQueueTransmit(queue, true);
			assertTrue(sent > 0);
		}
	}

	/**
	 * Tests extended statistics collection. Verifies gathering of Windows-specific
	 * capture statistics.
	 */
	@Test
	@Tag("user-permission")
	@Tag("live-capture")
	@EnabledOnOs(OS.WINDOWS)
	void testStatsEx() throws PcapException {
		try (var pcap = pcapOpenLiveTestHandle()) {
			var stats = ((WinPcap) pcap).statsEx();
			assertNotNull(stats);
		}
	}
}