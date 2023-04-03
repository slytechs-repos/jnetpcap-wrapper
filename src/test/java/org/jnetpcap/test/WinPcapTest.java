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
package org.jnetpcap.test;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.IOException;

import org.jnetpcap.PcapException;
import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.constant.PcapSrc;
import org.jnetpcap.windows.WinPcap;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

/**
 * WinPcap unit tests.
 * <p>
 * Defines the following junit tags
 * <dl>
 * <dt>windows</dt>
 * <dd>selects tests that are only supported on Microsoft Windows platforms</dd>
 * <dt>user-permission</dt>
 * <dd>selects tests which will run using any non-privileged permission</dd>
 * <dt>live-capture</dt>
 * <dd>selects test which test live capture capabilities</dd>
 * <dt>offline-capture</dt>
 * <dd>selects tests which test offline capture capabilities</dd>
 * </dl>
 * </p>
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
@Tag("windows-api")
class WinPcapTest extends AbstractTestBase {

	/**
	 * Test method for {@link org.jnetpcap.Pcap#parseSrcStr(java.lang.String)}.
	 */
	@Test
	@Tag("user-permission")
	@Disabled
	void testParseSrcStr() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#createSrcStr(org.jnetpcap.constant.PcapSrc, java.lang.String, java.lang.String, java.lang.String)}.
	 */
	@Test
	@Tag("user-permission")
	@Disabled
	void testCreateSrcStr() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#findAllDevsEx(java.lang.String, org.jnetpcap.constant.PcapSrc, java.lang.String, java.lang.String)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("user-permission")
	void testFindAllDevsEx() throws PcapException {
		assertFalse(WinPcap.findAllDevsEx("rpcap://", PcapSrc.SRC_IFLOCAL, "", "").isEmpty());
	}

	/**
	 * Test method for {@link org.jnetpcap.windows.WinPcap#isSupported()}.
	 */
	@Test
	@Tag("user-permission")
	void testWinPcapIsSupported() {
		assertTrue(WinPcap.isSupported());
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.windows.WinPcap#create(java.lang.String)}.
	 */
	@Test
	@Tag("user-permission")
	@Disabled
	void testCreateString() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.windows.WinPcap#openDead(org.jnetpcap.constant.PcapDlt, int)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("user-permission")
	@Tag("offline-capture")
	void testOpenDeadPcapDltInt() throws PcapException {
		try (var pcap = WinPcap.openDead(PcapDlt.EN10MB, 0)) {}
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.windows.WinPcap#openOffline(java.lang.String)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("user-permission")
	@Tag("offline-capture")
	@Tag("windows")
	void testOpenOfflineString() throws PcapException {
//		try (var pcap = WinPcap.openOffline(OFFLINE_FILE)) {}
	}

	/**
	 * Test method for {@link org.jnetpcap.windows.WinPcap#wsockInit()}.
	 */
	@Test
	@Tag("user-permission")
	@Tag("windows")
	void testWsockInit() {
		assertDoesNotThrow(() -> WinPcap.wsockInit());
	}

	/**
	 * Test method for {@link org.jnetpcap.windows.WinPcap#getEvent()}.
	 */
	@Test
	@Tag("user-permission")
	@Disabled
	void testGetEvent() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.windows.WinPcap#liveDump(java.lang.String, int, int)}.
	 * 
	 * @throws PcapException
	 * @throws IOException
	 */
	@Test
	@Tag("sudo-permission")
	@Tag("offline-capture")
	@Tag("libpcap-dumper-api")
	@Tag("windows")
	void testLiveDump(TestInfo info) throws PcapException, IOException {
		final File tempDumpFile = cleanup(super.tempDumpFile(info), File::delete);
		final String filename = tempDumpFile.getCanonicalPath();
		final int MAX_BYTE_SIZE = 10 * 1024;
		final int MAX_PACKET_COUNT = 10;

		try (var pcap = WinPcap.openOffline(OFFLINE_FILE)) {

			/* Async operation */
			pcap.liveDump(filename, MAX_BYTE_SIZE, MAX_PACKET_COUNT);

			pcap.liveDumpEnded(true); // Block until liveDump finishes

			assertTrue(tempDumpFile.exists());
		}
	}

	/**
	 * Test method for {@link org.jnetpcap.windows.WinPcap#liveDumpEnded(boolean)}.
	 * 
	 * @throws IOException
	 * @throws PcapException
	 */
	@Test
	@Disabled
	void testLiveDumpEnded(TestInfo info) throws IOException, PcapException {
		final File tempDumpFile = cleanup(super.tempDumpFile(info), File::delete);
		final String filename = tempDumpFile.getCanonicalPath();
		final int MAX_BYTE_SIZE = 10 * 1024;
		final int MAX_PACKET_COUNT = 10;

		try (var pcap = WinPcap.openOffline(OFFLINE_FILE)) {

			/* Async operation */
			pcap.liveDump(filename, MAX_BYTE_SIZE, MAX_PACKET_COUNT);

			pcap.liveDumpEnded(true); // Block until liveDump finishes

			/* Transfered 10 packets worth of data */
			assertTrue(tempDumpFile.length() > 0);
		}
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.windows.WinPcap#sendQueueTransmit(org.jnetpcap.windows.PcapSendQueue, boolean)}.
	 */
	@Test
	@Disabled
	void testSendQueueTransmit() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link org.jnetpcap.windows.WinPcap#setBuff(int)}.
	 */
	@Test
	@Disabled
	void testSetBuff() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link org.jnetpcap.windows.WinPcap#setMinToCopy(int)}.
	 */
	@Test
	@Disabled
	void testSetMinToCopy() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.windows.WinPcap#setMode(org.jnetpcap.windows.Mode)}.
	 */
	@Test
	@Disabled
	void testSetModeMode() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link org.jnetpcap.windows.WinPcap#setMode(int)}.
	 */
	@Test
	@Disabled
	void testSetModeInt() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link org.jnetpcap.windows.WinPcap#statsEx()}.
	 */
	@Test
	@Disabled
	void testStatsEx() {
		fail("Not yet implemented");
	}

}
