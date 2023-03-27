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

import static java.util.concurrent.TimeUnit.*;
import static org.jnetpcap.constant.PcapConstants.*;
import static org.jnetpcap.test.AbstractTestBase.TestPacket.*;
import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.lang.foreign.MemoryAddress;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.jnetpcap.BpFilter;
import org.jnetpcap.Pcap;
import org.jnetpcap.Pcap.LibraryPolicy;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapHandler;
import org.jnetpcap.constant.PcapConstants;
import org.jnetpcap.constant.PcapDirection;
import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.constant.PcapTStampPrecision;
import org.jnetpcap.constant.PcapTstampType;
import org.jnetpcap.util.NetIp4Address;
import org.jnetpcap.util.PcapPacketRef;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

/**
 * Main Pcap unit tests.
 * <p>
 * Defines the following junit tags
 * <dl>
 * <dt>pcap</dt>
 * <dd>selects tests that are generic libpcap and any api level and supported on
 * all platforms</dd>
 * <dt>non-pcap</dt>
 * <dd>selects test that are non-pcap methods but part of jNetPcap library</dd>
 * <dt>user-permission</dt>
 * <dd>selects tests which will run using any non-privileged permission</dd>
 * <dt>sudo-permission</dt>
 * <dd>selects tests which require super user permissions to run</dd>
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
 */
@Tag("libpcap-api")
class LibpcapApiTest extends AbstractTestBase {

	/**
	 * Test method for {@link org.jnetpcap.Pcap#activate()}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	void testActivate() throws PcapException {
		var pcap = super.pcapCreateTestHandle();

		assertDoesNotThrow(pcap::activate);
	}

	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	void testCanSetRfmon() throws PcapException {
		var pcap = super.pcapCreateTestHandle();

		assertDoesNotThrow(pcap::canSetRfmon);
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#breakloop()}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	void testBreakloop_liveCapture() throws PcapException {
		var pcap = super.pcapCreateTestHandle();

		pcap.activate();

		assertDoesNotThrow(pcap::breakloop);

		final int PACKET_COUNT = 1;
		final PcapHandler.OfArray<String> HANDLER = (user, header, packet) -> {};
		final String USER = "";

		assertEquals(PCAP_ERROR_BREAK, pcap.loop(PACKET_COUNT, HANDLER, USER), "expecting BREAK loop error code");
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#breakloop()}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testBreakloop_offlineCapture() throws PcapException {
		var pcap = pcapOpenOfflineTestHandle();

		assertDoesNotThrow(pcap::breakloop);

		final int PACKET_COUNT = 1;
		final PcapHandler.OfArray<String> HANDLER = (user, header, packet) -> {};
		final String USER = "";

		assertEquals(PCAP_ERROR_BREAK, pcap.loop(PACKET_COUNT, HANDLER, USER), "expecting BREAK loop error code");
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#breakloop()}.
	 * 
	 * TODO: CRASHES THE VM!!!!
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	@Disabled
	void testBreakloop_deadCapture() throws PcapException {
		var pcap = pcapOpenDeadTestHandle();

		assertDoesNotThrow(pcap::breakloop);

		final int PACKET_COUNT = 1;
		final PcapHandler.OfArray<String> HANDLER = (user, header, packet) -> {};
		final String USER = "";

		assertEquals(PCAP_ERROR_BREAK, pcap.loop(PACKET_COUNT, HANDLER, USER), "expecting BREAK loop error code");
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#close()}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testClose_DeadHandle() throws PcapException {
		var pcap = super.pcapOpenDeadTestHandle();

		assertDoesNotThrow(pcap::close);
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#close()}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testClose_OfflineHandle() throws PcapException {
		var pcap = super.pcapOpenOfflineTestHandle();

		assertDoesNotThrow(pcap::close);
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#close()}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	void testClose_LiveHandle() throws PcapException {
		var pcap = super.pcapOpenLiveTestHandle();

		assertDoesNotThrow(pcap::close);
	}

	@Test
	@Tag("user-permission")
	void testCompileNoPcap() throws PcapException {

		final int SNAPLEN = MAX_SNAPLEN;
		final PcapDlt DLT = PcapDlt.EN10MB;
		final String FILTER_STR = "tcp";
		final boolean OPTIMIZE = false;
		final int NETMASK = PCAP_NETMASK_UNKNOWN;

		/* Free native filter code after compile by calling BpFilter.close() */
		assertDoesNotThrow(() -> Pcap.compileNoPcap(SNAPLEN, DLT, FILTER_STR, OPTIMIZE, NETMASK).close());
	}

	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testCompile_DeadHandle() throws PcapException {
		var pcap = pcapOpenDeadTestHandle();

		final String FILTER_STR = "tcp";
		final boolean OPTIMIZE = false;

		/* Free native filter code after compile by calling BpFilter.close() */
		assertDoesNotThrow(() -> pcap.compile(FILTER_STR, OPTIMIZE).close());
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#compile(java.lang.String, boolean)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testCompile_OfflineHandle() throws PcapException {
		var pcap = pcapOpenOfflineTestHandle();

		final String FILTER_STR = "tcp";
		final boolean OPTIMIZE = false;

		/* Free native filter code after compile by calling BpFilter.close() */
		assertDoesNotThrow(() -> pcap.compile(FILTER_STR, OPTIMIZE).close());
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#compile(java.lang.String, boolean)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	void testCompile_LiveHandle() throws PcapException {
		var pcap = pcapOpenLiveTestHandle();

		final String FILTER_STR = "tcp";
		final boolean OPTIMIZE = false;

		/* Free native filter code after compile by calling BpFilter.close() */
		assertDoesNotThrow(() -> pcap.compile(FILTER_STR, OPTIMIZE).close());
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#compile(java.lang.String, boolean, int)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("user-permission")
	void testCompileWithNetmask_DeadHandle() throws PcapException {
		var pcap = pcapOpenDeadTestHandle();

		final String FILTER_STR = "tcp";
		final boolean OPTIMIZE = false;
		final int NETMASK = PCAP_NETMASK_UNKNOWN;

		/* Free native filter code after compile by calling BpFilter.close() */
		assertDoesNotThrow(() -> pcap.compile(FILTER_STR, OPTIMIZE, NETMASK));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#datalink()}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	void testDatalink() throws PcapException {
		var pcap = pcapOpenLiveTestHandle();

		assertNotNull(pcap.datalink());
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#dataLinkExt()}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	void testDataLinkExt() throws PcapException {
		var pcap = pcapOpenLiveTestHandle();

		assertNotNull(pcap.dataLinkExt());
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#datalinkNameToVal(java.lang.String)}.
	 */
	@Test
	@Tag("user-permission")
	void testDatalinkNameToVal() {
		final PcapDlt DLT = PcapDlt.EN10MB;
		assertEquals(DLT, Pcap.datalinkNameToVal(DLT.name()));
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#datalinkValToDescription(org.jnetpcap.constant.PcapDlt)}.
	 */
	@Test
	@Tag("user-permission")
	void testDatalinkValToDescription() {
		final PcapDlt DLT = PcapDlt.EN10MB;
		final String DLT_DESCRIPTION = "Ethernet";
		assertEquals(DLT_DESCRIPTION, Pcap.datalinkValToDescription(DLT));
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#datalinkValToName(org.jnetpcap.constant.PcapDlt)}.
	 */
	@Test
	@Tag("user-permission")
	void testDatalinkValToName() {
		final PcapDlt DLT = PcapDlt.EN10MB;
		assertEquals(DLT.name(), Pcap.datalinkValToName(DLT));
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#dispatch(int, org.jnetpcap.PcapHandler.OfArray, java.lang.Object)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testDispatch_OfArray_OfflineHandle() throws PcapException {
		var pcap = pcapOpenOfflineTestHandle();

		final int PACKET_COUNT = 5;
		final PcapHandler.OfArray<String> HANDLER = (user, header, packet) -> {/* discard */};
		final String USER = "";

		/* Pcap.dispatch retruns number of packets on success and -2 on breakloop */
		assertEquals(PACKET_COUNT, pcap.dispatch(PACKET_COUNT, HANDLER, USER));
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#dispatchRaw(int, org.jnetpcap.PcapHandler.OfRawPacket, MemoryAddress)}.
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testDispatch_OfRawPacket_OfflineHandle() throws PcapException {
		var pcap = pcapOpenOfflineTestHandle();

		final int PACKET_COUNT = 5;
		final PcapHandler.NativeCallback HANDLER = (ignore, header, packet) -> {/* discard */};

		/* Pcap.dispatch retruns number of packets on success and -2 on breakloop */
		assertEquals(PACKET_COUNT, pcap
				.dispatchWithAccessToRawPacket(
						PACKET_COUNT,
						HANDLER,
						MemoryAddress.NULL));
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#dispatch(int, org.jnetpcap.PcapDumper)}.
	 * 
	 * @throws PcapException
	 * @throws IOException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	@Tag("libpcap-dumper-api")
	void testDispatch_PcapDumper_OfflineHandle(TestInfo info) throws PcapException, IOException {
		final var pcap = pcapOpenOfflineTestHandle();
		final var TEMP_DUMP_FILENAME = tempDumpFile(info).getAbsolutePath();
		final int PACKET_COUNT = 5;

		try (PcapDumper dumper = pcap.dumpOpen(TEMP_DUMP_FILENAME)) {
			assertEquals(PACKET_COUNT, pcap.dispatch(PACKET_COUNT, dumper));
		}
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#dumpOpen(java.lang.String)}.
	 * 
	 * @throws PcapException
	 * @throws IOException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	@Tag("libpcap-dumper-api")
	void testDumpOpen_OfflineHandle(TestInfo info) throws PcapException, IOException {
		final var pcap = pcapOpenOfflineTestHandle();
		final var TEMP_DUMP_FILENAME = tempDumpFile(info).getAbsolutePath();

		try (PcapDumper dumper = pcap.dumpOpen(TEMP_DUMP_FILENAME)) {
			assertNotNull(dumper);
		}
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#findAllDevs()}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("user-permission")
	void testFindAllDevs() throws PcapException {
		assertFalse(Pcap.findAllDevs().isEmpty());
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#freeCode(org.jnetpcap.BpFilter)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testFreeCode_PcapCompile_OfflineHandle() throws PcapException {
		var pcap = pcapOpenOfflineTestHandle();

		final String FILTER_STR = "tcp";
		final boolean OPTIMIZE = false;

		BpFilter filter = pcap.compile(FILTER_STR, OPTIMIZE);

		/*
		 * native code is freed by calling BpFilter.close() method. Normally enclosed
		 * with try-with-resource to ensure closure under all conditions.
		 */
		assertDoesNotThrow(filter::close);
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#getPolicy()}.
	 */
	@Test
	@Tag("user-permission")
	void testGetDefaultMissingSymbolsPolicy() {
		assertNotNull(LibraryPolicy.getDefault());
	}

	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testGeterr_OfflineHandle() throws PcapException {
		var pcap = pcapOpenOfflineTestHandle();

		/*
		 * Force an error. Can not invoke stats on offline pcap handle, stats are
		 * available only on live handles/captures
		 */
		assertThrows(PcapException.class, pcap::stats);

		final String EXPECTED_ERR_MSG = "Statistics aren't available from savefiles";

		assertEquals(EXPECTED_ERR_MSG, pcap.geterr());
	}

	@Test
	@Tag("user-permission")
	void testInit() {
		final int PCAP_OPTIONS = PcapConstants.PCAP_CHAR_ENC_UTF_8;

		assertDoesNotThrow(() -> Pcap.init(PCAP_OPTIONS));
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#inject(java.lang.foreign.Addressable, int)}.
	 * 
	 * We create two test pcap handles, one for transmit and one for capture. We
	 * capture on the OUT bound direction only, should be the packet we're
	 * transmitting. However there is no guarantees, so we do a little loop and we
	 * compare source IP address of the captured packet against, the transmitted
	 * packet (192.168.253.5), to ensure that we get the right now. We loop a few
	 * times, if we do not match and each time we transmit a new packet, with a
	 * small delay (250ms). Either when we match or just hit the loop limit counter,
	 * we exit and compare the entire body of each packet. Again, we can't guarantee
	 * 100% correct test each time, but it does work in all runs we've tried so far.
	 * 
	 * That is why this test is tagged as "live-network-with-packets" and as such,
	 * all tests that rely on live network packets, are not 100% predictable but
	 * good enough, even if we have to run the test a few times.
	 * 
	 * @throws PcapException
	 * @throws InterruptedException
	 * @throws ExecutionException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	@Tag("live-network-with-packets")
	void testInject_MemorySegment_IntoLiveNetwork() throws PcapException, InterruptedException,
			ExecutionException {

		final long TRANSMIT_DELAY_IN_MILLIS = 250;
		final int TRANSMIT_RETRIES_COUNT = 20;

		var captureHandle = super.pcapCreateTestHandle();
		captureHandle.setTimeout(1000).activate();
		captureHandle.setDirection(PcapDirection.DIRECTION_OUT);

		var transmitHandle = super.pcapCreateTestHandle();
		transmitHandle.activate();

		var transmitter = super.setupPacketTransmitter(
				templates::tcpPacket /* packet factory */,
				(pkt, pktSize) -> Assertions /* Unit test */
						.assertDoesNotThrow(() -> transmitHandle.inject(pkt, pktSize)));

		TestPacket sentPacket = transmitter.getPacket();
		byte[] sentSrcAddress = sentPacket.ipSrc();

		byte[] SENT_PACKET = sentPacket.toArray();
		byte[] CAPTURED_PACKET = null;

		int loopCounter = TRANSMIT_RETRIES_COUNT;
		while (loopCounter-- > 0) {
			try (var joinOnAutoClose = transmitter.transmitPacketWithDelay(TRANSMIT_DELAY_IN_MILLIS);
					var pcapScope = MemorySession.openShared()) {

				/* do capture */
				var packet = fromPcapPacketRef(captureHandle.next(), pcapScope);

				/* Check if we have the just transmitted packet */
				if ((packet != null) && Arrays.equals(sentSrcAddress, packet.ipSrc())) {
					CAPTURED_PACKET = packet.toArray();
					break;
				}
			}
		}

		assertNotNull(CAPTURED_PACKET,
				"unable to capture the sent packet for verification of transmission after %d tries"
						.formatted(TRANSMIT_RETRIES_COUNT));

		assertArrayEquals(SENT_PACKET, CAPTURED_PACKET,
				"unable to capture the transmitted packet after %d tries"
						.formatted(TRANSMIT_RETRIES_COUNT));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#inject(byte[])}.
	 * 
	 * @throws PcapException
	 * @throws ExecutionException
	 * @throws InterruptedException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	@Tag("live-network-with-packets")
	void testInject_ByteArray_IntoLiveNetwork() throws PcapException, InterruptedException, ExecutionException {
		final long TRANSMIT_DELAY_IN_MILLIS = 250;
		final int TRANSMIT_RETRIES_COUNT = 20;
		final byte[] template = templates.tcpArray();
		final byte[] inputPacketData = Arrays.copyOf(template, template.length);

		var captureHandle = super.pcapCreateTestHandle();
		captureHandle.setTimeout(1000).activate();
		captureHandle.setDirection(PcapDirection.DIRECTION_OUT);

		var transmitHandle = super.pcapCreateTestHandle();
		transmitHandle.activate();

		var transmitter = super.setupPacketTransmitter(() -> Assertions /* Unit test */
				.assertDoesNotThrow(() -> transmitHandle.inject(inputPacketData)));

		byte[] sentSrcAddress = Arrays.copyOfRange(template, SRC_IP_OFFSET, SRC_IP_OFFSET + IP_ADDR_LEN);

		byte[] SENT_PACKET = inputPacketData;
		byte[] CAPTURED_PACKET = null;

		int loopCounter = TRANSMIT_RETRIES_COUNT;
		while (loopCounter-- > 0) {
			try (var joinOnAutoClose = transmitter.transmitPacketWithDelay(TRANSMIT_DELAY_IN_MILLIS);
					var pcapScope = MemorySession.openShared()) {

				/* do capture */
				var packet = fromPcapPacketRef(captureHandle.next(), pcapScope);

				/* Check if we have the just transmitted packet */
				if ((packet != null) && Arrays.equals(sentSrcAddress, packet.ipSrc())) {
					CAPTURED_PACKET = packet.toArray();
					break;
				}
			}
		}

		assertNotNull(CAPTURED_PACKET,
				"unable to capture the sent packet for verification of transmission after %d tries"
						.formatted(TRANSMIT_RETRIES_COUNT));

		assertArrayEquals(SENT_PACKET, CAPTURED_PACKET,
				"unable to capture the transmitted packet after %d tries"
						.formatted(TRANSMIT_RETRIES_COUNT));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#inject(byte[], int, int)}.
	 * 
	 * @throws PcapException
	 * @throws ExecutionException
	 * @throws InterruptedException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	@Tag("live-network-with-packets")
	void testInject_ByteArrayOffset_IntoLiveNetwork() throws PcapException, InterruptedException, ExecutionException {
		final long TRANSMIT_DELAY_IN_MILLIS = 250;
		final int TRANSMIT_RETRIES_COUNT = 20;
		final int BUFFER_SIZE = 1024 * 1024; // 1MB
		final byte[] template = templates.tcpArray();
		final int packetLength = template.length;

		final byte[] buffer = new byte[BUFFER_SIZE];
		final int offset = new Random().nextInt(0, BUFFER_SIZE - packetLength);
		System.arraycopy(template, 0, buffer, offset, packetLength);

		var captureHandle = super.pcapCreateTestHandle();
		captureHandle.setTimeout(1000).activate();
		captureHandle.setDirection(PcapDirection.DIRECTION_OUT);

		var transmitHandle = super.pcapCreateTestHandle();
		transmitHandle.activate();

		var transmitter = super.setupPacketTransmitter(() -> Assertions /* Unit test */
				.assertDoesNotThrow(() -> transmitHandle.inject(buffer, offset, packetLength)));

		byte[] sentSrcAddress = Arrays.copyOfRange(template, SRC_IP_OFFSET, SRC_IP_OFFSET + IP_ADDR_LEN);

		byte[] SENT_PACKET = template;
		byte[] CAPTURED_PACKET = null;

		int loopCounter = TRANSMIT_RETRIES_COUNT;
		while (loopCounter-- > 0) {
			try (var joinOnAutoClose = transmitter.transmitPacketWithDelay(TRANSMIT_DELAY_IN_MILLIS);
					var pcapScope = MemorySession.openShared()) {

				/* do capture */
				var packet = fromPcapPacketRef(captureHandle.next(), pcapScope);

				/* Check if we have the just transmitted packet */
				if ((packet != null) && Arrays.equals(sentSrcAddress, packet.ipSrc())) {
					CAPTURED_PACKET = packet.toArray();
					break;
				}
			}
		}

		assertNotNull(CAPTURED_PACKET,
				"unable to capture the sent packet for verification of transmission after %d tries"
						.formatted(TRANSMIT_RETRIES_COUNT));

		assertArrayEquals(SENT_PACKET, CAPTURED_PACKET,
				"unable to capture the transmitted packet after %d tries"
						.formatted(TRANSMIT_RETRIES_COUNT));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#inject(java.nio.ByteBuffer)}.
	 * 
	 * @throws PcapException
	 * @throws ExecutionException
	 * @throws InterruptedException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	@Tag("live-network-with-packets")
	void testInject_ArrayByteBuffer_IntoLiveNetwork() throws PcapException, InterruptedException, ExecutionException {
		final long TRANSMIT_DELAY_IN_MILLIS = 250;
		final int TRANSMIT_RETRIES_COUNT = 20;
		final byte[] template = templates.tcpArray();
		final ByteBuffer buffer = ByteBuffer.wrap(template);

		var captureHandle = super.pcapCreateTestHandle();
		captureHandle.setTimeout(1000).activate();
		captureHandle.setDirection(PcapDirection.DIRECTION_OUT);

		var transmitHandle = super.pcapCreateTestHandle();
		transmitHandle.activate();

		var transmitter = super.setupPacketTransmitter(() -> Assertions /* Unit test */
				.assertDoesNotThrow(() -> transmitHandle.inject(buffer)));

		byte[] sentSrcAddress = Arrays.copyOfRange(template, SRC_IP_OFFSET, SRC_IP_OFFSET + IP_ADDR_LEN);

		byte[] SENT_PACKET = template;
		byte[] CAPTURED_PACKET = null;

		int loopCounter = TRANSMIT_RETRIES_COUNT;
		while (loopCounter-- > 0) {
			try (var joinOnAutoClose = transmitter.transmitPacketWithDelay(TRANSMIT_DELAY_IN_MILLIS);
					var pcapScope = MemorySession.openShared()) {

				/* do capture */
				var packet = fromPcapPacketRef(captureHandle.next(), pcapScope);

				/* Check if we have the just transmitted packet */
				if ((packet != null) && Arrays.equals(sentSrcAddress, packet.ipSrc())) {
					CAPTURED_PACKET = packet.toArray();
					break;
				}
			}
		}

		assertNotNull(CAPTURED_PACKET,
				"unable to capture the sent packet for verification of transmission after %d tries"
						.formatted(TRANSMIT_RETRIES_COUNT));

		assertArrayEquals(SENT_PACKET, CAPTURED_PACKET,
				"unable to capture the transmitted packet after %d tries"
						.formatted(TRANSMIT_RETRIES_COUNT));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#inject(java.nio.ByteBuffer)}.
	 * 
	 * @throws PcapException
	 * @throws ExecutionException
	 * @throws InterruptedException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	@Tag("live-network-with-packets")
	void testInject_NativeByteBuffer_IntoLiveNetwork() throws PcapException, InterruptedException, ExecutionException {
		final long TRANSMIT_DELAY_IN_MILLIS = 250;
		final int TRANSMIT_RETRIES_COUNT = 20;
		final byte[] template = templates.tcpArray();
		final ByteBuffer buffer = ByteBuffer.allocateDirect(template.length);
		buffer.put(template).flip();

		var captureHandle = super.pcapCreateTestHandle();
		captureHandle.setTimeout(1000).activate();
		captureHandle.setDirection(PcapDirection.DIRECTION_OUT);

		var transmitHandle = super.pcapCreateTestHandle();
		transmitHandle.activate();

		var transmitter = super.setupPacketTransmitter(() -> Assertions /* Unit test */
				.assertDoesNotThrow(() -> transmitHandle.inject(buffer)));

		byte[] sentSrcAddress = Arrays.copyOfRange(template, SRC_IP_OFFSET, SRC_IP_OFFSET + IP_ADDR_LEN);

		byte[] SENT_PACKET = template;
		byte[] CAPTURED_PACKET = null;

		int loopCounter = TRANSMIT_RETRIES_COUNT;
		while (loopCounter-- > 0) {
			try (var joinOnAutoClose = transmitter.transmitPacketWithDelay(TRANSMIT_DELAY_IN_MILLIS);
					var pcapScope = MemorySession.openShared()) {

				/* do capture */
				var packet = fromPcapPacketRef(captureHandle.next(), pcapScope);

				/* Check if we have the just transmitted packet */
				if ((packet != null) && Arrays.equals(sentSrcAddress, packet.ipSrc())) {
					CAPTURED_PACKET = packet.toArray();
					break;
				}
			}
		}

		assertNotNull(CAPTURED_PACKET,
				"unable to capture the sent packet for verification of transmission after %d tries"
						.formatted(TRANSMIT_RETRIES_COUNT));

		assertArrayEquals(SENT_PACKET, CAPTURED_PACKET,
				"unable to capture the transmitted packet after %d tries"
						.formatted(TRANSMIT_RETRIES_COUNT));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#isSwapped()}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testIsSwapped_OfflineHandle() throws PcapException {
		var pcap = pcapOpenOfflineTestHandle();

		assertFalse(pcap.isSwapped());
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#libVersion()}.
	 */
	@Test
	@Tag("user-permission")
	void testLibVersion() {
		assertTrue(Pcap.libVersion().contains("libpcap"));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#listDataLinks()}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testListDataLinks() throws PcapException {
		var pcap = pcapOpenOfflineTestHandle();

		final PcapDlt DTL = PcapDlt.EN10MB;

		assertEquals(DTL, pcap.listDataLinks().get(0));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#listTstampTypes()}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testListTstampTypes() throws PcapException {
		var pcap = pcapOpenOfflineTestHandle();

		final PcapTstampType TSTAMP_TYPE = PcapTstampType.TSTAMP_TYPE_HOST;

		assertEquals(TSTAMP_TYPE, pcap.listTstampTypes().get(0));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#loadNativePcapLibrary()}.
	 */
	@Test
	@Tag("user-permission")
	void testLoadNativePcapLibrary() {
		assertTrue(Pcap.loadNativePcapLibrary());
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#lookupDev()}.
	 * 
	 * Deprecated or not, we still have to test it, until its officially removed
	 * from libpcap API.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("user-permission")
	@SuppressWarnings("deprecation")
	void testLookupDev() {
		assertThrows(PcapException.class, Pcap::lookupDev);
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#lookupNet(java.lang.String)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("user-permission")
	void testLookupNet() throws PcapException {
		String firstDevice = Pcap.findAllDevs().get(0).name();

		NetIp4Address ipAddress = Pcap.lookupNet(firstDevice);

		final int IP4_ADDRESS = ipAddress.address();
		final int IP4_NETMAKS = ipAddress.netmask();

		assertTrue(IP4_ADDRESS > 0, "invalid ip address");
		assertTrue(IP4_NETMAKS > 0, "invalid ip netmask");
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#loop(int, org.jnetpcap.PcapHandler.OfArray, java.lang.Object)}.
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testLoop_OfArray_OfflineHandle() throws PcapException {
		var pcap = pcapOpenOfflineTestHandle();

		final int PACKET_COUNT = 5;
		final int LOOP_OK_STATUS = 0;
		final PcapHandler.OfArray<String> HANDLER = (user, header, packet) -> {/* discard */};
		final String USER = "";

		/* Pcap.loop returns 0 on success unlike Pcap.dispatch, -2 on breakloop */
		assertEquals(LOOP_OK_STATUS, pcap.loop(PACKET_COUNT, HANDLER, USER));
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#loopRaw(int, org.jnetpcap.PcapHandler.OfRawPacket, MemoryAddress)}.
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testLoop_OfRawPacket_OfflineHandle() throws PcapException {
		var pcap = pcapOpenOfflineTestHandle();

		final int PACKET_COUNT = 5;
		final int LOOP_OK_STATUS = 0;
		final PcapHandler.NativeCallback HANDLER = (user, header, packet) -> {/* discard */};

		assertEquals(LOOP_OK_STATUS, pcap.loopWithAccessToRawPacket(PACKET_COUNT, HANDLER));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#loop(int, org.jnetpcap.PcapDumper)}.
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	@Tag("libpcap-dumper-api")
	void testLoop_PcapDumper_OfflineHandle(TestInfo info) throws PcapException, IOException {
		final var pcap = pcapOpenOfflineTestHandle();
		final var TEMP_DUMP_FILENAME = tempDumpFile(info).getAbsolutePath();

		final int PACKET_COUNT = 5;
		final int LOOP_OK_STATUS = 0;

		try (PcapDumper dumper = pcap.dumpOpen(TEMP_DUMP_FILENAME)) {
			assertEquals(LOOP_OK_STATUS, pcap.loop(PACKET_COUNT, dumper));
		}
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#majorVersion()}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testMajorVersion_OfflineHandle() throws PcapException {
		var pcap = pcapOpenOfflineTestHandle();

		final int MAJOR_VERSION = 2;

		assertEquals(MAJOR_VERSION, pcap.majorVersion());
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#minorVersion()}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testMinorVersion() throws PcapException {
		var pcap = pcapOpenOfflineTestHandle();

		final int MINOR_VERSION = 4;

		assertEquals(MINOR_VERSION, pcap.minorVersion());
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#next(java.util.function.Consumer)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testNext_OfflineHandle() throws PcapException {
		var pcap = pcapOpenOfflineTestHandle();

		PcapPacketRef PACKET_REF = pcap.next();

		assertNotNull(PACKET_REF.header());
		assertNotNull(PACKET_REF.data());
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#nextEx()}.
	 * 
	 * @throws PcapException
	 * @throws TimeoutException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testNextEx_OfflineHandle() throws PcapException, TimeoutException {
		var pcap = pcapOpenOfflineTestHandle();

		PcapPacketRef ref = pcap.nextEx();

		assertNotEquals(MemoryAddress.NULL, ref.header());
		assertNotEquals(MemoryAddress.NULL, ref.data());
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#offlineFilter(org.jnetpcap.BpFilter, java.lang.foreign.MemoryAddress, java.lang.foreign.MemoryAddress)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("user-permission")
	void testOfflineFilter() throws PcapException {

		/* define our parameters to compile the filter string */
		final int SNAPLEN = MAX_SNAPLEN;
		final PcapDlt DLT = PcapDlt.EN10MB;
		final String FILTER_STR = "tcp";
		final boolean OPTIMIZE = false;
		final int NETMASK = PCAP_NETMASK_UNKNOWN;

		/*
		 * Compile our filter string and close the filter when we're done (free filter
		 * native memory managed by BpFilter class)
		 */
		try (BpFilter filter = Pcap.compileNoPcap(SNAPLEN, DLT, FILTER_STR, OPTIMIZE, NETMASK);
				var scope = MemorySession.openShared()) {

			final TestPacket packet = templates.tcpPacket(scope);
			final MemorySegment HEADER = packet.header();
			final MemorySegment PACKET = packet.data();

			/* If everything went right, we should match on our TCP packet */
			assertTrue(Pcap.offlineFilter(filter, HEADER, PACKET), filter.toString());
		}
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#openDead(org.jnetpcap.constant.PcapDlt, int)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testOpenDead() throws PcapException {
		final PcapDlt DTL = PcapDlt.EN10MB;
		final int SNAPLEN = MAX_SNAPLEN;

		try (Pcap pcap = Pcap.openDead(DTL, SNAPLEN)) {
			assertNotNull(pcap);
		}
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#openDeadWithTstampPrecision(org.jnetpcap.constant.PcapDlt, int, org.jnetpcap.constant.PcapTStampPrecision)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testOpenDeadWithTstampPrecision() throws PcapException {
		final PcapDlt DTL = PcapDlt.EN10MB;
		final int SNAPLEN = MAX_SNAPLEN;
		final PcapTStampPrecision TSTAMP_PRECISION = PcapTStampPrecision.TSTAMP_PRECISION_MICRO;

		try (Pcap pcap = Pcap.openDeadWithTstampPrecision(DTL, SNAPLEN, TSTAMP_PRECISION)) {
			assertNotNull(pcap);
		}
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#openLive(java.lang.String, int, boolean, long, java.util.concurrent.TimeUnit)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	void testOpenLive() throws PcapException {
		var pcapIf = Pcap.findAllDevs().get(0);

		final String DEVICE = pcapIf.name();
		final int SNAPLEN = MAX_SNAPLEN;
		final boolean PROMISC = true;
		final int TIMEOUT = 1000;
		final TimeUnit UNIT = MILLISECONDS;

		try (Pcap pcap = Pcap.openLive(DEVICE, SNAPLEN, PROMISC, TIMEOUT, UNIT)) {
			assertNotNull(pcap);
		}
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#openOffline(java.lang.String)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testOpenOffline() throws PcapException {
		try (Pcap pcap = Pcap.openOffline(OFFLINE_FILE)) {
			assertNotNull(pcap);
		}
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#order()}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testOrder() throws PcapException {
		var pcap = super.pcapOpenOfflineTestHandle();

		final ByteOrder ORDER = ByteOrder.nativeOrder();

		assertEquals(ORDER, pcap.order());
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#perror(java.lang.String)}.
	 * 
	 * @throws PcapException
	 */
	@Disabled
	void testPerror() throws PcapException {
		fail("Not implemented, too obscure to try to get stdout from native library into junit");
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#sendPacket(java.lang.foreign.Addressable, int)}.
	 * 
	 * @throws PcapException
	 * @throws ExecutionException
	 * @throws InterruptedException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	@Tag("live-network-with-packets")
	@Tag("active-test")
	void testSendPacket_MemorySegment_IntoLiveNetwork() throws PcapException, InterruptedException, ExecutionException {
		final long TRANSMIT_DELAY_IN_MILLIS = 250;
		final int TRANSMIT_RETRIES_COUNT = 20;

		var captureHandle = super.pcapCreateTestHandle();
		captureHandle.setTimeout(1000).activate();
		captureHandle.setDirection(PcapDirection.DIRECTION_OUT);

		var transmitHandle = super.pcapCreateTestHandle();
		transmitHandle.activate();

		var transmitter = super.setupPacketTransmitter(
				templates::tcpPacket /* packet factory */,
				(pkt, pktSize) -> Assertions /* Unit test */
						.assertDoesNotThrow(() -> transmitHandle.sendPacket(pkt, pktSize)));

		TestPacket sentPacket = transmitter.getPacket();
		byte[] sentSrcAddress = sentPacket.ipSrc();

		byte[] SENT_PACKET = sentPacket.toArray();
		byte[] CAPTURED_PACKET = null;

		int loopCounter = TRANSMIT_RETRIES_COUNT;
		while (loopCounter-- > 0) {
			try (var joinOnAutoClose = transmitter.transmitPacketWithDelay(TRANSMIT_DELAY_IN_MILLIS);
					var pcapScope = MemorySession.openShared()) {

				/* do capture */
				var packet = fromPcapPacketRef(captureHandle.next(), pcapScope);

				/* Check if we have the just transmitted packet */
				if ((packet != null) && Arrays.equals(sentSrcAddress, packet.ipSrc())) {
					CAPTURED_PACKET = packet.toArray();
					break;
				}
			}
		}

		assertNotNull(CAPTURED_PACKET,
				"unable to capture the sent packet for verification of transmission after %d tries"
						.formatted(TRANSMIT_RETRIES_COUNT));

		assertArrayEquals(SENT_PACKET, CAPTURED_PACKET,
				"unable to capture the transmitted packet after %d tries"
						.formatted(TRANSMIT_RETRIES_COUNT));

	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#sendPacket(byte[])}.
	 * 
	 * @throws PcapException
	 * @throws ExecutionException
	 * @throws InterruptedException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	@Tag("live-network-with-packets")
	@Tag("active-test")
	void testSendPacket_ByteArray_IntoLiveNetwork() throws PcapException, InterruptedException, ExecutionException {
		final long TRANSMIT_DELAY_IN_MILLIS = 250;
		final int TRANSMIT_RETRIES_COUNT = 20;
		final byte[] template = templates.tcpArray();
		final byte[] inputPacketData = Arrays.copyOf(template, template.length);

		var captureHandle = super.pcapCreateTestHandle();
		captureHandle.setTimeout(1000).activate();
		captureHandle.setDirection(PcapDirection.DIRECTION_OUT);

		var transmitHandle = super.pcapCreateTestHandle();
		transmitHandle.activate();

		var transmitter = super.setupPacketTransmitter(() -> Assertions /* Unit test */
				.assertDoesNotThrow(() -> transmitHandle.sendPacket(inputPacketData)));

		byte[] sentSrcAddress = Arrays.copyOfRange(template, SRC_IP_OFFSET, SRC_IP_OFFSET + IP_ADDR_LEN);

		byte[] SENT_PACKET = inputPacketData;
		byte[] CAPTURED_PACKET = null;

		int loopCounter = TRANSMIT_RETRIES_COUNT;
		while (loopCounter-- > 0) {
			try (var joinOnAutoClose = transmitter.transmitPacketWithDelay(TRANSMIT_DELAY_IN_MILLIS);
					var pcapScope = MemorySession.openShared()) {

				/* do capture */
				var packet = fromPcapPacketRef(captureHandle.next(), pcapScope);

				/* Check if we have the just transmitted packet */
				if ((packet != null) && Arrays.equals(sentSrcAddress, packet.ipSrc())) {
					CAPTURED_PACKET = packet.toArray();
					break;
				}
			}
		}

		assertNotNull(CAPTURED_PACKET,
				"unable to capture the sent packet for verification of transmission after %d tries"
						.formatted(TRANSMIT_RETRIES_COUNT));

		assertArrayEquals(SENT_PACKET, CAPTURED_PACKET,
				"unable to capture the transmitted packet after %d tries"
						.formatted(TRANSMIT_RETRIES_COUNT));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#sendPacket(byte[], int, int)}.
	 * 
	 * @throws PcapException
	 * @throws ExecutionException
	 * @throws InterruptedException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	@Tag("live-network-with-packets")
	@Tag("active-test")
	void testSendPacket_ByteArrayOffset_IntoLiveNetwork() throws PcapException, InterruptedException,
			ExecutionException {
		final long TRANSMIT_DELAY_IN_MILLIS = 250;
		final int TRANSMIT_RETRIES_COUNT = 20;
		final int BUFFER_SIZE = 1024 * 1024; // 1MB
		final byte[] template = templates.tcpArray();
		final int packetLength = template.length;

		final byte[] buffer = new byte[BUFFER_SIZE];
		final int offset = new Random().nextInt(0, BUFFER_SIZE - packetLength);
		System.arraycopy(template, 0, buffer, offset, packetLength);

		var captureHandle = super.pcapCreateTestHandle();
		captureHandle.setTimeout(1000).activate();
		captureHandle.setDirection(PcapDirection.DIRECTION_OUT);

		var transmitHandle = super.pcapCreateTestHandle();
		transmitHandle.activate();

		var transmitter = super.setupPacketTransmitter(() -> Assertions /* Unit test */
				.assertDoesNotThrow(() -> transmitHandle.sendPacket(buffer, offset, packetLength)));

		byte[] sentSrcAddress = Arrays.copyOfRange(template, SRC_IP_OFFSET, SRC_IP_OFFSET + IP_ADDR_LEN);

		byte[] SENT_PACKET = template;
		byte[] CAPTURED_PACKET = null;

		int loopCounter = TRANSMIT_RETRIES_COUNT;
		while (loopCounter-- > 0) {
			try (var joinOnAutoClose = transmitter.transmitPacketWithDelay(TRANSMIT_DELAY_IN_MILLIS);
					var pcapScope = MemorySession.openShared()) {

				/* do capture */
				var packet = fromPcapPacketRef(captureHandle.next(), pcapScope);

				/* Check if we have the just transmitted packet */
				if ((packet != null) && Arrays.equals(sentSrcAddress, packet.ipSrc())) {
					CAPTURED_PACKET = packet.toArray();
					break;
				}
			}
		}

		assertNotNull(CAPTURED_PACKET,
				"unable to capture the sent packet for verification of transmission after %d tries"
						.formatted(TRANSMIT_RETRIES_COUNT));

		assertArrayEquals(SENT_PACKET, CAPTURED_PACKET,
				"unable to capture the transmitted packet after %d tries"
						.formatted(TRANSMIT_RETRIES_COUNT));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#sendPacket(java.nio.ByteBuffer)}.
	 * 
	 * @throws PcapException
	 * @throws ExecutionException
	 * @throws InterruptedException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	@Tag("live-network-with-packets")
	@Tag("active-test")
	void testSendPacket_ArrayByteBuffer_IntoLiveNetwork() throws PcapException, InterruptedException,
			ExecutionException {
		final long TRANSMIT_DELAY_IN_MILLIS = 250;
		final int TRANSMIT_RETRIES_COUNT = 20;
		final byte[] template = templates.tcpArray();
		final ByteBuffer buffer = ByteBuffer.wrap(template);

		var captureHandle = super.pcapCreateTestHandle();
		captureHandle.setTimeout(1000).activate();
		captureHandle.setDirection(PcapDirection.DIRECTION_OUT);

		var transmitHandle = super.pcapCreateTestHandle();
		transmitHandle.activate();

		var transmitter = super.setupPacketTransmitter(() -> Assertions /* Unit test */
				.assertDoesNotThrow(() -> transmitHandle.sendPacket(buffer)));

		byte[] sentSrcAddress = Arrays.copyOfRange(template, SRC_IP_OFFSET, SRC_IP_OFFSET + IP_ADDR_LEN);

		byte[] SENT_PACKET = template;
		byte[] CAPTURED_PACKET = null;

		int loopCounter = TRANSMIT_RETRIES_COUNT;
		while (loopCounter-- > 0) {
			try (var joinOnAutoClose = transmitter.transmitPacketWithDelay(TRANSMIT_DELAY_IN_MILLIS);
					var pcapScope = MemorySession.openShared()) {

				/* do capture */
				var packet = fromPcapPacketRef(captureHandle.next(), pcapScope);

				/* Check if we have the just transmitted packet */
				if ((packet != null) && Arrays.equals(sentSrcAddress, packet.ipSrc())) {
					CAPTURED_PACKET = packet.toArray();
					break;
				}
			}
		}

		assertNotNull(CAPTURED_PACKET,
				"unable to capture the sent packet for verification of transmission after %d tries"
						.formatted(TRANSMIT_RETRIES_COUNT));

		assertArrayEquals(SENT_PACKET, CAPTURED_PACKET,
				"unable to capture the transmitted packet after %d tries"
						.formatted(TRANSMIT_RETRIES_COUNT));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#inject(java.nio.ByteBuffer)}.
	 * 
	 * @throws PcapException
	 * @throws ExecutionException
	 * @throws InterruptedException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	@Tag("live-capture")
	@Tag("sudo-permission")
	@Tag("live-network-with-packets")
	@Tag("active-test")
	void testSendPacket_NativeByteBuffer_IntoLiveNetwork() throws PcapException, InterruptedException,
			ExecutionException {
		final long TRANSMIT_DELAY_IN_MILLIS = 250;
		final int TRANSMIT_RETRIES_COUNT = 20;
		final byte[] template = templates.tcpArray();
		final ByteBuffer buffer = ByteBuffer.allocateDirect(template.length);
		buffer.put(template).flip();

		var captureHandle = super.pcapCreateTestHandle();
		captureHandle.setTimeout(1000).activate();
		captureHandle.setDirection(PcapDirection.DIRECTION_OUT);

		var transmitHandle = super.pcapCreateTestHandle();
		transmitHandle.activate();

		var transmitter = super.setupPacketTransmitter(() -> Assertions /* Unit test */
				.assertDoesNotThrow(() -> transmitHandle.sendPacket(buffer)));

		byte[] sentSrcAddress = Arrays.copyOfRange(template, SRC_IP_OFFSET, SRC_IP_OFFSET + IP_ADDR_LEN);

		byte[] SENT_PACKET = template;
		byte[] CAPTURED_PACKET = null;

		int loopCounter = TRANSMIT_RETRIES_COUNT;
		while (loopCounter-- > 0) {
			try (var joinOnAutoClose = transmitter.transmitPacketWithDelay(TRANSMIT_DELAY_IN_MILLIS);
					var pcapScope = MemorySession.openShared()) {

				/* do capture */
				var packet = fromPcapPacketRef(captureHandle.next(), pcapScope);

				/* Check if we have the just transmitted packet */
				if ((packet != null) && Arrays.equals(sentSrcAddress, packet.ipSrc())) {
					CAPTURED_PACKET = packet.toArray();
					break;
				}
			}
		}

		assertNotNull(CAPTURED_PACKET,
				"unable to capture the sent packet for verification of transmission after %d tries"
						.formatted(TRANSMIT_RETRIES_COUNT));

		assertArrayEquals(SENT_PACKET, CAPTURED_PACKET,
				"unable to capture the transmitted packet after %d tries"
						.formatted(TRANSMIT_RETRIES_COUNT));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#setBufferSize(int)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("live-capture")
	@Tag("user-permission")
	void testSetBufferSize() throws PcapException {
		var pcap = super.pcapCreateTestHandle();

		final int BUFFER_SIZE = 1024 * 1024;

		assertDoesNotThrow(() -> pcap.setBufferSize(BUFFER_SIZE));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#setBufferSize(int)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	void testSetBufferSize_AfterActivate() throws PcapException {
		var pcap = super.pcapCreateTestHandle();

		final int BUFFER_SIZE = 1024 * 1024;

		pcap.activate();

		/* can't set after already activated */
		assertThrows(PcapException.class, () -> pcap.setBufferSize(BUFFER_SIZE));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#setDatalink(int)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	void testSetDatalink() throws PcapException {
		var pcap = super.pcapCreateTestHandle();

		pcap.activate();

		final PcapDlt DTL = PcapDlt.EN10MB;

		assertDoesNotThrow(() -> pcap.setDatalink(DTL), pcap.toString());
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#setDirection(int)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	void testSetDirection() throws PcapException {
		var pcap = super.pcapCreateTestHandle();

		pcap.activate();

		final PcapDirection DIRECTION = PcapDirection.DIRECTION_IN;

		assertDoesNotThrow(() -> pcap.setDirection(DIRECTION));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#setFilter(org.jnetpcap.BpFilter)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("offline-capture")
	@Tag("user-permission")
	void testSetFilter() throws PcapException {
		var pcap = super.pcapOpenOfflineTestHandle();

		final String FILTER_STR = "tcp";
		final boolean optimize = true;

		try (BpFilter filter = pcap.compile(FILTER_STR, optimize)) {
			assertDoesNotThrow(() -> pcap.setFilter(filter));
		}
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#setImmediateMode(boolean)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("live-capture")
	@Tag("user-permission")
	void testSetImmediateMode() throws PcapException {
		var pcap = super.pcapCreateTestHandle();

		final boolean ENABLE_IMMEDIATE_MODE = true;

		assertDoesNotThrow(() -> pcap.setImmediateMode(ENABLE_IMMEDIATE_MODE));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#setNonBlock(boolean)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("live-capture")
	@Tag("user-permission")
	void testSetNonBlock() throws PcapException {
		var pcap = super.pcapCreateTestHandle();

		final boolean ENABLE_NON_BLOCK_MODE = true;

		assertDoesNotThrow(() -> pcap.setNonBlock(ENABLE_NON_BLOCK_MODE));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#setPromisc(boolean)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("live-capture")
	@Tag("user-permission")
	void testSetPromisc() throws PcapException {
		var pcap = super.pcapCreateTestHandle();

		final boolean ENABLE_PROMISCOUS_MODE = true;

		assertDoesNotThrow(() -> pcap.setPromisc(ENABLE_PROMISCOUS_MODE));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#setRfmon(boolean)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("live-capture")
	@Tag("user-permission")
	void testSetRfmon() throws PcapException {
		var pcap = super.pcapCreateTestHandle();

		final boolean ENABLE_PROMISCOUS_MODE = true;

		assertDoesNotThrow(() -> pcap.setPromisc(ENABLE_PROMISCOUS_MODE));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#setSnaplen(int)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("live-capture")
	@Tag("user-permission")
	void testSetSnaplen() throws PcapException {
		var pcap = super.pcapCreateTestHandle();

		final int SNAPLEN = MAX_SNAPLEN;

		assertDoesNotThrow(() -> pcap.setSnaplen(SNAPLEN));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#setTimeout(int)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("live-capture")
	@Tag("user-permission")
	void testSetTimeout() throws PcapException {
		var pcap = super.pcapCreateTestHandle();

		final int TIMEOUT = MAX_SNAPLEN;

		assertDoesNotThrow(() -> pcap.setTimeout(TIMEOUT));
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#setTstampPrecision(org.jnetpcap.constant.PcapTStampPrecision)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("live-capture")
	@Tag("user-permission")
	void testSetTstampPrecision() throws PcapException {
		var pcap = super.pcapCreateTestHandle();

		final PcapTStampPrecision TSTAMP_PRECISION = PcapTStampPrecision.TSTAMP_PRECISION_MICRO;

		assertDoesNotThrow(() -> pcap.setTstampPrecision(TSTAMP_PRECISION));
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#setTstampType(org.jnetpcap.constant.PcapTstampType)}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("live-capture")
	@Tag("user-permission")
	void testSetTstampType() throws PcapException {
		var pcap = super.pcapCreateTestHandle();

		final PcapTstampType TSTAMP_TYPE = PcapTstampType.TSTAMP_TYPE_HOST;

		assertDoesNotThrow(() -> pcap.setTstampType(TSTAMP_TYPE));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#snapshot()}.
	 * 
	 * @throws PcapException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	void testSnapshot() throws PcapException {
		var pcap = super.pcapCreateTestHandle();

		final int SNAPLEN = 16 * 1024;

		pcap.setSnaplen(SNAPLEN);

		pcap.activate();

		assertEquals(SNAPLEN, pcap.snapshot());
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#stats()}.
	 * 
	 * @throws PcapException
	 * @throws InterruptedException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	void testStats_LiveHandle() throws PcapException, InterruptedException {
		var pcap = super.pcapCreateTestHandle();
		pcap.activate();

		/* Check if we're able to collect statistics without any errors */
		assertDoesNotThrow(() -> pcap.stats());
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#stats()}.
	 * 
	 * @throws PcapException
	 * @throws InterruptedException
	 */
	@Test
	@Tag("live-capture")
	@Tag("sudo-permission")
	@Tag("live-network-with-packets")
	void testStats_CollectStatistics_LiveHandle(TestInfo info) throws PcapException,
			InterruptedException {
		var pcap = super.pcapCreateTestHandle();

		pcap.activate();
		pcap.stats(); // Prime the statistics engine

		final long SLEEP_INTERVAL = 5;
		TimeUnit.SECONDS.sleep(SLEEP_INTERVAL);

		var stats = pcap.stats();

		assertTrue(false

				|| stats.recv() > 0
				|| stats.drop() > 0
				|| stats.capt() > 0
				|| stats.sent() > 0
				|| stats.netdrop() > 0,
				"Did not collect any statistics in %d second interval"
						.formatted(SLEEP_INTERVAL)

		);
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#statusToStr(org.jnetpcap.constant.PcapCode)}.
	 */
	@Test
	@Tag("user-permission")
	void testStatusToStr() {
		final String STATUS_STR = "Loop terminated by pcap_breakloop";

		assertEquals(STATUS_STR, Pcap.statusToStr(PCAP_ERROR_BREAK));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#strerror(int)}.
	 */
	@Test
	@Tag("user-permission")
	void testStrerror() {
		final String SYSTEM_ERROR_STR = "No such file or directory";
		final int NO_SUCH_FILE_ERROR = 2;

		assertEquals(SYSTEM_ERROR_STR, Pcap.strerror(NO_SUCH_FILE_ERROR));
	}

}
