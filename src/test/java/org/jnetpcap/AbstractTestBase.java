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

import java.io.File;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.jnetpcap.AbstractTestBase.TestPacket.PacketTemplates;
import org.jnetpcap.constant.PcapConstants;
import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.internal.PcapHeaderABI;
import org.jnetpcap.internal.UnsafePcapHandle;
import org.jnetpcap.util.PcapPacketRef;
import org.jnetpcap.util.PcapUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.TestInfo;

/**
 * Base class for all Tests in this package. Mainly it facilitates a standard
 * way of opening pcap handles and registering cleanup actions which can be
 * executed in tearnDown after each test and constants.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
@SuppressWarnings("exports")
abstract class AbstractTestBase {

	/**
	 * Execution interface which allows exceptions to be thrown and/or discarded.
	 */
	public interface TestExec {

		/**
		 * Executes and silently discards any errors
		 *
		 * @param exec the execution code
		 */
		static boolean discardErrors(TestExec exec) {
			try {
				exec.execute();
				
				return true;
			} catch (Throwable e) {
				return false;
			}
		}

		void execute() throws Throwable;
	}

	/**
	 * A private packet container using in unit testing with 2 simple fields, header
	 * and data.
	 */
	protected record TestPacket(PcapHeaderABI abi, MemorySegment header, MemorySegment data) {

		public static final int SRC_IP_OFFSET = 14 + 12;
		public static final int DST_IP_OFFSET = 14 + 16;
		public static final int IP_ADDR_LEN = 4;

		public static class PacketTemplates {

			/**
			 * Make a packet from supplied byte array.
			 *
			 * @param dataSupplier the packet template
			 * @param arena        the arena
			 * @return the test packet
			 */
			public TestPacket makePacket(PcapHeaderABI abi, Supplier<byte[]> dataSupplier, Arena arena) {
				final byte[] packetBytes = dataSupplier.get();

				return TestPacket.fromArray(abi, packetBytes, arena);
			}

			/**
			 * Lets make a native packet. Hex stream copied from Wireshark and this is the
			 * decoded output, while changing the IP addresses to both be on non-routable
			 * local-net:
			 * 
			 * <pre>
			Frame 1: 74 bytes on wire (592 bits), 74 bytes captured (592 bits)
			Ethernet II, Src: ASUSTekC_b3:01:84 (00:1d:60:b3:01:84), Dst: Actionte_2f:47:87 (00:26:62:2f:47:87)
			Internet Protocol Version 4, Src: 192.168.253.5, Dst: 192.168.253.6
			Transmission Control Protocol, Src Port: 57678 (57678), Dst Port: http (80), Seq: 0, Len: 0
			 * </pre>
			 */
			public byte[] tcpArray() {

				/* raw bytes of our packet */
				final String ETHERNET = "0026622f4787001d60b301840800";
				final String IPv4 = "4500003ccb5b4000400628e4 c0a8FD05 c0a8FD06";
				final String TCP = "e14e00508e50190100000000a00216d08f470000020405b40402080a0021d25a0000000001030307";
				final byte[] packetBytes = PcapUtils.parseHexString(ETHERNET + IPv4 + TCP);

				return packetBytes;
			}

			/**
			 * Make a TCP test packet suitable for unit testing purposes. IP addresses have
			 * been modified to be on private non-routable network.
			 *
			 * @param arena the arena for native memory allocation
			 * @return the test packet containing a header and data in native memory
			 */
			public TestPacket tcpPacket(PcapHeaderABI abi, Arena arena) {
				return makePacket(abi, this::tcpArray, arena);
			}

		}

		private static MemorySegment createHeaderAsSegment(int length) {
			long epochMillis = System.currentTimeMillis();
			int TV_SEC = (int) (epochMillis / 1000);
			int TV_USEC = (int) ((epochMillis % 1000) + (System.nanoTime() % 1000_1000) / 1000);
			int CAPLEN = length;
			int WIRELEN = length;

			/* lets make our native header structure from values */
			final MemorySegment HEADER = new PcapHeader(TV_SEC, TV_USEC, CAPLEN, WIRELEN).asMemorySegment();

			return HEADER;
		}

		public static TestPacket fromArray(PcapHeaderABI abi, byte[] packetData, Arena arena) {
			return fromArray(abi, packetData, 0, packetData.length, arena);
		}

		public static TestPacket fromArray(PcapHeaderABI abi, byte[] packetData, int offset, int length, Arena arena) {
			MemorySegment packetSegment = arena.allocate(length);
			MemorySegment.copy(packetData, offset, packetSegment, ValueLayout.JAVA_BYTE, 0, length);

			MemorySegment headerSegment = createHeaderAsSegment(length);

			return new TestPacket(abi, headerSegment, packetSegment);
		}

		public static TestPacket fromPcapPacketRef(PcapHeaderABI abi, PcapPacketRef ref, Arena arena) {
			if (ref == null)
				return null;

			var hdr = new PcapHeader(abi, ref.header(), arena);
			var pkt = ref.data().reinterpret(hdr.captureLength(), arena, __ -> {
			});

			return new TestPacket(abi, hdr.asMemorySegment(), pkt);
		}

		public PcapPacketRef getPacket() {
			return new PcapPacketRef(abi, header, data);
		}

		public byte[] toArray() {
			return toArray(0, (int) data.byteSize());
		}

		public byte[] toArray(int offset, int length) {
			byte[] array = new byte[length];

			for (int i = 0; i < length; i++)
				array[i] = data.get(ValueLayout.JAVA_BYTE, offset + i);

			return array;
		}

		public byte[] ipSrc() {
			return toArray(SRC_IP_OFFSET, IP_ADDR_LEN);
		}

		public byte[] ipDst() {
			return toArray(DST_IP_OFFSET, IP_ADDR_LEN);
		}
	}

	/**
	 * Transmitter interface used to unit tests, to create and transmit a packet in
	 * a worker thread. The return value, is the future of the packet that was
	 * transmitted.
	 */
	protected interface TestTransmitter {
		public interface Joinable extends AutoCloseable {

			@Override
			default void close() throws InterruptedException, ExecutionException {
				join();
			}

			void join() throws InterruptedException, ExecutionException;
		}

		void close();

		TestPacket getPacket();

		void join() throws InterruptedException, ExecutionException;

		Joinable transmitPacketWithDelay(long delayInMillis);
	}

	protected static final String OFFLINE_FILE = "src/test/pcaps/HTTP.cap";

	protected Runnable cleanupAction;

	protected final PacketTemplates templates = new PacketTemplates();

	/**
	 * Registers a cleanup action with no specific target.
	 *
	 * @param action the action
	 */
	protected void cleanup(Runnable action) {
		/* Setup a cleanup runner to run the action and consume all errors */
		final Runnable before = cleanupAction;
		this.cleanupAction = () -> {
			try {
				if (before != null)
					before.run();

			} catch (Throwable e) {
				// Discard all errors in cleanup action!
			}

			try {
				action.run();
			} catch (Throwable e) {
				// Discard all errors in cleanup action!
			}
		};
	}

	/**
	 * Registers a cleanup action, that take a target on which the cleanup action
	 * will be taken.
	 *
	 * @param <T>    the generic target type
	 * @param target the target object
	 * @param action the action to perform on the target
	 * @return the target after registering the cleanup action on it
	 */
	protected <T> T cleanup(T target, Consumer<T> action) {
		/* Setup a cleanup runner to run the action and consume all errors */
		final Runnable before = cleanupAction;
		this.cleanupAction = () -> {
			try {
				if (before != null)
					before.run();

			} catch (Throwable e) {
				// Discard all errors in cleanup action!
			}

			try {
				action.accept(target);
			} catch (Throwable e) {
				// Discard all errors in cleanup action!
			}
		};

		return target;
	}

	protected UnsafePcapHandle pcapCreateTestHandle() throws PcapException {
		var pcapIf = Pcap.findAllDevs().get(0);

		return cleanup(UnsafePcapHandle.create(pcapIf.name()), Pcap::close);
	}

	protected Pcap pcapOpenDeadTestHandle() throws PcapException {
		return cleanup(Pcap.openDead(PcapDlt.EN10MB, PcapConstants.MAX_SNAPLEN), Pcap::close);
	}

	protected Pcap pcapOpenLiveTestHandle() throws PcapException {
		var pcapIf = Pcap.findAllDevs().get(0);

		String dev = pcapIf.name();
		int snaplen = PcapConstants.MAX_SNAPLEN;
		boolean promisc = true;
		int timeout = 1000;
		TimeUnit unit = TimeUnit.MILLISECONDS;

		return cleanup(Pcap.openLive(dev, snaplen, promisc, timeout, unit), Pcap::close);
	}

	protected UnsafePcapHandle pcapOpenOfflineTestHandle() throws PcapException {
		return cleanup(UnsafePcapHandle.openOffline(OFFLINE_FILE), Pcap::close);
	}

	/**
	 * Performs all recorded cleanup actions. The cleanup actions are reset after
	 * this call. This call is safe to call multiple times without any side effects.
	 * 
	 * <p>
	 * Clean up actions make sure that mandatory actions are performed after each
	 * test. For example pcap handles need to be closed to prevent resource leaks
	 * from native library, if test failure occurs before the Pcap.close can be
	 * called, etc.
	 * </p>
	 *
	 * @param info information about the test so we can include a bit of where this
	 *             happened
	 * @throws IllegalStateException thrown if an exception, which should've been
	 *                               supressed by the cleanup runner, where
	 *                               detected. This should not happen as cleanup
	 *                               actions are expected to throw lots of
	 *                               exceptions, but those should be consumed by the
	 *                               cleanup runner and never get out here.
	 */
	@AfterEach
	void runCleanupActions(TestInfo info) throws IllegalStateException {
		try {
			if (cleanupAction != null)
				cleanupAction.run();

		} catch (Throwable e) {
			throw new IllegalStateException(
					"%s: cleanup action threw an error, this should not happen".formatted(info.getDisplayName()), e);
		} finally {
			/* Reset cleanup */
			cleanupAction = null;
		}
	}

	/**
	 * Setup packet transmitter from a worker thread. A new packet is generated for
	 * each call to TestTransmitter.transmitWithDelay() and the packet is also
	 * returned.
	 * 
	 * The transmitter auto cleans up after itself when the test completes.
	 * 
	 * @param sendAction the test specific transmit action such as pcap.send or
	 *                   pcap.inject, etc. Can wrap in junit assert* method as well.
	 *
	 * @return the test transmitter
	 */
	protected TestTransmitter setupPacketTransmitter(PcapHeaderABI abi,
			BiFunction<PcapHeaderABI, Arena, TestPacket> packetFactory, BiConsumer<MemorySegment, Integer> sendAction) {
		final Arena arena = Arena.ofShared();
		final TestPacket packetToSend = packetFactory.apply(abi, arena);

		final ScheduledExecutorService scheduleExecutor = Executors.newScheduledThreadPool(1);

		return cleanup(new TestTransmitter() {

			Future<TestPacket> future;

			@Override
			public void close() {
				arena.close();
				scheduleExecutor.close();
			}

			@Override
			public TestPacket getPacket() {
				return packetToSend;
			}

			@Override
			public void join() throws InterruptedException, ExecutionException {
				if (future != null)
					future.get();

			}

			@Override
			public Joinable transmitPacketWithDelay(long delayInMillis) {
				future = scheduleExecutor.schedule(() -> {

					sendAction.accept(packetToSend.data, (int) packetToSend.data.byteSize());

					return packetToSend;
				}, delayInMillis, TimeUnit.MILLISECONDS);

				return () -> future.get();
			}

		}, TestTransmitter::close);
	}

	/**
	 * Setup packet transmitter from a worker thread. A new packet is generated for
	 * each call to TestTransmitter.transmitWithDelay() and the packet is also
	 * returned.
	 * 
	 * The transmitter auto cleans up after itself when the test completes.
	 * 
	 * @param sendAction the test specific transmit action such as pcap.send or
	 *                   pcap.inject, etc. Can wrap in junit assert* method as well.
	 *
	 * @return the test transmitter
	 */
	protected TestTransmitter setupPacketTransmitter(Runnable sendAction) {
		final ScheduledExecutorService scheduleExecutor = Executors.newScheduledThreadPool(1);

		return cleanup(new TestTransmitter() {

			Future<TestPacket> future;

			@Override
			public void close() {
				scheduleExecutor.close();
			}

			@Override
			public TestPacket getPacket() {
				return null;
			}

			@Override
			public void join() throws InterruptedException, ExecutionException {
				if (future != null)
					future.get();
			}

			@Override
			public Joinable transmitPacketWithDelay(long delayInMillis) {
				future = scheduleExecutor.schedule(() -> {

					sendAction.run();

					return null;
				}, delayInMillis, TimeUnit.MILLISECONDS);

				return () -> future.get();
			}
		}, TestTransmitter::close);
	}

	protected static final Random RANDOM = new Random();
	protected static final String TEST_RUN_ID = "%x".formatted(System.currentTimeMillis() / 1000);

	protected File tempFile(TestInfo info, String suffix) throws IOException {
		final String PREFIX = "%s_%s".formatted(info.getTestMethod().orElseThrow().getName(),
				info.getTestClass().orElseThrow().getSimpleName());
		final Path DIR_PATH = Path.of("target/test_tmp_files");
		final File DIR_FILE = DIR_PATH.toFile();
		final String FILENAME = "test_%s-%s.%s".formatted(TEST_RUN_ID, PREFIX, suffix);
		File tempFile = Path.of(DIR_PATH.toString(), FILENAME).toFile();

		if (!DIR_FILE.exists())
			Files.createDirectory(DIR_PATH);

//		tempFile.deleteOnExit();

		return tempFile;
	}

	protected File tempDumpFile(TestInfo info) throws IOException {
		final String SUFFIX = "cap";

		return tempFile(info, SUFFIX);
	}

}
