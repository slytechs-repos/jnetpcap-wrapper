/*
 * Sly Technologies Free License
 * 
 * Copyright 2023 Sly Technologies Inc.
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
package org.jnetpcap.internal;

import java.lang.foreign.MemoryAddress;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;

/**
 * A proxy PcapHandler, which receives packets from native pcap handle and
 * forwards all packets to the sink java PcapHandler.
 */
public class StandardPcapDispatcher implements PcapDispatcher {

	/**
	 * @see {@code int pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback,
	 *      u_char *user)}
	 * @since libpcap 0.4
	 */
	static final PcapForeignDowncall pcap_dispatch;

	/**
	 * The Constant pcap_loop.
	 *
	 * @see {@code int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char
	 *      *user)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_loop;

	/**
	 * This upcall foreign reference is a callback method that is called to java
	 * from pcap_loop and pcap_dispatch calls.
	 * 
	 * @see {@code typedef void (*pcap_handler)(u_char *user, const struct
	 *      pcap_pkthdr *h, const u_char *bytes);}
	 * @since libpcap 0.4
	 */
	static final ForeignUpcall<NativeCallback> pcap_handler;

	static {

		try (var foreign = new PcapForeignInitializer(StandardPcapDispatcher.class)) {

			// @formatter:off
			pcap_dispatch    = foreign.downcall("pcap_dispatch(AIAA)I");
			pcap_loop        = foreign.downcall("pcap_loop(AIAA)I");
			pcap_handler     = foreign.upcall  ("nativeCallback(AAA)V", NativeCallback.class);
			// @formatter:on

		}
	}

	private static final PcapHeaderABI ABI = PcapHeaderABI.nativeAbi();

	private final MemorySegment pcapCallbackStub;
	private final MemoryAddress pcapHandle;
	private NativeCallback sink;

	protected final MemorySession session;

	private RuntimeException uncaughtException;
	private boolean interrupted = false;
	private boolean interruptOnErrors = true;

	private final Runnable breakDispatch;

	public StandardPcapDispatcher(MemoryAddress pcapHandle, Runnable breakDispatch) {
		this.pcapHandle = pcapHandle;
		this.breakDispatch = breakDispatch;
		this.session = MemorySession.openShared();
		this.pcapCallbackStub = pcap_handler.virtualStubPointer(this, this.session);
	}

	/**
	 * @see org.jnetpcap.internal.PcapDispatcher#captureLength(java.lang.foreign.MemoryAddress)
	 */
	@Override
	public int captureLength(MemoryAddress headerAddress) {
		return ABI.captureLength(headerAddress);
	}

	/**
	 * @see java.lang.AutoCloseable#close()
	 */
	@Override
	public void close() {
		session.close();
	}

	@Override
	public final int dispatchNative(int count, NativeCallback handler, MemoryAddress user) {
		this.sink = handler;

		return dispatchRaw(
				count,
				pcapCallbackStub.address(),
				user);
	}

	/**
	 * @param count
	 * @param callbackFunc
	 * @param userData
	 */
	@Override
	public final int dispatchRaw(int count, MemoryAddress callbackFunc, MemoryAddress userData) {
		int result = pcap_dispatch.invokeInt(
				pcapHandle,
				count,
				callbackFunc,
				userData);

		if (interrupted)
			handleInterrupt();

		return result;
	}

	/**
	 * @see org.jnetpcap.internal.PcapDispatcher#headerLength(java.lang.foreign.MemoryAddress)
	 */
	@Override
	public int headerLength(MemoryAddress headerAddress) {
		return ABI.headerLength();
	}

	private final void interrupt() {
		this.breakDispatch.run();
		this.interrupted = true;
	}

	@Override
	public final int loopNative(int count, NativeCallback handler, MemoryAddress user) {
		this.sink = handler;

		return loopRaw(
				count,
				pcapCallbackStub.address(),
				user);
	}

	/**
	 * @param count
	 * @param callbackFunc
	 * @param userData
	 */
	@Override
	public final int loopRaw(int count, MemoryAddress callbackFunc, MemoryAddress userData) {
		int result = pcap_loop.invokeInt(
				pcapHandle,
				count,
				callbackFunc,
				userData);

		if (interrupted)
			handleInterrupt();

		return result;
	}

	/**
	 * @see org.jnetpcap.Pcap0_4.MemoryAddressCallback#nativeCallback(java.lang.foreign.MemoryAddress,
	 *      java.lang.foreign.MemoryAddress, java.lang.foreign.MemoryAddress)
	 */
	@Override
	public final void nativeCallback(MemoryAddress user, MemoryAddress header, MemoryAddress packet) {
		this.uncaughtException = null; // Reset any previous unclaimed exceptions

		try {
			this.sink.nativeCallback(user, header, packet);
		} catch (RuntimeException e) {
			this.uncaughtException = e;
			interrupt();

		} catch (Throwable e) {
			this.uncaughtException = new IllegalStateException(e);
			interrupt();
		}
	}

	private final void handleInterrupt() throws RuntimeException {
		interrupted = false; // Reset flag
		
		if (uncaughtException != null) {
			throw uncaughtException;
		}
	}

	/**
	 * @return the uncaughtException
	 */
	@Override
	public final RuntimeException getUncaughtException() {
		return uncaughtException;
	}
}