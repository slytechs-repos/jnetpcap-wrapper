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

import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.foreign.MemoryAddress;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.util.concurrent.TimeoutException;

import org.jnetpcap.PcapException;
import org.jnetpcap.constant.PcapCode;
import org.jnetpcap.util.PcapPacketRef;

import static java.lang.foreign.MemoryAddress.*;
import static java.lang.foreign.MemorySegment.*;
import static java.lang.foreign.MemorySession.*;
import static java.lang.foreign.ValueLayout.*;

/**
 * A proxy PcapHandler, which receives packets from native pcap handle and
 * forwards all packets to the sink java PcapHandler.
 */
public class StandardPcapDispatcher implements PcapDispatcher {

	/**
	 * @see {@code char *pcap_geterr(pcap_t *p)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_geterr;

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

	/**
	 * @see {@code const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_next;

	/**
	 * @see {@code int pcap_next_ex (pcap_t *p, struct pcap_pkthdr **pkt_header,
	 *      const u_char **pkt_data)}
	 * @since libpcap 0.8
	 */
	private static final PcapForeignDowncall pcap_next_ex;

	static {

		try (var foreign = new PcapForeignInitializer(StandardPcapDispatcher.class)) {

			// @formatter:off
			pcap_handler     = foreign.upcall  ("nativeCallback(AAA)V", NativeCallback.class);
			pcap_geterr      = foreign.downcall("pcap_geterr(A)A"); //$NON-NLS-1$
			pcap_dispatch    = foreign.downcall("pcap_dispatch(AIAA)I");
			pcap_loop        = foreign.downcall("pcap_loop(AIAA)I");
			pcap_next        = foreign.downcall("pcap_next(AA)A");
			pcap_next_ex     = foreign.downcall("pcap_next_ex(AAA)I");
		// @formatter:on

		}
	}

	private final MemorySegment pcapCallbackStub;
	private final MemoryAddress pcapHandle;
	private NativeCallback userSink;

	protected final MemorySession session;

	private UncaughtExceptionHandler uncaughtExceptionHandler;
	private RuntimeException uncaughtException;
	private boolean interrupted = false;
	@SuppressWarnings("unused")
	private boolean interruptOnErrors = true;

	private final Runnable breakDispatch;

	private final PcapHeaderABI abi;

	public StandardPcapDispatcher(MemoryAddress pcapHandle, PcapHeaderABI abi, Runnable breakDispatch) {
		this.pcapHandle = pcapHandle;
		this.abi = abi;
		this.breakDispatch = breakDispatch;
		this.session = MemorySession.openShared();
		this.pcapCallbackStub = pcap_handler.virtualStubPointer(this, this.session);
	}

	/**
	 * Gets the last pcap error string.
	 *
	 * @return the err
	 */
	public final String geterr() {
		return pcap_geterr.invokeString(pcapHandle);
	}

	/**
	 * @see org.jnetpcap.internal.PcapDispatcher#captureLength(java.lang.foreign.MemoryAddress)
	 */
	@Override
	public int captureLength(MemoryAddress headerAddress) {
		return abi.captureLength(headerAddress);
	}

	/**
	 * @see java.lang.AutoCloseable#close()
	 */
	@Override
	public void close() {
		if (session.isAlive())
			session.close();
	}

	@Override
	public final int dispatchNative(int count, NativeCallback handler, MemoryAddress user) {
		this.userSink = handler;

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
	 * @return the uncaughtException
	 */
	@Override
	public final RuntimeException getUncaughtException() {
		return uncaughtException;
	}

	private final void handleInterrupt() throws RuntimeException {
		interrupted = false; // Reset flag

		if (uncaughtException != null) {
			throw uncaughtException;
		}
	}

	/**
	 * @see org.jnetpcap.internal.PcapDispatcher#headerLength(java.lang.foreign.MemoryAddress)
	 */
	@Override
	public int headerLength(MemoryAddress headerAddress) {
		return abi.headerLength();
	}

	@Override
	public final void interrupt() {
		this.breakDispatch.run();
		this.interrupted = true;
	}

	@Override
	public final int loopNative(int count, NativeCallback handler, MemoryAddress user) {
		this.userSink = handler;

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
			this.userSink.nativeCallback(user, header, packet);
		} catch (RuntimeException e) {
			onNativeCallbackException(e);
		}
	}

	/**
	 * Called on a native callback exception within the user handler.
	 *
	 * @param e the exception
	 */
	@Override
	public final void onNativeCallbackException(RuntimeException e) {
		this.uncaughtException = e;

		if (uncaughtExceptionHandler != null) {
			var veto = VetoableExceptionHandler.wrap(uncaughtExceptionHandler);
			if (veto.vetoableException(e)) {
				this.uncaughtException = e;
				interrupt();
			}

		} else {
			this.uncaughtException = e;
			interrupt();
		}
	}

	@Override
	public final void setUncaughtExceptionHandler(UncaughtExceptionHandler exceptionHandler) {
		this.uncaughtExceptionHandler = exceptionHandler;
	}

	/**
	 * @see org.jnetpcap.internal.PcapDispatcher#pcapHeaderABI()
	 */
	@Override
	public PcapHeaderABI pcapHeaderABI() {
		return this.abi;
	}

	private final MemorySegment POINTER_TO_POINTER1 = allocateNative(ADDRESS, openImplicit());
	private final MemorySegment POINTER_TO_POINTER2 = allocateNative(ADDRESS, openImplicit());
	private final MemorySegment PCAP_HEADER_BUFFER = MemorySession.openImplicit()
			.allocate(PcapHeaderABI.nativeAbi().headerLength());

	/**
	 * Dynamic non-pcap utility method to convert libpcap error code to a string, by
	 * various fallback methods with an active pcap handle.
	 *
	 * @param error the code
	 * @return the error string
	 */
	protected String getErrorString(int error) {
		String msg = this.geterr();

		return msg;
	}

	/**
	 * @see org.jnetpcap.internal.PcapDispatcher#nextEx()
	 */
	@Override
	public PcapPacketRef nextEx() throws PcapException, TimeoutException {
		int result = pcap_next_ex.invokeInt(
				this::getErrorString,
				pcapHandle,
				POINTER_TO_POINTER1, // hdr_p
				POINTER_TO_POINTER2); // pkt_p

		if (result == 0)
			throw new TimeoutException();

		else if (result == PcapCode.PCAP_ERROR_BREAK)
			return null;

		MemoryAddress hdr = POINTER_TO_POINTER1.get(ADDRESS, 0);
		MemoryAddress pkt = POINTER_TO_POINTER2.get(ADDRESS, 0);

		return new PcapPacketRef(abi, hdr, pkt);
	}

	/**
	 * @see org.jnetpcap.internal.PcapDispatcher#next()
	 */
	@Override
	public PcapPacketRef next() throws PcapException {
		MemorySegment hdr = PCAP_HEADER_BUFFER;
		MemoryAddress pkt = pcap_next.invokeObj(this::geterr, pcapHandle, hdr);

		return (pkt == null) || (pkt == NULL)
				? null
				: new PcapPacketRef(abi, hdr, pkt);
	}
}