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
package org.jnetpcap.internal;

import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.foreign.MemorySegment;
import java.util.concurrent.TimeoutException;

import org.jnetpcap.PcapException;
import org.jnetpcap.PcapHandler.NativeCallback;
import org.jnetpcap.util.PcapPacketRef;

/**
 * The Interface PcapDispatcher.
 */
public interface PcapDispatcher extends NativeCallback, AutoCloseable {

	/**
	 * Capture length.
	 *
	 * @param address the address
	 * @return the int
	 */
	int captureLength(MemorySegment address);

	/**
	 * Dispatch native.
	 *
	 * @param count   the count
	 * @param handler the handler
	 * @param user    the user
	 * @return the int
	 */
	int dispatchNative(int count, NativeCallback handler, MemorySegment user);

	/**
	 * Dispatch raw.
	 *
	 * @param count        the count
	 * @param callbackFunc the callback func
	 * @param userData     the user data
	 * @return the int
	 */
	int dispatchRaw(int count, MemorySegment callbackFunc, MemorySegment userData);

	/**
	 * Header length.
	 *
	 * @param address the address
	 * @return the int
	 */
	int headerLength(MemorySegment address);

	/**
	 * Loop native.
	 *
	 * @param count   the count
	 * @param handler the handler
	 * @param user    the user
	 * @return the int
	 */
	int loopNative(int count, NativeCallback handler, MemorySegment user);

	/**
	 * Loop raw.
	 *
	 * @param count        the count
	 * @param callbackFunc the callback func
	 * @param userData     the user data
	 * @return the int
	 */
	int loopRaw(int count, MemorySegment callbackFunc, MemorySegment userData);

	/**
	 * Gets the uncaught exception.
	 *
	 * @return the uncaught exception
	 */
	RuntimeException getUncaughtException();

	/**
	 * Sets the uncaught exception handler.
	 *
	 * @param exceptionHandler the new uncaught exception handler
	 */
	void setUncaughtExceptionHandler(UncaughtExceptionHandler exceptionHandler);

	/**
	 * @see java.lang.AutoCloseable#close()
	 */
	@Override
	void close();

	/**
	 * On native callback exception.
	 *
	 * @param e the e
	 */
	void onNativeCallbackException(RuntimeException e);

	/**
	 * Interrupt.
	 */
	void interrupt();

	/**
	 * Pcap header ABI.
	 *
	 * @return the pcap header ABI
	 */
	PcapHeaderABI pcapHeaderABI();

	/**
	 * Next ex.
	 *
	 * @return the pcap packet ref
	 * @throws PcapException    the pcap exception
	 * @throws TimeoutException the timeout exception
	 */
	PcapPacketRef nextEx() throws PcapException, TimeoutException;

	/**
	 * Next.
	 *
	 * @return the pcap packet ref
	 * @throws PcapException the pcap exception
	 */
	PcapPacketRef next() throws PcapException;
}