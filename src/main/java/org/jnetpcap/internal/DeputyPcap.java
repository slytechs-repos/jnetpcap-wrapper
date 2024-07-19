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
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import org.jnetpcap.BpFilter;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapActivatedException;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapHandler.NativeCallback;
import org.jnetpcap.PcapHandler.OfArray;
import org.jnetpcap.PcapHandler.OfMemorySegment;
import org.jnetpcap.PcapStat;
import org.jnetpcap.constant.PcapDirection;
import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.constant.PcapTStampPrecision;
import org.jnetpcap.constant.PcapTstampType;
import org.jnetpcap.util.PcapPacketRef;

/**
 * The Class NonSealedPcap.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 */
public non-sealed class DeputyPcap<T extends Pcap> extends Pcap {

	private final Pcap delegatePcap;

	/**
	 * Instantiates a new non sealed pcap.
	 *
	 * @param pcapHandle the pcap handle
	 */
	protected DeputyPcap(Pcap pcap) {
		super(pcap);
		this.delegatePcap = pcap;
	}

	/**
	 * @throws PcapActivatedException
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#activate()
	 */
	@Override
	public void activate() throws PcapActivatedException, PcapException {
		delegatePcap.activate();
	}

	/**
	 * 
	 * @see org.jnetpcap.Pcap#breakloop()
	 */
	@Override
	public void breakloop() {
		delegatePcap.breakloop();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#canSetRfmon()
	 */
	@Override
	public boolean canSetRfmon() throws PcapException {
		return delegatePcap.canSetRfmon();
	}

	/**
	 * 
	 * @see org.jnetpcap.Pcap#close()
	 */
	@Override
	public void close() {
		delegatePcap.close();
	}

	/**
	 * @param str
	 * @param optimize
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#compile(java.lang.String, boolean)
	 */
	@Override
	public BpFilter compile(String str, boolean optimize) throws PcapException {
		return delegatePcap.compile(str, optimize);
	}

	/**
	 * @param str
	 * @param optimize
	 * @param netmask
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#compile(java.lang.String, boolean, int)
	 */
	@Override
	public BpFilter compile(String str, boolean optimize, int netmask) throws PcapException {
		return delegatePcap.compile(str, optimize, netmask);
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#datalink()
	 */
	@Override
	public PcapDlt datalink() throws PcapException {
		return delegatePcap.datalink();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#dataLinkExt()
	 */
	@Override
	public PcapDlt dataLinkExt() throws PcapException {
		return delegatePcap.dataLinkExt();
	}

	/**
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @see org.jnetpcap.Pcap#dispatch(int, org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemorySegment)
	 */
	@Override
	public int dispatch(int count, NativeCallback handler, MemorySegment user) {
		return delegatePcap.dispatch(count, handler, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#dispatch(int, org.jnetpcap.PcapHandler.OfArray,
	 *      java.lang.Object)
	 */
	@Override
	public <U> int dispatch(int count, OfArray<U> handler, U user) throws PcapException {
		return delegatePcap.dispatch(count, handler, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#dispatch(int,
	 *      org.jnetpcap.PcapHandler.OfMemorySegment, java.lang.Object)
	 */
	@Override
	public <U> int dispatch(int count, OfMemorySegment<U> handler, U user) throws PcapException {
		return delegatePcap.dispatch(count, handler, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param pcapDumper
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#dispatch(int, org.jnetpcap.PcapDumper)
	 */
	@Override
	public <U> int dispatch(int count, PcapDumper pcapDumper) throws PcapException {
		return delegatePcap.dispatch(count, pcapDumper);
	}

	/**
	 * @param fname
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#dumpOpen(java.lang.String)
	 */
	@Override
	public PcapDumper dumpOpen(String fname) throws PcapException {
		return delegatePcap.dumpOpen(fname);
	}

	/**
	 * @param obj
	 * @return
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		return delegatePcap.equals(obj);
	}

	/**
	 * @return
	 * @see org.jnetpcap.Pcap#geterr()
	 */
	@Override
	public String geterr() {
		return delegatePcap.geterr();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#getNonBlock()
	 */
	@Override
	public boolean getNonBlock() throws PcapException {
		return delegatePcap.getNonBlock();
	}

	/**
	 * @return
	 * @see org.jnetpcap.Pcap#getPcapHeaderABI()
	 */
	@Override
	public PcapHeaderABI getPcapHeaderABI() {
		return delegatePcap.getPcapHeaderABI();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#getTstampPrecision()
	 */
	@Override
	public PcapTStampPrecision getTstampPrecision() throws PcapException {
		return delegatePcap.getTstampPrecision();
	}

	/**
	 * @return
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return delegatePcap.hashCode();
	}

	/**
	 * @param packet
	 * @param length
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#inject(java.lang.foreign.MemorySegment, int)
	 */
	@Override
	public int inject(MemorySegment packet, int length) throws PcapException {
		return delegatePcap.inject(packet, length);
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#isSwapped()
	 */
	@Override
	public boolean isSwapped() throws PcapException {
		return delegatePcap.isSwapped();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#listDataLinks()
	 */
	@Override
	public List<PcapDlt> listDataLinks() throws PcapException {
		return delegatePcap.listDataLinks();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#listTstampTypes()
	 */
	@Override
	public List<PcapTstampType> listTstampTypes() throws PcapException {
		return delegatePcap.listTstampTypes();
	}

	/**
	 * @param <U>
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @see org.jnetpcap.Pcap#loop(int, org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemorySegment)
	 */
	@Override
	public <U> int loop(int count, NativeCallback handler, MemorySegment user) {
		return delegatePcap.loop(count, handler, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#loop(int, org.jnetpcap.PcapHandler.OfArray,
	 *      java.lang.Object)
	 */
	@Override
	public <U> int loop(int count, OfArray<U> handler, U user) throws PcapException {
		return delegatePcap.loop(count, handler, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#loop(int, org.jnetpcap.PcapHandler.OfMemorySegment,
	 *      java.lang.Object)
	 */
	@Override
	public <U> int loop(int count, OfMemorySegment<U> handler, U user) throws PcapException {
		return delegatePcap.loop(count, handler, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param pcapDumper
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#loop(int, org.jnetpcap.PcapDumper)
	 */
	@Override
	public <U> int loop(int count, PcapDumper pcapDumper) throws PcapException {
		return delegatePcap.loop(count, pcapDumper);
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#majorVersion()
	 */
	@Override
	public int majorVersion() throws PcapException {
		return delegatePcap.majorVersion();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#minorVersion()
	 */
	@Override
	public int minorVersion() throws PcapException {
		return delegatePcap.minorVersion();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#next()
	 */
	@Override
	public PcapPacketRef next() throws PcapException {
		return delegatePcap.next();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @throws TimeoutException
	 * @see org.jnetpcap.Pcap#nextEx()
	 */
	@Override
	public PcapPacketRef nextEx() throws PcapException, TimeoutException {
		return delegatePcap.nextEx();
	}

	/**
	 * @param prefix
	 * @return
	 * @see org.jnetpcap.Pcap#perror(java.lang.String)
	 */
	@Override
	public T perror(String prefix) {
		delegatePcap.perror(prefix);
		return us();
	}

	/**
	 * @param packet
	 * @param length
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#sendPacket(java.lang.foreign.MemorySegment, int)
	 */
	@Override
	public void sendPacket(MemorySegment packet, int length) throws PcapException {
		delegatePcap.sendPacket(packet, length);
	}

	/**
	 * @param bufferSize
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setBufferSize(int)
	 */
	@Override
	public T setBufferSize(int bufferSize) throws PcapException {
		return delegate1(delegatePcap::setBufferSize, bufferSize);
	}

	/**
	 * @param dlt
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setDatalink(int)
	 */
	@Override
	public T setDatalink(int dlt) throws PcapException {
		return delegate1(delegatePcap::setDatalink, dlt);
	}

	/**
	 * @param dlt
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setDatalink(java.util.Optional)
	 */
	@Override
	public T setDatalink(Optional<PcapDlt> dlt) throws PcapException {
		return delegate1(delegatePcap::setDatalink, dlt);
	}

	/**
	 * @param dlt
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setDatalink(org.jnetpcap.constant.PcapDlt)
	 */
	@Override
	public T setDatalink(PcapDlt dlt) throws PcapException {
		return delegate1(delegatePcap::setDatalink, dlt);
	}

	/**
	 * @param dir
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setDirection(int)
	 */
	@Override
	public T setDirection(int dir) throws PcapException {
		return delegate1(delegatePcap::setDirection, dir);
	}

	/**
	 * @param dir
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setDirection(java.util.Optional)
	 */
	@Override
	public T setDirection(Optional<PcapDirection> dir) throws PcapException {
		return delegate1(delegatePcap::setDirection, dir);
	}

	/**
	 * @param dir
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setDirection(org.jnetpcap.constant.PcapDirection)
	 */
	@Override
	public T setDirection(PcapDirection dir) throws PcapException {
		return delegate1(delegatePcap::setDirection, dir);
	}

	/**
	 * @param bpfProgram
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setFilter(org.jnetpcap.BpFilter)
	 */
	@Override
	public T setFilter(BpFilter bpfProgram) throws PcapException {
		return delegate1(delegatePcap::setFilter, bpfProgram);
	}

	/**
	 * @param bpfProgram
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setFilter(java.util.Optional)
	 */
	@Override
	public T setFilter(Optional<BpFilter> bpfProgram) throws PcapException {
		return delegate1(delegatePcap::setFilter, bpfProgram);
	}

	/**
	 * @param enable
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setImmediateMode(boolean)
	 */
	@Override
	public T setImmediateMode(boolean enable) throws PcapException {
		return delegate1(delegatePcap::setImmediateMode, enable);
	}

	/**
	 * @param blockMode
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setNonBlock(boolean)
	 */
	@Override
	public T setNonBlock(boolean blockMode) throws PcapException {
		return delegate1(delegatePcap::setNonBlock, blockMode);
	}

	/**
	 * @param promiscousMode
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setPromisc(boolean)
	 */
	@Override
	public T setPromisc(boolean promiscousMode) throws PcapException {
		return delegate1(delegatePcap::setPromisc, promiscousMode);
	}

	/**
	 * @param rfMonitor
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setRfmon(boolean)
	 */
	@Override
	public T setRfmon(boolean rfMonitor) throws PcapException {
		return delegate1(delegatePcap::setRfmon, rfMonitor);
	}

	/**
	 * @param snaplen
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setSnaplen(int)
	 */
	@Override
	public T setSnaplen(int snaplen) throws PcapException {
		return delegate1(delegatePcap::setSnaplen, snaplen);
	}

	/**
	 * @param timeoutInMillis
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setTimeout(int)
	 */
	@Override
	public T setTimeout(int timeoutInMillis) throws PcapException {
		return delegate1(delegatePcap::setTimeout, timeoutInMillis);
	}

	/**
	 * @param precision
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setTstampPrecision(org.jnetpcap.constant.PcapTStampPrecision)
	 */
	@Override
	public T setTstampPrecision(PcapTStampPrecision precision) throws PcapException {
		return delegate1(delegatePcap::setTstampPrecision, precision);
	}

	/**
	 * @param type
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setTstampType(org.jnetpcap.constant.PcapTstampType)
	 */
	@Override
	public T setTstampType(PcapTstampType type) throws PcapException {
		return delegate1(delegatePcap::setTstampType, type);
	}

	/**
	 * @param exceptionHandler
	 * @return
	 * @see org.jnetpcap.Pcap#setUncaughtExceptionHandler(java.util.function.Consumer)
	 */
	@Override
	public T setUncaughtExceptionHandler(Consumer<? super Throwable> exceptionHandler) {
		delegatePcap.setUncaughtExceptionHandler(exceptionHandler);
		return us();
	}

	/**
	 * @param exceptionHandler
	 * @return
	 * @see org.jnetpcap.Pcap#setUncaughtExceptionHandler(java.lang.Thread.UncaughtExceptionHandler)
	 */
	@Override
	public T setUncaughtExceptionHandler(UncaughtExceptionHandler exceptionHandler) {
		delegatePcap.setUncaughtExceptionHandler(exceptionHandler);
		return us();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#snapshot()
	 */
	@Override
	public int snapshot() throws PcapException {
		return delegatePcap.snapshot();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#stats()
	 */
	@Override
	public PcapStat stats() throws PcapException {
		return delegatePcap.stats();
	}

	/**
	 * @return
	 * @see org.jnetpcap.Pcap#toString()
	 */
	@Override
	public String toString() {
		return delegatePcap.toString();
	}

	/**
	 * Adapted this reference.
	 *
	 * @return reference to this object
	 */
	@SuppressWarnings("unchecked")
	private T us() {
		return (T) this;
	}

	protected interface PcapConsumer<U> {
		void accept(U arg) throws PcapException;
	}

	protected <U> T delegate1(PcapConsumer<U> exec, U arg1) throws PcapException {
		exec.accept(arg1);

		return us();
	}
}
