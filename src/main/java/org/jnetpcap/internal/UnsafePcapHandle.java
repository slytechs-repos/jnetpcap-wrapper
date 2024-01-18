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

import java.lang.foreign.MemorySegment;

import org.jnetpcap.Pcap0_4;
import org.jnetpcap.Pcap1_0;
import org.jnetpcap.Pcap1_10;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapHandler;
import org.jnetpcap.constant.PcapDlt;

/**
 * Non public unsafe Pcap handle mainly needed for jUnit testing.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public non-sealed class UnsafePcapHandle extends Pcap1_10 {
	
	/**
	 * Make dead handle name.
	 *
	 * @param dlt the dlt
	 * @return the string
	 */
	public static String makeDeadHandleName(PcapDlt dlt) {
		return "dead-" + dlt.name().toLowerCase();
	}

	/**
	 * Make live handle name.
	 *
	 * @param device the device
	 * @return the string
	 */
	public static String makeLiveHandleName(String device) {
		return device;
	}

	/**
	 * Make offline handle name.
	 *
	 * @param fname the fname
	 * @return the string
	 */
	public static String makeOfflineHandleName(String fname) {
		return fname;
	}

	/**
	 * Open a saved capture file for reading.
	 * 
	 * <p>
	 * pcap_open_offline() and pcap_open_offline_with_tstamp_precision() are called
	 * to open a ``savefile'' for reading.
	 * </p>
	 *
	 * @param fname specifies the name of the file to open. The file can have the
	 *              pcap file format as described in pcap-savefile(5), which is the
	 *              file format used by, among other programs, tcpdump(1) and
	 *              tcpslice(1), or can have the pcapng file format, although not
	 *              all pcapng files can be read
	 * @return the pcap handle
	 * @throws PcapException any errors
	 * @since libpcap 0.4
	 */
	public static UnsafePcapHandle openOffline(String fname) throws PcapException {
		return Pcap0_4.openOffline(UnsafePcapHandle::new, fname);
	}

	/**
	 * Create a live capture handle.
	 * 
	 * {@code create} is used to create a packet capture handle to look at packets
	 * on the network. source is a string that specifies the network device to open;
	 * on Linux systems with 2.2 or later kernels, a source argument of "any" or
	 * NULL can be used to capture packets from all interfaces. The returned handle
	 * must be activated with pcap_activate() before pack' ets can be captured with
	 * it; options for the capture, such as promiscu' ous mode, can be set on the
	 * handle before activating it.
	 *
	 * @author Sly Technologies, Inc.
	 * @param device a string that specifies the network device to open; on Linux
	 *               systems with 2.2 or later kernels, a source argument of "any"
	 *               or NULL can be used to capture packets from all interfaces.
	 * @return a new pcap object that needs to be activated using
	 *         {@link #activate()} call
	 * @throws PcapException the pcap exception
	 * @since libpcap 1.0
	 */
	public static UnsafePcapHandle create(String device) throws PcapException {
		return Pcap1_0.create(UnsafePcapHandle::new, device);
	}

	/**
	 * Instantiates a new unsafe pcap handle.
	 *
	 * @param pcapHandle the pcap handle
	 * @param name       the name
	 * @param abi        the abi
	 */
	protected UnsafePcapHandle(MemorySegment pcapHandle, String name, PcapHeaderABI abi) {
		super(pcapHandle, name, abi);
	}

	/**
	 * Address.
	 *
	 * @return the memory segment
	 */
	public MemorySegment address() {
		return getPcapHandle();
	}

	/**
	 * Process packets from a live capture or savefile.
	 * 
	 * <p>
	 * Processes packets from a live capture or ``savefile'' until cnt packets are
	 * processed, the end of the current bufferful of packets is reached when doing
	 * a live capture, the end of the ``savefile'' is reached when reading from a
	 * ``savefile'', pcap_breakloop() is called, or an error occurs. Thus, when
	 * doing a live capture, cnt is the maximum number of packets to process before
	 * returning, but is not a minimum number; when reading a live capture, only one
	 * bufferful of packets is read at a time, so fewer than cnt packets may be
	 * processed. A value of -1 or 0 for cnt causes all the packets received in one
	 * buffer to be processed when reading a live capture, and causes all the
	 * packets in the file to be processed when reading a ``savefile''.
	 * </p>
	 * 
	 * <p>
	 * Note that, when doing a live capture on some platforms, if the read timeout
	 * expires when there are no packets available, pcap_dispatch() will return 0,
	 * even when not in non-blocking mode, as there are no packets to process.
	 * Applications should be prepared for this to happen, but must not rely on it
	 * happening.
	 * </p>
	 * 
	 * <p>
	 * Callback specifies a pcap_handler routine to be called with three arguments:
	 * a u_char pointer which is passed in the user argument to pcap_loop() or
	 * pcap_dispatch(), a const struct pcap_pkthdr pointer pointing to the packet
	 * time stamp and lengths, and a const u_char pointer to the first caplen (as
	 * given in the struct pcap_pkthdr a pointer to which is passed to the callback
	 * routine) bytes of data from the packet. The struct pcap_pkthdr and the packet
	 * data are not to be freed by the callback routine, and are not guaranteed to
	 * be valid after the callback routine returns; if the full needs them to be
	 * valid after the callback, it must make a copy of them.
	 * </p>
	 * 
	 * <p>
	 * The bytes of data from the packet begin with a link-layer header. The format
	 * of the link-layer header is indicated by the return value of the
	 * pcap_datalink(3PCAP) routine when handed the pcap_t value also passed to
	 * pcap_loop() or pcap_dispatch(). https://www.tcpdump.org/linktypes.html lists
	 * the values pcap_datalink() can return and describes the packet formats that
	 * correspond to those values. The value it returns will be valid for all
	 * packets received unless and until pcap_set_datalink(3PCAP) is called; after a
	 * successful call to pcap_set_datalink(), all subsequent packets will have a
	 * link-layer header of the type specified by the link-layer header type value
	 * passed to pcap_set_datalink().
	 * </p>
	 * 
	 * <p>
	 * Do NOT assume that the packets for a given capture or ``savefile`` will have
	 * any given link-layer header type, such as DLT_EN10MB for Ethernet. For
	 * example, the "any" device on Linux will have a link-layer header type of
	 * DLT_LINUX_SLL or DLT_LINUX_SLL2 even if all devices on the system at the time
	 * the "any" device is opened have some other data link type, such as DLT_EN10MB
	 * for Ethernet.
	 * </p>
	 *
	 * @param count   maximum number of packets to process before returning
	 * @param handler the handler
	 * @param user    TODO
	 * @return the number of packets processed on success; this can be 0 if no
	 *         packets were read from a live capture (if, for example, they were
	 *         discarded because they didn't pass the packet filter, or if, on
	 *         platforms that support a packet buffer timeout that starts before any
	 *         packets arrive, the timeout expires before any packets arrive, or if
	 *         the file descriptor for the capture device is in non-blocking mode
	 *         and no packets were available to be read) or if no more packets are
	 *         available in a ``savefile.''
	 * @since libpcap 0.4
	 */
	public int dispatchWithAccessToRawPacket(
			int count,
			PcapHandler.NativeCallback handler,
			MemorySegment user) {
		return super.dispatch(count, handler, user);
	}

	/**
	 * Process packets from a live capture or savefile.
	 * 
	 * <p>
	 * Processes packets from a live capture or ``savefile'' until cnt packets are
	 * processed, the end of the current bufferful of packets is reached when doing
	 * a live capture, the end of the ``savefile'' is reached when reading from a
	 * ``savefile'', pcap_breakloop() is called, or an error occurs. Thus, when
	 * doing a live capture, cnt is the maximum number of packets to process before
	 * returning, but is not a minimum number; when reading a live capture, only one
	 * bufferful of packets is read at a time, so fewer than cnt packets may be
	 * processed. A value of -1 or 0 for cnt causes all the packets received in one
	 * buffer to be processed when reading a live capture, and causes all the
	 * packets in the file to be processed when reading a ``savefile''.
	 * </p>
	 * 
	 * <p>
	 * Note that, when doing a live capture on some platforms, if the read timeout
	 * expires when there are no packets available, pcap_dispatch() will return 0,
	 * even when not in non-blocking mode, as there are no packets to process.
	 * Applications should be prepared for this to happen, but must not rely on it
	 * happening.
	 * </p>
	 * 
	 * <p>
	 * Callback specifies a pcap_handler routine to be called with three arguments:
	 * a u_char pointer which is passed in the user argument to pcap_loop() or
	 * pcap_dispatch(), a const struct pcap_pkthdr pointer pointing to the packet
	 * time stamp and lengths, and a const u_char pointer to the first caplen (as
	 * given in the struct pcap_pkthdr a pointer to which is passed to the callback
	 * routine) bytes of data from the packet. The struct pcap_pkthdr and the packet
	 * data are not to be freed by the callback routine, and are not guaranteed to
	 * be valid after the callback routine returns; if the full needs them to be
	 * valid after the callback, it must make a copy of them.
	 * </p>
	 * 
	 * <p>
	 * The bytes of data from the packet begin with a link-layer header. The format
	 * of the link-layer header is indicated by the return value of the
	 * pcap_datalink(3PCAP) routine when handed the pcap_t value also passed to
	 * pcap_loop() or pcap_dispatch(). https://www.tcpdump.org/linktypes.html lists
	 * the values pcap_datalink() can return and describes the packet formats that
	 * correspond to those values. The value it returns will be valid for all
	 * packets received unless and until pcap_set_datalink(3PCAP) is called; after a
	 * successful call to pcap_set_datalink(), all subsequent packets will have a
	 * link-layer header of the type specified by the link-layer header type value
	 * passed to pcap_set_datalink().
	 * </p>
	 * 
	 * <p>
	 * Do NOT assume that the packets for a given capture or ``savefile`` will have
	 * any given link-layer header type, such as DLT_EN10MB for Ethernet. For
	 * example, the "any" device on Linux will have a link-layer header type of
	 * DLT_LINUX_SLL or DLT_LINUX_SLL2 even if all devices on the system at the time
	 * the "any" device is opened have some other data link type, such as DLT_EN10MB
	 * for Ethernet.
	 * </p>
	 *
	 * @param count   maximum number of packets to process before returning
	 * @param handler the handler
	 * @return the number of packets processed on success; this can be 0 if no
	 *         packets were read from a live capture (if, for example, they were
	 *         discarded because they didn't pass the packet filter, or if, on
	 *         platforms that support a packet buffer timeout that starts before any
	 *         packets arrive, the timeout expires before any packets arrive, or if
	 *         the file descriptor for the capture device is in non-blocking mode
	 *         and no packets were available to be read) or if no more packets are
	 *         available in a ``savefile.''
	 * @since libpcap 0.4
	 */
	public int loopWithAccessToRawPacket(int count, PcapHandler.NativeCallback handler) {
		return super.loop(count, handler, MemorySegment.NULL);
	}

	/**
	 * Inject.
	 *
	 * @param packet the packet
	 * @param length the length
	 * @return the int
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap0_9#inject(java.lang.foreign.MemorySegment, int)
	 */
	@Override
	public int inject(MemorySegment packet, int length) throws PcapException {
		return super.inject(packet, length);
	}

	/**
	 * Send packet.
	 *
	 * @param packet the packet
	 * @param length the length
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.Pcap0_8#sendPacket(java.lang.foreign.MemorySegment, int)
	 */
	@Override
	public void sendPacket(MemorySegment packet, int length) throws PcapException {
		super.sendPacket(packet, length);
	}

}
