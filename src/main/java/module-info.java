/*
 * Apache License, Version 2.0
 * 
 * Copyright 2013-2022 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

/**
 * Native <em>Pcap</em> wrapper API and implementation on *Unix and Microsoft
 * Windows platforms.
 * <h2>Description</h2>
 * <p>
 * The Packet Capture library provides a high level interface to packet capture
 * systems. All packets on the network, even those destined for other hosts, are
 * accessible through this mechanism. It also supports saving captured packets
 * to a ``savefile'', and reading packets from a ``savefile''.
 * </p>
 * 
 * <h2>Opening a capture handle for reading</h2>
 * <p>
 * To open a handle for a live capture, given the name of the network or other
 * interface on which the capture should be done, call
 * {@link org.jnetpcap.Pcap#create(PcapIf)}, set the appropriate options on the
 * handle, and then activate it with {@link org.jnetpcap.Pcap#activate()}. If
 * {@link org.jnetpcap.Pcap#activate()} fails, the handle should be closed with
 * {@link org.jnetpcap.Pcap#close()}.
 * </p>
 * 
 * <p>
 * To obtain a list of devices that can be opened for a live capture, call
 * {@link org.jnetpcap.Pcap#findAllDevs()}; the list is automatically freed by
 * <em>jNePcap</em>. {@link org.jnetpcap.Pcap#lookupDev()} will return the first
 * device on that list that is not a ``loopback`` network interface.
 * </p>
 * 
 * <p>
 * To open a handle for a ``savefile'' from which to read packets, given the
 * pathname of the ``savefile'', call
 * {@link org.jnetpcap.Pcap#openOffline(File file)}; to set up a handle for a
 * ``savefile'', given a FILE * referring to a file already opened for reading,
 * call {@link org.jnetpcap.Pcap#openOffline(File file)}.
 * </p>
 * 
 * <p>
 * In order to get a ``fake'' {@code Pcap} for use in routines that require a
 * {@code Pcap} as an argument, such as routines to open a ``savefile'' for
 * writing and to compile a filter expression, call
 * {@link org.jnetpcap.Pcap#openDead(PcapDlt, int)}.
 * </p>
 * 
 * <p>
 * {@link org.jnetpcap.Pcap#create},
 * {@link org.jnetpcap.Pcap#openOffline(File file)}, and
 * {@link org.jnetpcap.Pcap#openDead(PcapDlt, int)} return a reference to a
 * {@code Pcap}, which is the handle used for reading packets from the capture
 * stream or the ``savefile'', and for finding out information about the capture
 * stream or ``savefile''. To close a handle, use
 * {@link org.jnetpcap.Pcap#close()}.
 * </p>
 * 
 * <p>
 * The options that can be set on a capture handle include
 * <dl>
 * <dt>snapshot length</dt>
 * <dd>
 * <p>
 * If, when capturing, you capture the entire contents of the packet, that
 * requires more CPU time to copy the packet to your application, more disk and
 * possibly network bandwidth to write the packet data to a file, and more disk
 * space to save the packet. If you don't need the entire contents of the packet
 * - for example, if you are only interested in the TCP headers of packets - you
 * can set the "snapshot length" for the capture to an appropriate value. If the
 * snapshot length is set to snaplen, and snaplen is less than the size of a
 * packet that is captured, only the first snaplen bytes of that packet will be
 * captured and provided as packet data.
 * </p>
 * <p>
 * A snapshot length of 65535 should be sufficient, on most if not all networks,
 * to capture all the data available from the packet.
 * </p>
 * <p>
 * The snapshot length is set with {@link org.jnetpcap.Pcap#setSnaplen(int)}.
 * </p>
 * </dd>
 * <dt>promiscuous mode</dt>
 * <dd>
 * <p>
 * On broadcast LANs such as Ethernet, if the network isn't switched, or if the
 * adapter is connected to a "mirror port" on a switch to which all packets
 * passing through the switch are sent, a network adapter receives all packets
 * on the LAN, including unicast or multicast packets not sent to a network
 * address that the network adapter isn't configured to recognize.
 * </p>
 * <p>
 * Normally, the adapter will discard those packets; however, many network
 * adapters support "promiscuous mode", which is a mode in which all packets,
 * even if they are not sent to an address that the adapter recognizes, are
 * provided to the host. This is useful for passively capturing traffic between
 * two or more other hosts for analysis.
 * </p>
 * <p>
 * Note that even if an application does not set promiscuous mode, the adapter
 * could well be in promiscuous mode for some other reason.
 * </p>
 * <p>
 * For now, this doesn't work on the "any" device; if an argument of "any" or
 * NULL is supplied, the setting of promiscuous mode is ignored.
 * </p>
 * <p>
 * Promiscuous mode is set with {@link org.jnetpcap.Pcap#setPromisc(boolean)}.
 * </p>
 * </dd>
 * <dt>monitor mode</dt>
 * <dd>
 * <p>
 * On IEEE 802.11 wireless LANs, even if an adapter is in promiscuous mode, it
 * will supply to the host only frames for the network with which it's
 * associated. It might also supply only data frames, not management or control
 * frames, and might not provide the 802.11 header or radio information
 * pseudo-header for those frames.
 * </p>
 * <p>
 * In "monitor mode", sometimes also called "rfmon mode" (for "Radio Frequency
 * MONitor"), the adapter will supply all frames that it receives, with 802.11
 * headers, and might supply a pseudo-header with radio information about the
 * frame as well.
 * </p>
 * <p>
 * Note that in monitor mode the adapter might disassociate from the network
 * with which it's associated, so that you will not be able to use any wireless
 * networks with that adapter. This could prevent accessing files on a network
 * server, or resolving host names or network addresses, if you are capturing in
 * monitor mode and are not connected to another network with another adapter.
 * </p>
 * <p>
 * Monitor mode is set with {@link org.jnetpcap.Pcap#setRfmon(boolean)}, and
 * {@link org.jnetpcap.Pcap#canSetRfmon()} can be used to determine whether an
 * adapter can be put into monitor mode.
 * </p>
 * </dd>
 * <dt>In monitor mode</dt>
 * <dd>
 * <p>
 * If, when capturing, packets are delivered as soon as they arrive, the
 * application capturing the packets will be woken up for each packet as it
 * arrives, and might have to make one or more calls to the operating system to
 * fetch each packet.
 * </p>
 * <p>
 * If, instead, packets are not delivered as soon as they arrive, but are
 * delivered after a short delay (called a "packet buffer timeout"), more than
 * one packet can be accumulated before the packets are delivered, so that a
 * single wakeup would be done for multiple packets, and each set of calls made
 * to the operating system would supply multiple packets, rather than a single
 * packet. This reduces the per-packet CPU overhead if packets are arriving at a
 * high rate, increasing the number of packets per second that can be captured.
 * </p>
 * <p>
 * The packet buffer timeout is required so that an application won't wait for
 * the operating system's capture buffer to fill up before packets are
 * delivered; if packets are arriving slowly, that wait could take an
 * arbitrarily long period of time.
 * </p>
 * <p>
 * Not all platforms support a packet buffer timeout; on platforms that don't,
 * the packet buffer timeout is ignored. A zero value for the timeout, on
 * platforms that support a packet buffer timeout, will cause a read to wait
 * forever to allow enough packets to arrive, with no timeout. A negative value
 * is invalid; the result of setting the timeout to a negative value is
 * unpredictable.
 * </p>
 * <p>
 * <b>NOTE:</b> the packet buffer timeout cannot be used to cause calls that
 * read packets to return within a limited period of time, because, on some
 * platforms, the packet buffer timeout isn't supported, and, on other
 * platforms, the timer doesn't start until at least one packet arrives. This
 * means that the packet buffer timeout should <b>NOT</b> be used, for example,
 * in an interactive application to allow the packet capture loop to ``poll''
 * for user input periodically, as there's no guarantee that a call reading
 * packets will return after the timeout expires even if no packets have
 * arrived.
 * </p>
 * <p>
 * The packet buffer timeout is set with {@link org.jnetpcap.Pcap#setTimeout}.
 * </p>
 * </dd>
 * <dt>immediate mode</dt>
 * <dd>
 * <p>
 * In immediate mode, packets are always delivered as soon as they arrive, with
 * no buffering. Immediate mode is set with pcap_set_immediate_mode().
 * </p>
 * </dd>
 * <dt>buffer size</dt>
 * <dd>
 * <p>
 * Packets that arrive for a capture are stored in a buffer, so that they do not
 * have to be read by the application as soon as they arrive. On some platforms,
 * the buffer's size can be set; a size that's too small could mean that, if too
 * many packets are being captured and the snapshot length doesn't limit the
 * amount of data that's buffered, packets could be dropped if the buffer fills
 * up before the application can read packets from it, while a size that's too
 * large could use more non-pageable operating system memory than is necessary
 * to prevent packets from being dropped.
 * </p>
 * <p>
 * The buffer size is set with {@link org.jnetpcap.Pcap#setBufferSize}.
 * </p>
 * </dd>
 * <dt>timestamp type</dt>
 * <dd>
 * <p>
 * On some platforms, the time stamp given to packets on live captures can come
 * from different sources that can have different resolutions or that can have
 * different relationships to the time values for the current time supplied by
 * routines on the native operating system.
 * </p>
 * <p>
 * The time stamp type is set with
 * {@link org.jnetpcap.Pcap#setTstampType(PcapTstampType)}.
 * </p>
 * </dd>
 * </dl>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 * @author repos@slytechs.com
 * 
 */
module org.jnetpcap {
	exports org.jnetpcap;
	exports org.jnetpcap.windows;
	exports org.jnetpcap.constant;
	exports org.jnetpcap.util;

	exports org.jnetpcap.internal to
			com.slytechs.jnet.jnetpcap.pro;
}