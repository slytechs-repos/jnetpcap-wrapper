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
 * The Packet Capture library provides a high level interface to packet capture
 * systems. All packets on the network, even those destined for other hosts, are
 * accessible through this mechanism. It also supports saving captured packets
 * to a ``savefile'', and reading packets from a ``savefile''.
 * </p>
 * 
 * <h1>Opening a capture handle for reading</h1>
 * <p>
 * To open a handle for a live capture, given the name of the network or other
 * interface on which the capture should be done, call pcap_create(), set the
 * appropriate options on the handle, and then activate it with
 * {@link org.jnetpcap.Pcap#activate()}. If pcap_activate() fails, the handle
 * should be closed with {@link org.jnetpcap.Pcap#close()}.
 * </p>
 * 
 * <p>
 * To obtain a list of devices that can be opened for a live capture, call
 * {@link org.jnetpcap.Pcap#findAllDevs}; the list is automatically freed by
 * <em>jNePcap</em>. {@link org.jnetpcap.Pcap#lookupDev()} will return the first
 * device on that list that is not a ``loopback`` network interface.
 * </p>
 * 
 * <p>
 * To open a handle for a ``savefile'' from which to read packets, given the
 * pathname of the ``savefile'', call pcap_open_offline(); to set up a handle
 * for a ``savefile'', given a FILE * referring to a file already opened for
 * reading, call {@link org.jnetpcap.Pcap#openOffline}.
 * </p>
 * 
 * <p>
 * In order to get a ``fake'' pcap_t for use in routines that require a pcap_t
 * as an argument, such as routines to open a ``savefile'' for writing and to
 * compile a filter expression, call {@link org.jnetpcap.Pcap#openDead}.
 * </p>
 * 
 * <p>
 * {@link org.jnetpcap.Pcap#create}, {@link org.jnetpcap.Pcap#openOffline},
 * pcap_fopen_offline(), and {@link org.jnetpcap.Pcap#openDead} return a pointer
 * to a pcap_t, which is the handle used for reading packets from the capture
 * stream or the ``savefile'', and for finding out information about the capture
 * stream or ``savefile''. To close a handle, use pcap_close().
 * </p>
 * <p>
 * Here is an example which uses PcapReceiver and several of its functional
 * packet handler interfaces.
 * 
 * <pre>
 * <full>
try (Pcap pcap = Pcap.openOffline(PCAP_FILE)) {

	BpFilter filter = pcap.compile("tcp", true);

	pcap.setFilter(filter);

	pcap.loop(1, PcapExample1::nextDefault, "Hello, this is copy to byte[] from Pcap class dispatch");

	PcapReceiver handler = new PcapReceiver(pcap::loop);

	handler.forEachCopy(1, PcapExample1::nextDefault, "Hello, this is copy to byte[] dispatch");
	handler.forEachCopy(1, PcapExample1::nextByteBuffer, "Helllo, this is copy to ByteBuffer dispatch");
	handler.forEachDirect(1, PcapExample1::nextByteBuffer, "Hello, this is no-copy, direct ByteBuffer dispatch");
}
...
private static void nextByteBuffer(String message, PcapHeader header, ByteBuffer packet) {

	System.out.println(message);
	System.out.printf("Packet [timestamp=%s, wirelen=%-4d caplen=%-4d %s]%n",
			Instant.ofEpochMilli(header.toEpochMillis()),
			header.wireLength(),
			header.captureLength(),
			PcapUtils.toHexCurleyString(packet.limit(6)));
}

private static void nextDefault(String message, PcapHeader header, byte[] packet) {

	System.out.println(message);
	System.out.printf("Packet [timestamp=%s, wirelen=%-4d caplen=%-4d %s]%n",
			Instant.ofEpochMilli(header.toEpochMillis()),
			header.wireLength(),
			header.captureLength(),
			PcapUtils.toHexCurleyString(packet, 0, 6));
}
 * </full>
 * </pre>
 * 
 * Output:
 * 
 * <pre>
Hello, this is copy to byte[] from Pcap class dispatch
Packet [timestamp=2011-03-01T20:45:13.266Z, wirelen=74   caplen=74   {00:26:62:2f:47:87}]
Hello, this is copy to byte[] dispatch
Packet [timestamp=2011-03-01T20:45:13.313Z, wirelen=74   caplen=74   {00:1d:60:b3:01:84}]
Helllo, this is copy to ByteBuffer dispatch
Packet [timestamp=2011-03-01T20:45:13.313Z, wirelen=66   caplen=66   {00:26:62:2f:47:87}]
Hello, this is no-copy, direct ByteBuffer dispatch
Packet [timestamp=2011-03-01T20:45:13.313Z, wirelen=200  caplen=200  {00:26:62:2f:47:87}]
 * </pre>
 * </p>
 * <p>
 * First the {@link Pcap#loop(int, org.jnetpcap.PcapHandler.OfArray, Object)} is
 * used to dispatch 1 packet. A single simple dispatcher type is provided
 * directly with Pcap class, as it is per native loop/dispatch calls available
 * from libpcap. Then a {@link org.jnetpcap.util.PcapReceiver} is setup with additional
 * capabilities and more advanced dispatch methods. Notice that both copy and
 * no-copy of packet data handlers are available through
 * {@link org.jnetpcap.util.PcapReceiver}.
 * </p>
 * 
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
package org.jnetpcap;
