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
 * to a savefile, and reading packets from a savefile.
 * 
 * <h2>Opening a capture handle for reading</h2>
 * <p>
 * To open a handle for a live capture, given the name of the network or other
 * interface on which the capture should be done, call
 * {@link Pcap#create(String)}, set the appropriate options on the handle, and
 * then activate it with {@link Pcap#activate()}. If activate() fails, the
 * handle should be closed with {@link Pcap#close()}.
 * </p>
 * 
 * <p>
 * To obtain a list of devices that can be opened for a live capture, call
 * {@link Pcap#findAllDevs()}; the returned list contains {@link PcapIf} objects
 * representing each interface. {@link Pcap#lookupDev()} will return the first
 * device on that list that is not a loopback network interface.
 * </p>
 * 
 * <p>
 * To open a handle for a savefile from which to read packets, given the
 * pathname of the savefile, call {@link Pcap#openOffline(String)}. To set up a
 * handle for writing to a savefile, use {@link Pcap#dumpOpen(String)}.
 * </p>
 * 
 * <p>
 * To create a "fake" handle for use in routines that require a Pcap instance as
 * an argument, such as routines to compile a filter expression, call
 * {@link Pcap#openDead(PcapDlt, int)}.
 * </p>
 * 
 * <p>
 * All Pcap instances implement {@link AutoCloseable}, so they can be used with
 * try-with-resources statements to ensure proper cleanup. When you're done with
 * a handle, it will be automatically closed when exiting the try block.
 * </p>
 * 
 * <h2>Example Usage</h2> Here is an example which demonstrates capturing
 * packets using different handler types:
 * 
 * <pre>{@code
 * try (Pcap pcap = Pcap.openOffline("capture.pcap")) {
 * 	// Create and apply a filter
 * 	BpFilter filter = pcap.compile("tcp", true);
 * 	pcap.setFilter(filter);
 * 
 * 	// Capture packets using byte array handler
 * 	pcap.loop(1, (String msg, PcapHeader header, byte[] packet) -> {
 * 		System.out.printf("Packet [timestamp=%s, wirelen=%d caplen=%d]%n",
 * 				Instant.ofEpochMilli(header.toEpochMillis()),
 * 				header.wireLength(),
 * 				header.captureLength());
 * 	}, "Example message");
 * 
 * 	// Capture packets using ByteBuffer handler for zero-copy
 * 	pcap.loop(1, (String msg, PcapHeader header, ByteBuffer packet) -> {
 * 		System.out.printf("Packet [timestamp=%s, wirelen=%d caplen=%d]%n",
 * 				Instant.ofEpochMilli(header.toEpochMillis()),
 * 				header.wireLength(),
 * 				header.captureLength());
 * 	}, "Example message");
 * }
 * }</pre>
 * 
 * <h2>Packet Handlers</h2> The library provides several types of packet
 * handlers through the {@link PcapHandler} interface:
 * <ul>
 * <li>{@link PcapHandler.OfArray} - Receives packets as byte arrays (with
 * copy)</li>
 * <li>{@link PcapHandler.OfByteBuffer} - Receives packets as ByteBuffers</li>
 * <li>{@link PcapHandler.OfMemorySegment} - Direct access to native memory
 * segments (advanced usage)</li>
 * </ul>
 * 
 * <h2>Network Interfaces</h2> Network interfaces are represented by the
 * {@link PcapIf} class, which provides information about:
 * <ul>
 * <li>Interface name and description</li>
 * <li>Network addresses (IPv4, IPv6)</li>
 * <li>Interface flags and capabilities</li>
 * <li>Hardware (MAC) addresses</li>
 * </ul>
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
package org.jnetpcap;
