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
 * Native Packet Capture (Pcap) wrapper API and implementation for Unix and
 * Windows platforms. This module provides high-level Java interfaces to packet
 * capture systems through the native libpcap/WinPcap libraries.
 * 
 * <h2>Module Overview</h2>
 * <p>
 * The module allows access to all network packets, including those destined for
 * other hosts, through various capture mechanisms. It supports both live packet
 * capture and working with saved capture files ("savefiles").
 * </p>
 * 
 * <h2>Core Packages</h2>
 * <ul>
 * <li>{@code org.jnetpcap} - Core API and implementation</li>
 * <li>{@code org.jnetpcap.windows} - Windows-specific extensions</li>
 * <li>{@code org.jnetpcap.constant} - Constant definitions and
 * enumerations</li>
 * <li>{@code org.jnetpcap.util} - Utility classes</li>
 * <li>{@code org.jnetpcap.spi} - Service provider interfaces</li>
 * </ul>
 * 
 * <h2>Using the Module</h2>
 * <p>
 * The primary entry point is the {@link org.jnetpcap.Pcap} class, which
 * provides methods for:
 * </p>
 * <ul>
 * <li>Creating capture handles ({@link org.jnetpcap.Pcap#create(PcapIf)})</li>
 * <li>Finding network devices ({@link org.jnetpcap.Pcap#findAllDevs()})</li>
 * <li>Opening capture files ({@link org.jnetpcap.Pcap#openOffline(File)})</li>
 * <li>Creating test handles
 * ({@link org.jnetpcap.Pcap#openDead(PcapDlt, int)})</li>
 * </ul>
 * 
 * <h2>Configurable Capture Options</h2>
 * 
 * <h3>Snapshot Length</h3>
 * <p>
 * Controls how much of each packet is captured. Set via
 * {@link org.jnetpcap.Pcap#setSnaplen(int)}. A length of 65535 bytes typically
 * captures complete packets on most networks. Smaller values reduce CPU,
 * bandwidth and storage requirements but may truncate packets.
 * </p>
 * 
 * <h3>Promiscuous Mode</h3>
 * <p>
 * When enabled via {@link org.jnetpcap.Pcap#setPromisc(boolean)}, captures all
 * packets on the network segment, not just those addressed to the capture
 * interface. Useful for network analysis but may be restricted on some systems.
 * </p>
 * 
 * <h3>Monitor (RFMON) Mode</h3>
 * <p>
 * For wireless interfaces, enables capture of all 802.11 frames including
 * management and control frames via
 * {@link org.jnetpcap.Pcap#setRfmon(boolean)}. Check support with
 * {@link org.jnetpcap.Pcap#canSetRfmon()}. Note that this may disable normal
 * network connectivity.
 * </p>
 * 
 * <h3>Buffer Timeout</h3>
 * <p>
 * Controls packet delivery timing through {@link org.jnetpcap.Pcap#setTimeout}:
 * </p>
 * <ul>
 * <li>Zero: Wait indefinitely for buffer to fill</li>
 * <li>Positive value: Maximum wait time for buffering packets</li>
 * <li>Negative values are invalid</li>
 * </ul>
 * <p>
 * Note: Not supported on all platforms and should not be used for polling.
 * </p>
 * 
 * <h3>Immediate Mode</h3>
 * <p>
 * When enabled, delivers packets immediately without buffering. Set via
 * {@link org.jnetpcap.Pcap#setImmediateMode(boolean)}.
 * </p>
 * 
 * <h3>Buffer Size</h3>
 * <p>
 * Controls the kernel capture buffer size via
 * {@link org.jnetpcap.Pcap#setBufferSize}. Larger buffers prevent packet drops
 * during traffic bursts but use more memory. Too small buffers may drop packets
 * under heavy load.
 * </p>
 * 
 * <h3>Timestamp Type</h3>
 * <p>
 * Selects the timestamp source for captured packets through
 * {@link org.jnetpcap.Pcap#setTstampType(PcapTstampType)}. Available types vary
 * by platform and can affect timestamp resolution and synchronization.
 * </p>
 * 
 * <h2>Service Providers</h2>
 * <p>
 * The module uses the {@link org.jnetpcap.spi.PcapMessagesProvider} service for
 * localization and message handling.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
module org.jnetpcap {

	/* Public API */
	exports org.jnetpcap;
	exports org.jnetpcap.windows;
	exports org.jnetpcap.constant;
	exports org.jnetpcap.util;
	exports org.jnetpcap.spi;

	uses org.jnetpcap.spi.PcapMessagesProvider;

	/* Private API */
	exports org.jnetpcap.internal;
}