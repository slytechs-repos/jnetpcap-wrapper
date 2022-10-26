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
 * Provides support for <em>Pcap</em> on Microsoft Windows platforms.
 * <p>
 * Two java wrapper implementations are provided by this package.
 * </p>
 * <dl>
 * <dt>WinPcap</dt>
 * <dd><em>WinPcap</em> is the legacy <em>Pcap</em> implementation on Microsoft
 * Windows. However, WinPcap is no longer maintained by the original authors.
 * None the less, WinPcap is still actively used by many projects.</dd>
 * <dt>Npcap</dt>
 * <dd><em>Npcap</em> is the actively maintained, <em>Nmap</em> project's packet
 * capture (and sending) library for Microsoft Windows that builds on legacy
 * <em>WinPcap</em> implementation.</dd>
 * </dl>
 */
package org.jnetpcap.windows;