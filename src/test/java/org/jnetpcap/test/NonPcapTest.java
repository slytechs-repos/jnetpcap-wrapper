/*
 * Apache License, Version 2.0
 * 
 * Copyright 2013-2022 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 *   
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jnetpcap.test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.Writer;

import org.jnetpcap.Pcap;
import org.jnetpcap.Pcap.LibraryPolicy;
import org.jnetpcap.util.PcapVersionException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
@Tag("non-libpcap-api")
@Tag("user-permission")
class NonPcapTest extends AbstractTestBase {

	/**
	 * Test property for {@link org.jnetpcap.Pcap#VERSION}.
	 */
	@Test
	void testPcapVersionProperty_startsWith_2() {
		assertTrue(Pcap.VERSION.startsWith("2"));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#checkPcapVersion(java.lang.String)}.
	 */
	@Test
	void testCheckPcapVersion_IsValid_ver2_0_1() {
		assertDoesNotThrow(() -> Pcap.checkPcapVersion("2.0.1"));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#checkPcapVersion(java.lang.String)}.
	 */
	@Test
	void testCheckPcapVersion_IsInvalid_ver1_4_25() {
		assertThrows(PcapVersionException.class, () -> Pcap.checkPcapVersion("1.4.25"));
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#isSupported()}.
	 */
	@Test
	@Tag("user-permission")
	void testIsSupported() {
		assertTrue(Pcap.isSupported());
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#setDefaultPolicy(org.jnetpcap.LibraryPolicy)}.
	 */
	@Test
	@Tag("user-permission")
	void testSetDefaultMissingSymbolsPolicy() {
		LibraryPolicy.setDefault((name, downcalls, upcalls) -> {});

		assertNotNull(LibraryPolicy.getDefault());
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#getLogginOutput())}.
	 */
	@Test
	@Tag("user-permission")
	void testGetLogginOutput() {
		assertEquals(
				LibraryPolicy.DEFAULT_LOGGING_OUTPUT,
				LibraryPolicy.getLogginOutput());
	}

	/**
	 * Test method for {@link org.jnetpcap.Pcap#setLoggingOutput(Appendable))}.
	 */
	@Test
	@Tag("user-permission")
	void testSetLoggingOutput() {

		try {

			LibraryPolicy.setLoggingOutput(Writer.nullWriter());
			assertNotEquals(
					LibraryPolicy.DEFAULT_LOGGING_OUTPUT,
					LibraryPolicy.getLogginOutput());

		} finally {
			LibraryPolicy.setLoggingOutput(LibraryPolicy.DEFAULT_LOGGING_OUTPUT);
		}
	}

}
