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
package org.jnetpcap;

/**
 * A multi-mudule I8N error handler for all jNetPcap messages.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class PcapErrorHandler {

	/**
	 * Instantiates a new pcap error handler.
	 */
	public PcapErrorHandler() {
	}

	/**
	 * Gets the error string.
	 *
	 * @param key the key
	 * @return the string
	 */
	public static String getString(String key) {
		return key;
	}

}
