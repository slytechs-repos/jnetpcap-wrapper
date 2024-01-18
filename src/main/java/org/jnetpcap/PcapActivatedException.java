/*
<<<<<<< HEAD
 * Copyright 2023 Sly Technologies Inc
=======
 * Apache License, Version 2.0
 * 
 * Copyright 2013-2022 Sly Technologies Inc.
>>>>>>> refs/remotes/origin/bugfix-2.0.0-javadoc-warnings
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
<<<<<<< HEAD
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
=======
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 *   
>>>>>>> refs/remotes/origin/bugfix-2.0.0-javadoc-warnings
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jnetpcap;

/**
 * Indicates that an operation is not permitted on an already activated
 * <em>pcap</em> handle.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class PcapActivatedException extends PcapException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 5824725740629248762L;

	/**
	 * Instantiates a new pcap activated exception.
	 *
	 * @param pcapErrorCode the pcap error code
	 */
	public PcapActivatedException(int pcapErrorCode) {
		super(pcapErrorCode);
	}

	/**
	 * Instantiates a new pcap activated exception.
	 *
	 * @param pcapErrorCode the pcap error code
	 * @param message       the message
	 */
	public PcapActivatedException(int pcapErrorCode, String message) {
		super(pcapErrorCode, message);
	}

}
