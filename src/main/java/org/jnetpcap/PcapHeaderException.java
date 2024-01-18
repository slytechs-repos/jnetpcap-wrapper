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
package org.jnetpcap;

import java.util.List;
import java.util.stream.Collectors;

import org.jnetpcap.internal.PcapHeaderABI;

/**
 * Reports any packet header runtime errors. The exception attempts to catch
 * error states for invalid C pkt_hdr structure values or if invalid ABI
 * (Application Binary Interface) has been assigned based on system and capture
 * attributes such as hardware architecture, whether the capture is live or
 * offline and if integer byte are swapped or not in the offline file.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class PcapHeaderException extends RuntimeException {

	/**
	 * Reports an out of range error for a value of native Pcap header field.
	 * Provides adds additional debugging information about the
	 */
	public static class OutOfRangeException extends PcapHeaderException {

		/** The Constant serialVersionUID. */
		private static final long serialVersionUID = -1194844250182172809L;

		/**
		 * A mutable flag that if set to true, then an extra list of per ABI
		 * possibilities for the out of range value field. This may be helpful in
		 * debugging and selecting the correct ABI which will have the plainly visible
		 * in range value. In range values should appear in front and are typically
		 * between 64 and 1528 bytes but may be as high as 9000 for jumbo frames.
		 */
		public static boolean INCLUDE_POSSIBILITIES = true;

		/** The abi. */
		private final PcapHeaderABI abi;
		
		/** The value. */
		private final int value;
		
		/** The possible values. */
		private List<String> possibleValues;
		
		/** The method name. */
		private String methodName = "Possibilities";

		/**
		 * Instantiates a new out of range exception.
		 *
		 * @param abi   the abi
		 * @param value the value
		 */
		public OutOfRangeException(PcapHeaderABI abi, int value) {
			super("invalid length [%d] from PcapHeaderABI [%s]"
					.formatted(value, abi.name()));
			this.abi = abi;
			this.value = value;
		}

		/**
		 * Gets the possiblities.
		 *
		 * @return the possibleValues
		 */
		public List<String> getPossiblities() {
			return possibleValues;
		}

		/**
		 * Gets the value.
		 *
		 * @return the value
		 */
		public int getValue() {
			return value;
		}

		/**
		 * Sets the possibilities.
		 *
		 * @param possibleValues the new possibilities
		 */
		public void setPossibilities(List<String> possibleValues) {
			this.possibleValues = possibleValues;
		}

		/**
		 * Sets the possiblities.
		 *
		 * @param possibleValues the possibleValues to set
		 * @return the out of range exception
		 */
		public OutOfRangeException setPossiblities(List<String> possibleValues) {
			this.possibleValues = possibleValues;

			return this;
		}

		/**
		 * Gets the abi.
		 *
		 * @return the abi
		 */
		public String getAbi() {
			return abi.name();
		}

		/**
		 * Gets the message.
		 *
		 * @return the message
		 * @see java.lang.Throwable#getMessage()
		 */
		@Override
		public String getMessage() {
			if (INCLUDE_POSSIBILITIES && (possibleValues != null))
				return super.getMessage()
						+ "\n%s: %s".formatted(methodName,
								possibleValues.stream()
										.sorted((s1, s2) -> s1.length() > s2.length() ? -1 : 0)
										.collect(Collectors.joining(" ")));
			else
				return super.getMessage();

		}

		/**
		 * Gets the method name.
		 *
		 * @return the methodName
		 */
		public String getMethodName() {
			return methodName;
		}

		/**
		 * Sets the method name.
		 *
		 * @param methodName the methodName to set
		 * @return the out of range exception
		 */
		public OutOfRangeException setMethodName(String methodName) {
			this.methodName = methodName;
			return this;
		}

	}

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = -694519865697844153L;

	/**
	 * Instantiates a new pcap header exception.
	 *
	 * @param message the message
	 */
	public PcapHeaderException(String message) {
		super(message);
	}

	/**
	 * Instantiates a new pcap header exception.
	 *
	 * @param message the message
	 * @param cause   the cause
	 */
	public PcapHeaderException(String message, Throwable cause) {
		super(message, cause);
	}

}
