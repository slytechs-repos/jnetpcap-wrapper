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
package org.jnetpcap.util;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Utility methods for jNetPcap library.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public final class PcapUtils {

	/**
	 * Parses a hex string to a byte array. Any whitespace and ':' characters are
	 * allowed and ignored.
	 *
	 * @param hexString the hex input string with characters in range
	 *                  {@code [0-9a-fA-f\\s:]}
	 * @return the byte[] comprised of the hex values parsed from the input string
	 */
	public static byte[] parseHexString(String hexString) {
		Objects.requireNonNull(hexString, "hexString");

		hexString = hexString.replaceAll("[:\s]", "");
		if ((hexString.length() % 2) != 0)
			throw new IllegalArgumentException(hexString);

		byte[] array = new byte[hexString.length() / 2];
		for (int i = 0; i < array.length; i++)
			array[i] = (byte) Integer.parseInt(hexString, (i * 2), ((i * 2) + 2), 16);

		return array;
	}

	/**
	 * Format an array as either IP ver 4, IP ver 6 or MAC address. If array length
	 * is 4 bytes, the address is treated as an IP ver 4 address. Otherwise both MAC
	 * and IP ver 6 addresses are formatted with a ':' separator and a 2 digit hex
	 * string.
	 *
	 * @param array the address
	 * @return the formatted string
	 */
	public static String toAddressString(byte[] array) {
		Objects.requireNonNull(array, "array");

		// assert (array.length == 4) || (array.length == 6) || (array.length == 16) : "invalid address array length [%d]".formatted(array.length);

		return (array.length == 4)
				? toIp4AddressString(array)
				: toHexString(array);
	}

	/**
	 * Formats individual bytes in an array to 2 digit hex values, each separated by
	 * ':' character enclosed within curley brackets <samp>{}</samp>.
	 * 
	 * <p>
	 * For example this is the formatted string of an array
	 * <samp>{00:26:62:2f:47:87}</samp> using a {@code toHexCurleyString(array, 0,
	 * 6)}.
	 * </p>
	 *
	 * @param array the source array for bytes
	 * @return the formatted string
	 */
	public static String toHexCurleyString(byte[] array) {
		Objects.requireNonNull(array, "array");

		return toHexCurleyString(array, 0, array.length);
	}

	/**
	 * Formats individual bytes in an array to 2 digit hex values, each separated by
	 * ':' character enclosed within curley brackets <samp>{}</samp>.
	 * 
	 * <p>
	 * For example this is the formatted string of 6 bytes out of the an array
	 * <samp>{00:26:62:2f:47:87}</samp> using a {@code toHexCurleyString(array, 0,
	 * 6)}.
	 * </p>
	 *
	 * @param array  the source array for bytes
	 * @param offset the offset into the array to start
	 * @param length the number of bytes to format
	 * @return the formatted string
	 */
	public static String toHexCurleyString(byte[] array, int offset, int length) {
		Objects.requireNonNull(array, "array");

		return toHexString(array, offset, length, "{", "}");
	}

	/**
	 * Formats individual bytes in a ByteBuffer to 2 digit hex values, each
	 * separated by ':' character enclosed within square brackets {@code []}.
	 * 
	 * <p>
	 * For example this is the formatted string of an ByteBuffer
	 * <samp>{00:26:62:2f:47:87}</samp> using a {@code toHexCurleyString(buf)}.
	 * </p>
	 *
	 * @param buf the source ByteBuffer for bytes
	 * @return the formatted string
	 */
	public static String toHexCurleyString(ByteBuffer buf) {
		Objects.requireNonNull(buf, "buf");

		byte[] array = new byte[buf.remaining()];
		buf.get(array);

		return toHexCurleyString(array);
	}

	/**
	 * Formats individual bytes in an array to 2 digit hex values, each separated by
	 * ':' character enclosed within square brackets {@code []}.
	 * 
	 * <p>
	 * For example this is the formatted string of an ByteBuffer
	 * <samp>[00:26:62:2f:47:87]</samp> using a {@code toHexSquareString(array)}.
	 * </p>
	 *
	 * @param array the source array for bytes
	 * @return the formatted string
	 */
	public static String toHexSquareString(byte[] array) {
		Objects.requireNonNull(array, "array");
		return toHexSquareString(array, 0, array.length);
	}

	/**
	 * Formats individual bytes in an array to 2 digit hex values, each separated by
	 * ':' character enclosed within square brackets {@code []}.
	 * 
	 * <p>
	 * For example this is the formatted string of 6 bytes out of the an array
	 * <samp>[00:26:62:2f:47:87]</samp> using a {@code toHexSquareString(array, 0,
	 * 6)}.
	 * </p>
	 *
	 * @param array  the source array for bytes
	 * @param offset the offset into the array to start
	 * @param length the number of bytes to format
	 * @return the formatted string
	 */
	public static String toHexSquareString(byte[] array, int offset, int length) {
		Objects.requireNonNull(array, "array");
		return toHexString(array, offset, length, "[", "]");
	}

	/**
	 * Formats individual bytes in a ByteBuffer to 2 digit hex values, each
	 * separated by ':' character enclosed within square brackets {@code []}.
	 * 
	 * <p>
	 * For example this is the formatted string of an ByteBuffer
	 * <samp>[00:26:62:2f:47:87]</samp> using a {@code toHexSquareString(buf)}.
	 * </p>
	 *
	 * @param buf the source ByteBuffer for bytes
	 * @return the formatted string
	 */
	public static String toHexSquareString(ByteBuffer buf) {
		Objects.requireNonNull(buf, "buf");

		byte[] array = new byte[buf.remaining()];
		buf.get(array);

		return toHexSquareString(array);
	}

	/**
	 * Formats individual bytes in an array to 2 digit hex values, each separated by
	 * ':' character.
	 * 
	 * <p>
	 * For example this is the formatted string of 6 bytes out of the an array
	 * <samp>00:26:62:2f:47:87</samp> using a {@code toHexString(array)}.
	 * </p>
	 *
	 * @param array the source array for bytes
	 * @return the formatted string
	 */
	public static String toHexString(byte[] array) {
		Objects.requireNonNull(array, "array");

		return toHexString(array, 0, array.length);
	}

	/**
	 * Formats individual bytes in an array to 2 digit hex values, each separated by
	 * ':' character.
	 * 
	 * <p>
	 * For example this is the formatted string of 6 bytes out of the an array
	 * <samp>00:26:62:2f:47:87</samp> using a {@code toHexString(array, 0, 6)}.
	 * </p>
	 *
	 * @param array  the source array for bytes
	 * @param offset the offset into the array to start
	 * @param length the number of bytes to format
	 * @return the formatted string
	 */
	public static String toHexString(byte[] array, int offset, int length) {
		Objects.requireNonNull(array, "array");

		return IntStream.range(offset, offset + length)
				.map(i -> Byte.toUnsignedInt(array[i]))
				.mapToObj("%02x"::formatted)
				.collect(Collectors.joining(":"));
	}

	/**
	 * Formats individual bytes in an array to 2 digit hex values, each separated by
	 * ':' character. Additionally a {@code prefix} and {@code postfix} are used to
	 * enclose the resultant hex string.
	 * 
	 * <p>
	 * For example this is the formatted string of 6 bytes out of the an array
	 * <samp>&lt;00:26:62:2f:47:87&gt;</samp> using a {@code toHexString(array, 0,
	 * 6, "<", ">")}.
	 * </p>
	 *
	 * @param array   the source array for bytes
	 * @param offset  the offset into the array to start
	 * @param length  the number of bytes to format
	 * @param prefix  the prefix in front of the resulting string
	 * @param postfix the postfix after the resulting string
	 * @return the formatted string
	 */
	public static String toHexString(byte[] array, int offset, int length, String prefix, String postfix) {
		Objects.requireNonNull(array, "array");
		Objects.requireNonNull(prefix, "prefix");
		Objects.requireNonNull(postfix, "postfix");

		return IntStream.range(offset, offset + length)
				.map(i -> Byte.toUnsignedInt(array[i]))
				.mapToObj("%02x"::formatted)
				.collect(Collectors.joining(":", prefix, postfix));
	}

	/**
	 * Formats individual bytes in an array to 2 digit hex values, each separated by
	 * ':' character. Additionally a {@code prefix} and {@code postfix} are used to
	 * enclose the resultant hex string.
	 * 
	 * <p>
	 * For example this is the formatted string an array
	 * <samp>&lt;00:26:62:2f:47:87&gt;</samp> using a {@code toHexString(array, "<",
	 * ">")}.
	 * </p>
	 *
	 * @param array   the source array for bytes
	 * @param prefix  the prefix in front of the resulting string
	 * @param postfix the postfix after the resulting string
	 * @return the formatted string
	 */
	public static String toHexString(byte[] array, String prefix, String postfix) {
		Objects.requireNonNull(array, "array");
		Objects.requireNonNull(prefix, "prefix");
		Objects.requireNonNull(postfix, "postfix");

		return toHexString(array, 0, array.length, prefix, postfix);
	}

	/**
	 * Formats individual bytes in a ByteBuffer to 2 digit hex values, each
	 * separated by ':' character.
	 * 
	 * <p>
	 * For example this is the formatted string a ByteBuffer
	 * <samp>00:26:62:2f:47:87</samp> using a {@code toHexString(buf)}.
	 * </p>
	 *
	 * @param buf the source ByteBuffer for bytes
	 * @return the formatted string
	 */
	public static String toHexString(ByteBuffer buf) {
		Objects.requireNonNull(buf, "buf");

		byte[] array = new byte[buf.remaining()];
		buf.get(array);

		return toHexString(array);
	}

	/**
	 * Formats the given array as a IP ver 4 address in the form of
	 * <samp>192.168.1.1</samp>.
	 *
	 * @param array the IP ver 4 address
	 * @return the formatted string
	 */
	public static String toIp4AddressString(byte[] array) {
		Objects.requireNonNull(array, "array");

		return IntStream.range(0, array.length)
				.map(i -> Byte.toUnsignedInt(array[i]))
				.mapToObj("%d"::formatted)
				.collect(Collectors.joining("."));
	}

	/**
	 * Instantiates a new pcap utils.
	 */
	private PcapUtils() {
		// Empty
	}

}
