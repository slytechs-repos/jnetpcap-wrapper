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

import java.util.Arrays;

import org.jnetpcap.PcapException;

/**
 * Indicates that installed runtime version of jNetPcap library is incompatible
 * with the client application version of jNetPcap being used.
 * 
 * <p>
 * Another words, the client application was compiled with a newer version of
 * jNetPcap library and is incompatible with the installed version on the system
 * running the client application. The version components {@code major.minor}
 * are used to determine the compatibility of jNetPcap library runtimes. All
 * other components are assumed to be backward compatible, as long as
 * {@code major.minor} components match.
 * </p>
 * <p>
 * Example:
 * {@code 1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta < 1.0.0-beta < 1.0.0-beta.2 < 1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0.}
 * </p>
 * 
 * For detailed specification please see http://semver.org
 * 
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
public final class PcapVersionException extends PcapException {

	/** The Constant VERSION_COMPONENT_CHECK_LIMIT. */
	private static final int VERSION_COMPONENT_CHECK_LIMIT = 2; // Limit to major.minor components

	/** The Constant VERSION_COMPONENT_SEPARATOR_REGEX. */
	private static final String VERSION_COMPONENT_SEPARATOR_REGEX = "[\\.\\+-]";

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = -7076460432578326479L;

	/**
	 * Builds the message.
	 *
	 * @param runtimeVersion     the runtime version
	 * @param applicationVersion the application version
	 * @return the string
	 */
	private static String buildMessage(String runtimeVersion, String applicationVersion) {
		return "Installed runtime %s.Pcap version %s and application version %s are incompatible"
				.formatted(PcapVersionException.class.getPackageName(),
						runtimeVersion,
						applicationVersion);
	}

	/**
	 * Compare 2 versions. If v1 is less than v2 then versions are incompatible and
	 * false is returned. Only the {@code major.minor} components are checked for
	 * compatibility. Any other components are ignored and assumed to be backward
	 * compatible with the installed runtime version.
	 *
	 * @param v1 the installed runtime version
	 * @param v2 the application version
	 * @return true, if runtime version is compatible with application version,
	 *         otherwise false when incompatible
	 */
	public static boolean compareVersions(String v1, String v2) {
		return compareVersions(v1, v2, VERSION_COMPONENT_CHECK_LIMIT);
	}

	/**
	 * Compare 2 versions. If v1 is less than v2 then versions are incompatible and
	 * false is returned. Only the {@code major.minor} specified by limit 2,
	 * components are checked for compatibility. Any other components are ignored
	 * and assumed to be backward compatible with the installed runtime version. For
	 * {@code major} only component check, specify limit of 1.
	 * 
	 * <p>
	 * For detailed information see https://semver.org - Semantic Versioning
	 * Specification used by jNetPcap
	 * </p>
	 * 
	 * @param v1    the installed runtime version
	 * @param v2    the application version
	 * @param limit Number of version components to check up to a maximum of 3. Use
	 *              2 for major.minor or 1 for major only. Any number greater than 3
	 *              major.minor.patch will throw a IllegalArgumentException
	 *              exception due to parsing errors of components which not ment to
	 *              be parsed and compared. A value of 3 major.minor.patch may
	 *              provide a check against a specific bug fix.
	 * @return true, if runtime version is compatible with application version,
	 *         otherwise false when incompatible
	 */
	public static boolean compareVersions(String v1, String v2, int limit) {

		if (limit < 0 || limit > 3)
			throw new IllegalArgumentException("Invalid limit value [" + limit + "]. Maximim value is 3");

		/* null disables comparison */
		if ((v1 == null) || (v2 == null))
			return true;

		try {
			int[] c1 = parseVersion(v1.trim());
			int[] c2 = parseVersion(v2.trim());

			if ((c1.length < limit) || (c2.length < limit) || (c1[0] < c2[0]) || (c1[1] < c2[1]))
				return false;

			return true;
		} catch (Throwable e) { // Any parsing errors
			return false;
		}
	}

	/**
	 * Equals.
	 *
	 * @param v1 the v 1
	 * @param v2 the v 2
	 * @return true, if successful
	 */
	public static boolean equals(String v1, String v2) {
		return v1.trim().equalsIgnoreCase(v2.trim());
	}

	/**
	 * Parses the version.
	 *
	 * @param version the version
	 * @return the int[]
	 */
	private static int[] parseVersion(String version) {
		return Arrays.stream(version.split(VERSION_COMPONENT_SEPARATOR_REGEX))
				.mapToInt(Integer::parseInt)
				.toArray();
	}

	/**
	 * Throw if version mismatch.
	 *
	 * @param runtimeVersion     the runtime version
	 * @param applicationVersion the application version
	 * @throws PcapVersionException the pcap version exception
	 */
	public static void throwIfVersionMismatch(String runtimeVersion, String applicationVersion)
			throws PcapVersionException {
		throwIfVersionMismatch(runtimeVersion, applicationVersion, VERSION_COMPONENT_CHECK_LIMIT);
	}

	/**
	 * Throw if version mismatch.
	 *
	 * @param runtimeVersion     the runtime version
	 * @param applicationVersion the application version
	 * @param limit              the limit
	 * @throws PcapVersionException the pcap version exception
	 */
	public static void throwIfVersionMismatch(String runtimeVersion, String applicationVersion, int limit)
			throws PcapVersionException {

		if (!compareVersions(runtimeVersion, applicationVersion, limit))
			throw new PcapVersionException(runtimeVersion, applicationVersion);
	}

	/**
	 * Private.
	 *
	 * @param runtimeVersion     the runtime version
	 * @param applicationVersion the application version
	 */
	private PcapVersionException(String runtimeVersion, String applicationVersion) {
		super(buildMessage(runtimeVersion, applicationVersion));
	}

}
