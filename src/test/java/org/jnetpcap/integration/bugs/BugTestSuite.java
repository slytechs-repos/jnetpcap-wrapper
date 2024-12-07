/*
 * Copyright 2024 Sly Technologies Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jnetpcap.integration.bugs;

import org.junit.platform.suite.api.IncludeTags;
import org.junit.platform.suite.api.SelectPackages;
import org.junit.platform.suite.api.Suite;
import org.junit.platform.suite.api.SuiteDisplayName;

/**
 * Test suite that aggregates all JNetPcap bug regression tests. This suite
 * includes tests that verify fixes for reported GitHub issues and ensures they
 * don't regress in future releases.
 * 
 * <p>
 * The suite is configured to run all tests tagged with "bugfix" in the
 * org.jnetpcap.integration.bugs package. Individual tests can also be run
 * separately using their specific GitHub issue tags (e.g., "gh-61", "gh-63").
 * </p>
 * 
 * <p>
 * To run this suite:
 * 
 * <pre>
 * mvn test -Dgroups="bugfix"
 * </pre>
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
@Suite
@SuiteDisplayName("JNetPcap Bug Regression Tests")
@SelectPackages("org.jnetpcap.integration.bugs")
@IncludeTags("bugfix")
public class BugTestSuite {
	// Test suite configuration class - no implementation needed
}