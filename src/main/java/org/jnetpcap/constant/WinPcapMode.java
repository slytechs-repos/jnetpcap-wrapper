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
package org.jnetpcap.constant;

import java.util.function.IntSupplier;

/**
 * WinPcap setmode values.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public enum WinPcapMode implements IntSupplier {

	/** The CAPTURE mode constant. */
	CAPT,

	/** The STATISTICS mode constant. */
	STAT,

	/** The MONITOR mode constant. */
	MON;

	/** The Constant MODE_CAPT. */
	public static final int MODE_CAPT = 0;

	/** The Constant MODE_STAT. */
	public static final int MODE_STAT = 1;

	/** The Constant MODE_MON. */
	public static final int MODE_MON = 2;

	/**
	 * Gets the as int.
	 *
	 * @return the as int
	 * @see java.util.function.IntSupplier#getAsInt()
	 */
	@Override
	public int getAsInt() {
		return ordinal();
	}

}
