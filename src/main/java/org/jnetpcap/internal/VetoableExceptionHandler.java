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
package org.jnetpcap.internal;

import java.lang.Thread.UncaughtExceptionHandler;

/**
 * Vetoable uncaught exception handler. Just like the JDK's
 * UncaughtExceptionHandler but allows a boolean value to be returned allowing a
 * veto or interruption of whatever service is running.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
interface VetoableExceptionHandler extends UncaughtExceptionHandler {

	/**
	 * Wrap.
	 *
	 * @param handler the handler
	 * @return the vetoable exception handler
	 */
	static VetoableExceptionHandler wrap(UncaughtExceptionHandler handler) {
		return new VetoableExceptionHandler() {
			/**
			 * @see com.slytechs.protocol.runtime.util.VetoableExceptionHandler#vetoableException(java.lang.Throwable)
			 */
			@Override
			public boolean vetoableException(Throwable exception) {
				try {
					handler.uncaughtException(Thread.currentThread(), exception);

					return false;
				} catch (Throwable e2) {
					return true;
				}
			}

			@Override
			public void uncaughtException(Thread t, Throwable e) {
				handler.uncaughtException(t, e);
			}
		};
	}

	/**
	 * Method invoked when the given thread terminates due to the given uncaught
	 * exception.
	 * 
	 * <p>
	 * Any exception thrown by this method will be ignored by the Java Virtual
	 * Machine.
	 * </p>
	 * 
	 * @param e the exception
	 * @return true, veto or interrupt whatever operation is in progress or if
	 *         false, consider the exception handled and continue with the operaton.
	 */
	boolean vetoableException(Throwable e);
}
