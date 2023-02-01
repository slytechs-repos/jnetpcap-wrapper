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
package org.jnetpcap.internal;

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryAddress;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.invoke.MethodType;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public class ForeignInitializer<T extends ForeignDowncall<E>, E extends Throwable> implements AutoCloseable {

	public enum CType {
		C_POINTER(ValueLayout.ADDRESS, MemoryAddress.class),
		C_CHAR(ValueLayout.JAVA_BYTE, byte.class),
		C_SHORT(ValueLayout.JAVA_SHORT, short.class),
		C_INT(ValueLayout.JAVA_INT, int.class),
		C_LONG(ValueLayout.JAVA_LONG, long.class),
		C_FLOAT(ValueLayout.JAVA_FLOAT, float.class),
		C_DOUBLE(ValueLayout.JAVA_DOUBLE, double.class),
		C_VA_LIST(ValueLayout.ADDRESS, MemoryAddress.class),
		C_VOID(null, null),

		;

		private final MemoryLayout layout;
		private final Class<?> javaType;

		private CType(MemoryLayout layout, Class<?> javaType) {
			this.layout = layout;
			this.javaType = javaType;
		}

		public Class<?> getJavaType() {
			return javaType;
		}

		public MemoryLayout getLayout() {
			return layout;
		}
	}

	public interface DowncallSupplier<T extends ForeignDowncall<?>> {
		T newDowncall(String symbolName, MemorySegment symbolAddress, MethodHandle handle);
	}

	public interface MethodHandleLookup {
		MethodHandle lookup(Lookup lookup, Class<?> clazz, String methodName, MethodType type)
				throws IllegalAccessException, NoSuchMethodException;
	}

	public interface MissingSymbolsPolicy {
		void onMissingSymbols(String name, List<String> missingDowncallSymbols, List<String> missingUpcallMethods)
				throws Throwable;
	}

	private static class SignatureParser {

		/**
		 * For example:
		 * 
		 * <pre>
		 * (AA)I int pcap_setfilter(pcap_t *p, struct bpf_program *fp)
		 * </pre>
		 */
		private static final Pattern SIG = Pattern.compile(
				"^(\\p{javaJavaIdentifierStart}\\p{javaJavaIdentifierPart}*)\\(([BCDFIJSAV]*)\\)([BCDFIJSAV]);?");

		private static Class<?>[] mapJavaPrimitiveTypes(String sig) {
			return sig.chars().mapToObj(SignatureParser::mapToJavaPrimitiveType).toArray(Class[]::new);
		}

		private static MemoryLayout[] mapLayouts(String sig) {
			return sig.chars().mapToObj(SignatureParser::mapToLayout).toArray(MemoryLayout[]::new);
		}

		private static CType mapToCType(int ch) {
			return switch (ch) {
			case 'A' -> CType.C_POINTER;
			case 'B' -> CType.C_CHAR;
			case 'I' -> CType.C_INT;
			case 'J' -> CType.C_LONG;
			case 'S' -> CType.C_SHORT;
			case 'F' -> CType.C_FLOAT;
			case 'D' -> CType.C_DOUBLE;
			case 'V' -> CType.C_VOID;

			default -> throw new IllegalStateException("illegal char in signature " + ch);
			};
		}

		private static Class<?> mapToJavaPrimitiveType(int ch) {
			return switch (ch) {
			case 'A' -> MemoryAddress.class;
			case 'B' -> byte.class;
			case 'I' -> int.class;
			case 'J' -> long.class;
			case 'S' -> short.class;
			case 'F' -> float.class;
			case 'D' -> double.class;
			case 'V' -> void.class;

			default -> throw new IllegalStateException("illegal char in signature " + ch);
			};
		}

		private static MemoryLayout mapToLayout(int ch) {
			return mapToCType(ch).getLayout();
		}

		private Matcher matcher;

		public MemoryLayout[] args() {
			return mapLayouts(group(2));
		}

		public String group(int index) {
			return matcher.group(index);
		}

		public Class<?>[] javaArgs() {
			return mapJavaPrimitiveTypes(group(2));
		}

		public Class<?> javaRet() {
			return mapToJavaPrimitiveType(matcher.group(3).charAt(0));
		}

		private boolean match(String str) {
			matcher = SIG.matcher(str.trim());

			return matcher.find() && matcher.groupCount() >= 2;
		}

		public MemoryLayout ret() {
			return mapToLayout(matcher.group(3).charAt(0));
		}

		public String symbol() {
			return group(1);
		}
	}

	private static final SignatureParser PARSER = new SignatureParser();
	private static final SymbolLookup C_SYMBOLS = SymbolLookup.loaderLookup();
	private static final Linker C_LINKER = Linker.nativeLinker();

	@SuppressWarnings({ "unchecked",
			"rawtypes" })
	private static <T extends ForeignDowncall<E>, E extends Throwable> T defaultInstance(String symbolName,
			MemorySegment symbolAddress, MethodHandle handle) {
		Function<String, E> exceptionFactory = msg -> (E) new IllegalStateException(msg);

		return (T) new ForeignDowncall(symbolName, symbolAddress, handle, exceptionFactory);
	}

	@SuppressWarnings({ "rawtypes",
			"unchecked" })
	private static <T extends ForeignDowncall<E>, E extends Throwable> T defaultInstance(String message,
			Throwable cause) {
		return (T) new ForeignDowncall(message, cause);
	}

	private static Method findMethodInClass(Class<?> clazz, String methodName) throws NoSuchMethodError,
			SecurityException {
		Method method = Arrays.stream(clazz.getDeclaredMethods())
				.filter(m -> m.getName().equals(methodName))
				.findAny()
				.orElseThrow(() -> new NoSuchMethodError(methodName));

		return method;
	}

	@SuppressWarnings("unused")
	private static Method findMethodInClass(Class<?> clazz, String methodName, Class<?>[] signature)
			throws NoSuchMethodException, SecurityException {
		return clazz.getDeclaredMethod(methodName, signature);
	}

	private final MethodHandles.Lookup methodHandleLookup;

	private DowncallSupplier<T> newFunctionSupplier;

	private BiFunction<String, Throwable, T> exceptionSupplier;

	private List<String> missingDowncalls = new ArrayList<>();

	private List<String> missingUpcalls = new ArrayList<>();

	private boolean makeAccessible;

	private MissingSymbolsPolicy missingSymbolPolicty = (name, down, up) -> {
		if (!up.isEmpty())
			throw new NoSuchMethodError("Messing java methods for upcalls %s in %s"
					.formatted(up.toString(), name));
	};

	private String name;

	public ForeignInitializer(String name) {
		this(name,
				ForeignInitializer::defaultInstance,
				ForeignInitializer::defaultInstance,
				MethodHandles.lookup());
	}

	protected ForeignInitializer(String name,
			DowncallSupplier<T> newFunctionSupplier,
			BiFunction<String, Throwable, T> exceptionSupplier,
			Lookup lookup) {

		this.setName(name);
		this.newFunctionSupplier = newFunctionSupplier;
		this.exceptionSupplier = exceptionSupplier;

		this.methodHandleLookup = lookup;
	}

	public ForeignInitializer(String name, Lookup lookup) {
		this(name,
				ForeignInitializer::defaultInstance,
				ForeignInitializer::defaultInstance,
				lookup);
	}

	/**
	 * @see java.lang.AutoCloseable#close()
	 */
	@Override
	public void close() throws ExceptionInInitializerError {
		try {
			if (!missingDowncalls.isEmpty() || !missingUpcalls.isEmpty())
				missingSymbolPolicty.onMissingSymbols(name, missingDowncalls, missingUpcalls);
		} catch (RuntimeException e) {
			throw e;

		} catch (Throwable e) {
			throw new ExceptionInInitializerError(e);
		}
	}

	/**
	 * Create ForeignDowncall from given signature. Function name must be part of
	 * the signature. For example given this signature {@code "getpid()I;"} where
	 * 'getpid' is the function name and will be used as a symbol to lookup the
	 * native function.
	 *
	 * @param signature the signature
	 * @return the foreign function
	 */
	public T downcall(String signature) {
		if (!PARSER.match(signature))
			throw new IllegalArgumentException("invalid foreign signature for C function (downcall) " + signature);

		String symbolName = PARSER.symbol();
		MemoryLayout ret = PARSER.ret();
		MemoryLayout[] args = PARSER.args();

		try {
			MemorySegment symbol = resolveSymbol(symbolName);
			var handle = downcallHandle(symbol, ret, args);

			return newFunctionSupplier.newDowncall(symbolName, symbol, handle);
		} catch (NoSuchElementException e) {
			missingDowncalls.add(symbolName);

			return exceptionSupplier.apply(signature, e);
		}
	}

	public T downcall(String symbolName, CType returnType, CType... arggumentTypes) {

		MemoryLayout ret = returnType.getLayout();
		MemoryLayout[] args = Arrays.stream(arggumentTypes)
				.map(CType::getLayout)
				.toArray(MemoryLayout[]::new);

		try {
			MemorySegment symbol = resolveSymbol(symbolName);
			var handle = downcallHandle(symbol, ret, args);

			return newFunctionSupplier.newDowncall(symbolName, symbol, handle);
		} catch (NoSuchElementException e) {
			missingDowncalls.add(symbolName);

			return exceptionSupplier.apply(symbolName, e);
		}
	}

	private MethodHandle downcallHandle(MemorySegment symbol, MemoryLayout retLayout, MemoryLayout[] argLayouts)
			throws NoSuchElementException {

		FunctionDescriptor descriptor = (retLayout == null)
				? FunctionDescriptor.ofVoid(argLayouts)
				: FunctionDescriptor.of(retLayout, argLayouts);

		MethodHandle handle = C_LINKER.downcallHandle(symbol, descriptor);

		return handle;
	}

	/**
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	public void makeAccessible(boolean b) {
		this.makeAccessible = b;
	}

	private MethodType methodType() {
		return MethodType.methodType(PARSER.javaRet(), PARSER.javaArgs());
	}

	private MemorySegment resolveSymbol(String symbolName) throws NoSuchElementException {
		Optional<MemorySegment> symbol = C_SYMBOLS.lookup(symbolName);
		if (symbol.isEmpty())
			throw new NoSuchElementException("native C symbol \"" + symbolName + "\" not found");

		return symbol.get();
	}

	public void setMissingSymbolsPolicy(MissingSymbolsPolicy missingSymbolsPolicy) {
		this.missingSymbolPolicty = missingSymbolsPolicy;
	}

	/**
	 * @param name the name to set
	 */
	public void setName(String name) {
		this.name = name;
	}

	private MethodHandle toStaticMethodHandle(Method method, MemoryLayout returnLayout,
			MemoryLayout[] argLayouts)
			throws IllegalAccessException {

		if (returnLayout == null) {
			FunctionDescriptor.ofVoid(argLayouts);
		} else {
			FunctionDescriptor.of(returnLayout, argLayouts);
		}

		// Enable accessibility for private static methods
		boolean isAccessible = method.canAccess(null);
		if (makeAccessible && !isAccessible)
			method.setAccessible(true);

		MethodHandle staticHandle = methodHandleLookup.unreflect(method);

		// Restore accessibility setting
		if (makeAccessible && (isAccessible != method.canAccess(null)))
			method.setAccessible(false);

		return staticHandle;
	}

	private MethodHandle toVirtualMethodHandle(
			MethodType type, Class<?> clazz, String methodName,
			Consumer<Method> methodSetup)
			throws IllegalAccessException, NoSuchMethodException {

		methodSetup.accept(clazz.getMethod(methodName, type.parameterArray()));

		var handle = methodHandleLookup.findVirtual(clazz, methodName, type);

		return handle;
	}

	public <U> ForeignUpcall<U> upcallStatic(Class<?> clazz, String signature) {
		if (!PARSER.match(signature))
			throw new IllegalArgumentException("invalid signature for java method (upcall) " + signature + "in class "
					+ clazz.getName());

		String methodName = PARSER.symbol();
		MemoryLayout retLayout = PARSER.ret();
		MemoryLayout[] argLayouts = PARSER.args();

		try {
			FunctionDescriptor descriptor = (retLayout == null)
					? FunctionDescriptor.ofVoid(argLayouts)
					: FunctionDescriptor.of(retLayout, argLayouts);

			Method method = findMethodInClass(clazz, methodName);

			MethodHandle handle = toStaticMethodHandle(method, retLayout, argLayouts);
			return new ForeignUpcall<>(handle, descriptor);
		} catch (IllegalAccessException | SecurityException e) {
			throw new RuntimeException(methodName, e);

		} catch (NoSuchMethodError e) {
			missingUpcalls.add(methodName);

			return new ForeignUpcall<>(methodName, e);
		}
	}

	public <U> ForeignUpcall<U> upcallStatic(Class<?> clazz, String methodName, CType returnType, CType... argTypes) {

		try {
			Method method = findMethodInClass(clazz, methodName);

			MemoryLayout retLayout = returnType.getLayout();
			MemoryLayout[] argLayouts = Arrays.stream(argTypes).map(CType::getLayout).toArray(MemoryLayout[]::new);

			FunctionDescriptor descriptor = (retLayout == null)
					? FunctionDescriptor.ofVoid(argLayouts)
					: FunctionDescriptor.of(retLayout, argLayouts);

			MethodHandle staticHandle = toStaticMethodHandle(method, retLayout, argLayouts);

			return new ForeignUpcall<>(staticHandle, descriptor);
		} catch (SecurityException | IllegalAccessException e) {
			throw new RuntimeException(methodName, e);

		} catch (NoSuchMethodError e) {
			missingUpcalls.add(methodName);

			return new ForeignUpcall<>(methodName, e);
		}

	}

	public <U> ForeignUpcall<U> upcall(String signature, Class<U> clazz) {
		return upcallVirtual(signature, clazz, m -> m.setAccessible(makeAccessible));
	}

	public <U> ForeignUpcall<U> upcallVirtual(
			String signature, Class<?> clazz, Consumer<Method> methodSetup) {

		if (!PARSER.match(signature))
			throw new IllegalArgumentException("invalid signature for java method (upcall) " + signature + "in class "
					+ clazz.getName());

		String methodName = PARSER.symbol();
		MemoryLayout retLayout = PARSER.ret();
		MemoryLayout[] argLayouts = PARSER.args();

		try {
			FunctionDescriptor descriptor = (retLayout == null)
					? FunctionDescriptor.ofVoid(argLayouts)
					: FunctionDescriptor.of(retLayout, argLayouts);

			MethodType type = methodType();

			MethodHandle virtualHandle = toVirtualMethodHandle(
					type, clazz, methodName, methodSetup);

			return new ForeignUpcall<>(virtualHandle, descriptor);
		} catch (IllegalAccessException | SecurityException e) {
			throw new RuntimeException("[%s] %s".formatted(methodName, e.getMessage()), e);

		} catch (NoSuchMethodError | NoSuchMethodException e) {
			missingUpcalls.add(methodName);

			return new ForeignUpcall<>(methodName, e);
		}
	}
}
