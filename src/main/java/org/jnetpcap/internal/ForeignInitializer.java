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

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
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
 * The Class ForeignInitializer.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 * @param <T> the generic type
 * @param <E> the element type
 */
public class ForeignInitializer<T extends ForeignDowncall<E>, E extends Throwable> implements AutoCloseable {

	/**
	 * The Enum CType.
	 */
	public enum CType {
		
		/** The c pointer. */
		C_POINTER(ValueLayout.ADDRESS, MemorySegment.class),
		
		/** The c char. */
		C_CHAR(ValueLayout.JAVA_BYTE, byte.class),
		
		/** The c short. */
		C_SHORT(ValueLayout.JAVA_SHORT, short.class),
		
		/** The c int. */
		C_INT(ValueLayout.JAVA_INT, int.class),
		
		/** The c long. */
		C_LONG(ValueLayout.JAVA_LONG, long.class),
		
		/** The c float. */
		C_FLOAT(ValueLayout.JAVA_FLOAT, float.class),
		
		/** The c double. */
		C_DOUBLE(ValueLayout.JAVA_DOUBLE, double.class),
		
		/** The c va list. */
		C_VA_LIST(ValueLayout.ADDRESS, MemorySegment.class),
		
		/** The c void. */
		C_VOID(null, null),

		;

		/** The layout. */
		private final MemoryLayout layout;
		
		/** The java type. */
		private final Class<?> javaType;

		/**
		 * Instantiates a new c type.
		 *
		 * @param layout   the layout
		 * @param javaType the java type
		 */
		private CType(MemoryLayout layout, Class<?> javaType) {
			this.layout = layout;
			this.javaType = javaType;
		}

		/**
		 * Gets the java type.
		 *
		 * @return the java type
		 */
		public Class<?> getJavaType() {
			return javaType;
		}

		/**
		 * Gets the layout.
		 *
		 * @return the layout
		 */
		public MemoryLayout getLayout() {
			return layout;
		}
	}

	/**
	 * The Interface DowncallSupplier.
	 *
	 * @param <T> the generic type
	 */
	public interface DowncallSupplier<T extends ForeignDowncall<?>> {
		
		/**
		 * New downcall.
		 *
		 * @param symbolName    the symbol name
		 * @param symbolAddress the symbol address
		 * @param handle        the handle
		 * @return the t
		 */
		T newDowncall(String symbolName, MemorySegment symbolAddress, MethodHandle handle);
	}

	/**
	 * The Interface MethodHandleLookup.
	 */
	public interface MethodHandleLookup {
		
		/**
		 * Lookup.
		 *
		 * @param lookup     the lookup
		 * @param clazz      the clazz
		 * @param methodName the method name
		 * @param type       the type
		 * @return the method handle
		 * @throws IllegalAccessException the illegal access exception
		 * @throws NoSuchMethodException  the no such method exception
		 */
		MethodHandle lookup(Lookup lookup, Class<?> clazz, String methodName, MethodType type)
				throws IllegalAccessException, NoSuchMethodException;
	}

	/**
	 * The Interface MissingSymbolsPolicy.
	 */
	public interface MissingSymbolsPolicy {
		
		/**
		 * On missing symbols.
		 *
		 * @param name                   the name
		 * @param missingDowncallSymbols the missing downcall symbols
		 * @param missingUpcallMethods   the missing upcall methods
		 * @throws Throwable the throwable
		 */
		void onMissingSymbols(String name, List<String> missingDowncallSymbols, List<String> missingUpcallMethods)
				throws Throwable;
	}

	/**
	 * The Class SignatureParser.
	 */
	private static class SignatureParser {

		/**
		 * For example:
		 * 
		 * <pre>
		 *  (AA)I int pcap_setfilter(pcap_t *p, struct bpf_program *fp)
		 * </pre>
		 * 
		 * .
		 */
		private static final Pattern SIG = Pattern.compile(
				"^(\\p{javaJavaIdentifierStart}\\p{javaJavaIdentifierPart}*)\\(([BCDFIJSAV]*)\\)([BCDFIJSAV]);?");

		/**
		 * Map java primitive types.
		 *
		 * @param sig the sig
		 * @return the class[]
		 */
		private static Class<?>[] mapJavaPrimitiveTypes(String sig) {
			return sig.chars().mapToObj(SignatureParser::mapToJavaPrimitiveType).toArray(Class[]::new);
		}

		/**
		 * Map layouts.
		 *
		 * @param sig the sig
		 * @return the memory layout[]
		 */
		private static MemoryLayout[] mapLayouts(String sig) {
			return sig.chars().mapToObj(SignatureParser::mapToLayout).toArray(MemoryLayout[]::new);
		}

		/**
		 * Map to C type.
		 *
		 * @param ch the ch
		 * @return the c type
		 */
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

		/**
		 * Map to java primitive type.
		 *
		 * @param ch the ch
		 * @return the class
		 */
		private static Class<?> mapToJavaPrimitiveType(int ch) {
			return switch (ch) {
			case 'A' -> MemorySegment.class;
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

		/**
		 * Map to layout.
		 *
		 * @param ch the ch
		 * @return the memory layout
		 */
		private static MemoryLayout mapToLayout(int ch) {
			return mapToCType(ch).getLayout();
		}

		/** The matcher. */
		private Matcher matcher;

		/**
		 * Args.
		 *
		 * @return the memory layout[]
		 */
		public MemoryLayout[] args() {
			return mapLayouts(group(2));
		}

		/**
		 * Group.
		 *
		 * @param index the index
		 * @return the string
		 */
		public String group(int index) {
			return matcher.group(index);
		}

		/**
		 * Java args.
		 *
		 * @return the class[]
		 */
		public Class<?>[] javaArgs() {
			return mapJavaPrimitiveTypes(group(2));
		}

		/**
		 * Java ret.
		 *
		 * @return the class
		 */
		public Class<?> javaRet() {
			return mapToJavaPrimitiveType(matcher.group(3).charAt(0));
		}

		/**
		 * Match.
		 *
		 * @param str the str
		 * @return true, if successful
		 */
		private boolean match(String str) {
			matcher = SIG.matcher(str.trim());

			return matcher.find() && matcher.groupCount() >= 2;
		}

		/**
		 * Ret.
		 *
		 * @return the memory layout
		 */
		public MemoryLayout ret() {
			return mapToLayout(matcher.group(3).charAt(0));
		}

		/**
		 * Symbol.
		 *
		 * @return the string
		 */
		public String symbol() {
			return group(1);
		}
	}

	/** The Constant PARSER. */
	private static final SignatureParser PARSER = new SignatureParser();
	
	/** The Constant C_SYMBOLS. */
	private static final SymbolLookup C_SYMBOLS = SymbolLookup.loaderLookup();
	
	/** The Constant C_LINKER. */
	private static final Linker C_LINKER = Linker.nativeLinker();

	/**
	 * Default instance.
	 *
	 * @param <T>           the generic type
	 * @param <E>           the element type
	 * @param symbolName    the symbol name
	 * @param symbolAddress the symbol address
	 * @param handle        the handle
	 * @return the t
	 */
	@SuppressWarnings({ "unchecked",
			"rawtypes" })
	private static <T extends ForeignDowncall<E>, E extends Throwable> T defaultInstance(String symbolName,
			MemorySegment symbolAddress, MethodHandle handle) {
		Function<String, E> exceptionFactory = msg -> (E) new IllegalStateException(msg);

		return (T) new ForeignDowncall(symbolName, symbolAddress, handle, exceptionFactory);
	}

	/**
	 * Default instance.
	 *
	 * @param <T>     the generic type
	 * @param <E>     the element type
	 * @param message the message
	 * @param cause   the cause
	 * @return the t
	 */
	@SuppressWarnings({ "rawtypes",
			"unchecked" })
	private static <T extends ForeignDowncall<E>, E extends Throwable> T defaultInstance(String message,
			Throwable cause) {
		return (T) new ForeignDowncall(message, cause);
	}

	/**
	 * Find method in class.
	 *
	 * @param clazz      the clazz
	 * @param methodName the method name
	 * @return the method
	 * @throws NoSuchMethodError the no such method error
	 * @throws SecurityException the security exception
	 */
	private static Method findMethodInClass(Class<?> clazz, String methodName) throws NoSuchMethodError,
			SecurityException {
		Method method = Arrays.stream(clazz.getDeclaredMethods())
				.filter(m -> m.getName().equals(methodName))
				.findAny()
				.orElseThrow(() -> new NoSuchMethodError(methodName));

		return method;
	}

	/**
	 * Find method in class.
	 *
	 * @param clazz      the clazz
	 * @param methodName the method name
	 * @param signature  the signature
	 * @return the method
	 * @throws NoSuchMethodException the no such method exception
	 * @throws SecurityException     the security exception
	 */
	@SuppressWarnings("unused")
	private static Method findMethodInClass(Class<?> clazz, String methodName, Class<?>[] signature)
			throws NoSuchMethodException, SecurityException {
		return clazz.getDeclaredMethod(methodName, signature);
	}

	/** The method handle lookup. */
	private final MethodHandles.Lookup methodHandleLookup;

	/** The new function supplier. */
	private DowncallSupplier<T> newFunctionSupplier;

	/** The exception supplier. */
	private BiFunction<String, Throwable, T> exceptionSupplier;

	/** The missing downcalls. */
	private List<String> missingDowncalls = new ArrayList<>();

	/** The missing upcalls. */
	private List<String> missingUpcalls = new ArrayList<>();

	/** The make accessible. */
	private boolean makeAccessible;

	/** The missing symbol policty. */
	private MissingSymbolsPolicy missingSymbolPolicty = (name, down, up) -> {
		if (!up.isEmpty())
			throw new NoSuchMethodError("Messing java methods for upcalls %s in %s"
					.formatted(up.toString(), name));
	};

	/** The name. */
	private String name;

	/**
	 * Instantiates a new foreign initializer.
	 *
	 * @param name the name
	 */
	public ForeignInitializer(String name) {
		this(name,
				ForeignInitializer::defaultInstance,
				ForeignInitializer::defaultInstance,
				MethodHandles.lookup());
	}

	/**
	 * Instantiates a new foreign initializer.
	 *
	 * @param name                the name
	 * @param newFunctionSupplier the new function supplier
	 * @param exceptionSupplier   the exception supplier
	 * @param lookup              the lookup
	 */
	protected ForeignInitializer(String name,
			DowncallSupplier<T> newFunctionSupplier,
			BiFunction<String, Throwable, T> exceptionSupplier,
			Lookup lookup) {

		this.setName(name);
		this.newFunctionSupplier = newFunctionSupplier;
		this.exceptionSupplier = exceptionSupplier;

		this.methodHandleLookup = lookup;
	}

	/**
	 * Instantiates a new foreign initializer.
	 *
	 * @param name   the name
	 * @param lookup the lookup
	 */
	public ForeignInitializer(String name, Lookup lookup) {
		this(name,
				ForeignInitializer::defaultInstance,
				ForeignInitializer::defaultInstance,
				lookup);
	}

	/**
	 * Close.
	 *
	 * @throws ExceptionInInitializerError the exception in initializer error
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

	/**
	 * Downcall.
	 *
	 * @param symbolName     the symbol name
	 * @param returnType     the return type
	 * @param arggumentTypes the arggument types
	 * @return the t
	 */
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

	/**
	 * Downcall handle.
	 *
	 * @param symbol     the symbol
	 * @param retLayout  the ret layout
	 * @param argLayouts the arg layouts
	 * @return the method handle
	 * @throws NoSuchElementException the no such element exception
	 */
	private MethodHandle downcallHandle(MemorySegment symbol, MemoryLayout retLayout, MemoryLayout[] argLayouts)
			throws NoSuchElementException {

		FunctionDescriptor descriptor = (retLayout == null)
				? FunctionDescriptor.ofVoid(argLayouts)
				: FunctionDescriptor.of(retLayout, argLayouts);

		MethodHandle handle = C_LINKER.downcallHandle(symbol, descriptor);

		return handle;
	}

	/**
	 * Gets the name.
	 *
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Make accessible.
	 *
	 * @param b the b
	 */
	public void makeAccessible(boolean b) {
		this.makeAccessible = b;
	}

	/**
	 * Method type.
	 *
	 * @return the method type
	 */
	private MethodType methodType() {
		return MethodType.methodType(PARSER.javaRet(), PARSER.javaArgs());
	}

	/**
	 * Resolve symbol.
	 *
	 * @param symbolName the symbol name
	 * @return the memory segment
	 * @throws NoSuchElementException the no such element exception
	 */
	private MemorySegment resolveSymbol(String symbolName) throws NoSuchElementException {
		Optional<MemorySegment> symbol = C_SYMBOLS.find(symbolName);
		if (symbol.isEmpty())
			throw new NoSuchElementException("native C symbol \"" + symbolName + "\" not found");

		return symbol.get();
	}

	/**
	 * Sets the missing symbols policy.
	 *
	 * @param missingSymbolsPolicy the new missing symbols policy
	 */
	public void setMissingSymbolsPolicy(MissingSymbolsPolicy missingSymbolsPolicy) {
		this.missingSymbolPolicty = missingSymbolsPolicy;
	}

	/**
	 * Sets the name.
	 *
	 * @param name the name to set
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * To static method handle.
	 *
	 * @param method       the method
	 * @param returnLayout the return layout
	 * @param argLayouts   the arg layouts
	 * @return the method handle
	 * @throws IllegalAccessException the illegal access exception
	 */
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

	/**
	 * To virtual method handle.
	 *
	 * @param type        the type
	 * @param clazz       the clazz
	 * @param methodName  the method name
	 * @param methodSetup the method setup
	 * @return the method handle
	 * @throws IllegalAccessException the illegal access exception
	 * @throws NoSuchMethodException  the no such method exception
	 */
	private MethodHandle toVirtualMethodHandle(
			MethodType type, Class<?> clazz, String methodName,
			Consumer<Method> methodSetup)
			throws IllegalAccessException, NoSuchMethodException {

		methodSetup.accept(clazz.getMethod(methodName, type.parameterArray()));

		var handle = methodHandleLookup.findVirtual(clazz, methodName, type);

		return handle;
	}

	/**
	 * Upcall static.
	 *
	 * @param <U>       the generic type
	 * @param clazz     the clazz
	 * @param signature the signature
	 * @return the foreign upcall
	 */
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

	/**
	 * Upcall static.
	 *
	 * @param <U>        the generic type
	 * @param clazz      the clazz
	 * @param methodName the method name
	 * @param returnType the return type
	 * @param argTypes   the arg types
	 * @return the foreign upcall
	 */
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

	/**
	 * Upcall.
	 *
	 * @param <U>       the generic type
	 * @param signature the signature
	 * @param clazz     the clazz
	 * @return the foreign upcall
	 */
	public <U> ForeignUpcall<U> upcall(String signature, Class<U> clazz) {
		return upcallVirtual(signature, clazz, m -> m.setAccessible(makeAccessible));
	}

	/**
	 * Upcall virtual.
	 *
	 * @param <U>         the generic type
	 * @param signature   the signature
	 * @param clazz       the clazz
	 * @param methodSetup the method setup
	 * @return the foreign upcall
	 */
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
