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

/**
 * Used to format binary BpFilter program instructions.
 */
@SuppressWarnings("unused")
class BpFilterFormatter {

	/** The Constant F_LD_. */
	private static final String F_LD_ = "(%03d) %-8s %-16s";
	
	/** The Constant F_ST_. */
	private static final String F_ST_ = "(%03d) %-8s %-16s";
	
	/** The Constant F_LDX. */
	private static final String F_LDX = "(%03d) %-8s %-16s";
	
	/** The Constant F_STX. */
	private static final String F_STX = "(%03d) %-8s %-16s";
	
	/** The Constant F_J__. */
	private static final String F_J__ = "(%03d) %-8s %-16s jt %-4d jf %-4d";
	
	/** The Constant F_RET. */
	private static final String F_RET = "(%03d) %-8s %-16s";
	
	/** The Constant F_UNK. */
	private static final String F_UNK = "(%03d) %-8s %-16s jt %-4d jf %-4d";

	/** The b. */
	StringBuilder b = new StringBuilder();
	
	/** The pc. */
	private int pc;
	
	/** The code. */
	private int code;
	
	/** The jt. */
	private int jt;
	
	/** The jf. */
	private int jf;
	
	/** The k. */
	private long k;

	/**
	 * Aa.
	 *
	 * @return the string
	 */
	private String aa() {
		return "4*(" + formatSrc() + "&0xf)";
	}

	/**
	 * Fmt.
	 *
	 * @param fmt the fmt
	 * @param op  the op
	 * @param r   the r
	 * @return the string
	 */
	public String fmt(String fmt, String op, String r) {
		return String.format(fmt, pc, op, r, jt + pc + 1, jf + pc + 1, jt, jf);
//			return String.format("[0x%02X] " + fmt + " k=%7$d", full, pc, op, r, jt + pc + 1, jf + pc + 1, jt, jf);
	}

	/**
	 * Format.
	 *
	 * @param index the index
	 * @param i     the i
	 * @return the string
	 */
	public String format(int index, BpFilterInstruction i) {
		reset();

		this.pc = index;
		code = i.code();
		jt = i.jt();
		jf = i.jf();
		k = i.k();

		return instClass();
	}

	/**
	 * Format hex.
	 *
	 * @return the string
	 */
	private String formatHex() {
		return String.format("#0x%x", k);
	}

	/**
	 * Format jmp.
	 *
	 * @param prefix the prefix
	 * @return the string
	 */
	private String formatJmp(String prefix) {
		return prefix + switch (code & 0xf0) {
		case 0x00 -> "a";
		case 0x10 -> "eq";
		case 0x20 -> "gt";
		case 0x30 -> "ge";
		case 0x40 -> "set";
		default -> "-{0x" + Integer.toHexString(code) + "}";
		};
	}

	/**
	 * Format mode.
	 *
	 * @return the string
	 */
	private String formatMode() {
		int mode = code & 0xe0;
		return switch (mode) {
		case 0x00 -> "0x#" + Long.toHexString(k); // BPF_IMM
		case 0x20 -> "[" + k + "]"; // BPF_ABS
		case 0x40 -> "[x + " + k + "]"; // BPF_IND
		case 0x60 -> "[x + " + k + "]"; // BPF_MEM
		case 0x80 -> "[x + " + k + "]"; // BPF_LEN
		case 0xa0 -> "4*([" + k + "]&0xf)"; // BPF_MSH
		case 0xc0 -> "[x + " + k + "]"; // BPF_MSH
		default -> "-{0x" + Integer.toHexString(code) + "}";
		};

	}

	/**
	 * Format rval.
	 *
	 * @return the string
	 */
	private String formatRval() {
		return switch (code & 0x18) {
		case 0x10 -> "[x + " + k + "]";
		default -> "#" + k + "";
		};

	}

	/**
	 * Format src.
	 *
	 * @return the string
	 */
	private String formatSrc() {
		return switch (code & 0x08) {
//			case 0x00 -> "[" + k + "]";
//			case 0x08 -> "[x + " + k + "]";
		default -> "-{0x" + Integer.toHexString(code) + "}";
		};

	}

	/**
	 * Inst class.
	 *
	 * @return the string
	 */
	private synchronized String instClass() {

		switch (code & 0x07) {
		case 0x00: // LD
			return fmt(F_LD_, sizeModifier("ld"), formatMode());
		case 0x01: // LDX
			return fmt(F_LDX, sizeModifier("ldx"), formatMode());
		case 0x02: // ST
			return fmt(F_ST_, sizeModifier("st"), formatMode());
		case 0x03: // STX
			return fmt(F_STX, sizeModifier("stx"), formatMode());
		case 0x04: // ALU
			return fmt(F_UNK, "st|stx|alu", formatHex());
		case 0x05: // JMP
			return fmt(F_J__, formatJmp("j"), formatHex());
		case 0x06: // RET
			return fmt(F_RET, "ret", formatRval());
		case 0x07: // MISC
		}

		return b.toString();
	}

	/**
	 * Reset.
	 */
	public void reset() {
		b.setLength(0);
		pc = 0;
		code = 0;
		jt = 0;
		jf = 0;
		k = 0;
	}

	/**
	 * Size modifier.
	 *
	 * @param prefix the prefix
	 * @return the string
	 */
	private String sizeModifier(String prefix) {
		return prefix + switch (code & 0x18) {
		case 0x00 -> "w";
		case 0x08 -> "h";
		case 0x10 -> "b";
		default -> "-{0x" + Integer.toHexString(code) + "}";
		};
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return b.toString();
	}
}