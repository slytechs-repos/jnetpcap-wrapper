/*
 * Copyright 2024 Sly Technologies Inc
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

	private static final String F_LD_ = "(%03d) %-8s %-16s";
	private static final String F_ST_ = "(%03d) %-8s %-16s";
	private static final String F_LDX = "(%03d) %-8s %-16s";
	private static final String F_STX = "(%03d) %-8s %-16s";
	private static final String F_J__ = "(%03d) %-8s %-16s jt %-4d jf %-4d";
	private static final String F_RET = "(%03d) %-8s %-16s";
	private static final String F_UNK = "(%03d) %-8s %-16s jt %-4d jf %-4d";

	private StringBuilder b = new StringBuilder();
	private int pc;
	private int code;
	private int jt;
	private int jf;
	private long k;

	/**
	 * Formats a BPF instruction into a human-readable string.
	 *
	 * @param index the instruction index
	 * @param i     the BpFilterInstruction
	 * @return the formatted string
	 */
	public String format(int index, BpFilterInstruction i) {
		reset();

		this.pc = index;
		this.code = i.code();
		this.jt = i.jt();
		this.jf = i.jf();
		this.k = i.k();

		return instClass();
	}

	/**
	 * Resets the formatter to its initial state.
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
	 * Formats the BPF instruction class.
	 *
	 * @return the formatted instruction string
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
			// Handle MISC instructions if needed
			break;
		}
		return b.toString();
	}

	/**
	 * Formats a BPF jump instruction.
	 *
	 * @param prefix the jump instruction prefix
	 * @return the formatted jump instruction
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
	 * Formats the mode of the instruction.
	 *
	 * @return the formatted mode string
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
	 * Formats the return value of the instruction.
	 *
	 * @return the formatted return value string
	 */
	private String formatRval() {
		return switch (code & 0x18) {
		case 0x10 -> "[x + " + k + "]";
		default -> "#" + k;
		};
	}

	/**
	 * Formats the source operand of the instruction.
	 *
	 * @return the formatted source operand string
	 */
	private String formatSrc() {
		return switch (code & 0x08) {
		default -> "-{0x" + Integer.toHexString(code) + "}";
		};
	}

	/**
	 * Formats a hexadecimal value.
	 *
	 * @return the formatted hexadecimal value
	 */
	private String formatHex() {
		return String.format("#0x%x", k);
	}

	/**
	 * Constructs a size modifier for the instruction.
	 *
	 * @param prefix the prefix for the size modifier
	 * @return the constructed size modifier string
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
	 * Constructs a formatted string for the instruction.
	 *
	 * @param fmt the format string
	 * @param op  the operation string
	 * @param r   the operand string
	 * @return the constructed formatted string
	 */
	public String fmt(String fmt, String op, String r) {
		return String.format(fmt, pc, op, r, jt + pc + 1, jf + pc + 1, jt, jf);
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return b.toString();
	}
}
