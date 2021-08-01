// Deobfuscate the strings in the Sodinokibi/REvil sample 
// 5f56d5748940e4039053f85978074bde16d64bd5ba97f6f0026ba8172cb29e93
//@author larsborn 
//@category malRE

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.OptionalLong;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;

public class SodinokibiREvilStrings extends GhidraScript {
	public void run() throws Exception {
		String deobfuscatorName;
		try {
			deobfuscatorName = askString("Enter Name", "Enter the name of the deobfuscation function below:",
					getFunctionBefore(currentAddress.next()).getName());
		} catch (CancelledException X) {
			return;
		}
		for (Address callAddr : getCallAddresses(deobfuscatorName)) {
			monitor.setMessage(String.format("parsing call at %08X", callAddr.getOffset()));
			deobfuscateStringForSingleCall(callAddr);
		}
	}

	private void deobfuscateStringForSingleCall(Address callAddr) throws Exception {
		int arguments[] = { 1, 2, 3, 4, 5 };
		OptionalLong options[] = getConstantCallArgument(callAddr, arguments);
		if (options[0].isEmpty() || options[1].isEmpty() || options[2].isEmpty() || options[3].isEmpty()) {
			println(String.format("Argument to call at %08X is not a constant string.", callAddr.getOffset()));
			return;
		}

		long blobAddress = options[0].getAsLong();
		long offset = options[1].getAsLong();
		long keySize = options[2].getAsLong();
		long stringSize = options[3].getAsLong();
		if (stringSize == 0 || keySize == 0) {
			return;
		}

		byte[] deobfuscatedData = deobfuscate(blobAddress, offset, keySize, stringSize);
		// hexdump(deobfuscatedData);

		String deobfuscatedString = asciiDammit(deobfuscatedData, (int) stringSize);
		makeDataAvailableInUserInterface(callAddr, deobfuscatedString,
				options[4].isEmpty() ? 0 : options[4].getAsLong());
	}

	private byte[] deobfuscate(long blobAddress, long offset, long keySize, long stringSize) {
		byte[] key = getOriginalBytes(toAddr(blobAddress + offset), (int) keySize);
		byte[] data = getOriginalBytes(toAddr(blobAddress + offset + keySize), (int) stringSize);
		return new RC4(key).decrypt(data);
	}

	public void makeDataAvailableInUserInterface(Address callAddr, String deobfuscatedString, long resultAddr) {
		println(String.format("%08X : %s", callAddr.getOffset(), deobfuscatedString));
		setComment(callAddr, String.format("Deobfuscated: %s", deobfuscatedString));
		createBookmark(callAddr, "DeobfuscatedString", deobfuscatedString);
		if (resultAddr > 0) {
			Address address = currentAddress.getNewAddress(resultAddr);
			Function function = getFunctionContaining(callAddr);
			StackFrame stackFrame = function.getStackFrame();
			for (Variable variable : stackFrame.getLocals()) {
				if (variable.getStackOffset() == (int) address.getOffset()) {
					try {
						variable.setName(sanitize(deobfuscatedString),
								ghidra.program.model.symbol.SourceType.USER_DEFINED);
					} catch (DuplicateNameException | InvalidInputException e) {
						println("Variable renaming failed for " + deobfuscatedString);
					}
				}
			}
		}
	}

	private String sanitize(String s) {
		return s.replace("\\", "_").replace(" ", "-").replace("\n", "_").replace("\t", "_").replace("\r", "_");
	}

	public String asciiDammit(byte[] data, int len) {
		boolean isWide = true;
		byte[] nonWide = new byte[len / 2];
		for (int i = 0; i < len / 2; i++) {
			if (data[i * 2 + 1] != '\0') {
				isWide = false;
				break;
			}
			nonWide[i] = data[i * 2];
		}
		return new String(isWide ? nonWide : data);
	}

	class UnknownVariableCopy extends Exception {
		public UnknownVariableCopy(PcodeOp unknownCode, Address addr) {
			super(String.format("unknown opcode %s for variable copy at %08X", unknownCode.getMnemonic(),
					addr.getOffset()));
		}
	}

	private OptionalLong traceVarnodeValue(Varnode argument) throws UnknownVariableCopy {
		while (!argument.isConstant()) {
			PcodeOp ins = argument.getDef();
			if (ins == null)
				break;
			switch (ins.getOpcode()) {
			case PcodeOp.CAST:
			case PcodeOp.COPY:
				argument = ins.getInput(0);
				break;
			case PcodeOp.PTRSUB:
			case PcodeOp.PTRADD:
				argument = ins.getInput(1);
				break;
			case PcodeOp.INT_MULT:
			case PcodeOp.MULTIEQUAL:
				// known cases where an array is indexed
				return OptionalLong.empty();
			default:
				// don't know how to handle this yet.
				throw new UnknownVariableCopy(ins, argument.getAddress());
			}
		}
		return OptionalLong.of(argument.getOffset());
	}

	private OptionalLong[] getConstantCallArgument(Address addr, int[] argumentIndices)
			throws IllegalStateException, UnknownVariableCopy {
		int argumentPos = 0;
		OptionalLong argumentValues[] = new OptionalLong[argumentIndices.length];
		Function caller = getFunctionBefore(addr);
		if (caller == null)
			throw new IllegalStateException();

		DecompInterface decompInterface = new DecompInterface();
		decompInterface.openProgram(currentProgram);
		DecompileResults decompileResults = decompInterface.decompileFunction(caller, 120, monitor);
		if (!decompileResults.decompileCompleted())
			throw new IllegalStateException();

		HighFunction highFunction = decompileResults.getHighFunction();
		Iterator<PcodeOpAST> pCodes = highFunction.getPcodeOps(addr);
		while (pCodes.hasNext()) {
			PcodeOpAST instruction = pCodes.next();
			if (instruction.getOpcode() == PcodeOp.CALL) {
				for (int index : argumentIndices) {
					argumentValues[argumentPos] = traceVarnodeValue(instruction.getInput(index));
					argumentPos++;
				}
			}
		}
		return argumentValues;
	}

	private byte[] getOriginalBytes(Address addr, int size) {
		MemoryBlock stringMemoryBlock = currentProgram.getMemory().getBlock(addr);
		if (stringMemoryBlock == null)
			return null;
		FileBytes fileBytes = currentProgram.getMemory().getAllFileBytes().get(0);
		MemoryBlockSourceInfo memoryInformation = stringMemoryBlock.getSourceInfos().get(0);
		long fileOffset = addr.getOffset() - memoryInformation.getMinAddress().getOffset()
				+ memoryInformation.getFileBytesOffset();
		try {
			byte[] result = new byte[size];
			fileBytes.getOriginalBytes(fileOffset, result);
			return result;
		} catch (IOException X) {
			return null;
		}
	}

	private List<Address> getCallAddresses(String functionName) {
		List<Address> addresses = new ArrayList<Address>();
		Function deobfuscator = getGlobalFunctions(functionName).get(0);
		for (Reference ref : getReferencesTo(deobfuscator.getEntryPoint())) {
			if (ref.getReferenceType() != RefType.UNCONDITIONAL_CALL)
				continue;
			addresses.add(ref.getFromAddress());
		}

		return addresses;
	}

	private void setComment(Address address, String comment) {
		setPlateComentToDisassembly(address, comment);
		setCommentToDecompiledCode(address, comment);
	}

	private void setPlateComentToDisassembly(Address address, String comment) {
		currentProgram.getListing().getCodeUnitAt(address).setComment(CodeUnit.PLATE_COMMENT, comment);
	}

	private void setCommentToDecompiledCode(Address address, String comment) {
		currentProgram.getListing().getCodeUnitAt(address).setComment(CodeUnit.PRE_COMMENT, comment);
	}

	private void hexdump(byte[] data) {
		int lineWidth = 16;
		for (int i = 0; i < Math.ceil((double) data.length / lineWidth); i++) {
			int offset = i * lineWidth;
			// address
			print(String.format("%08x  ", offset));

			// actual hex dump
			for (int j = 0; j < lineWidth; j++) {
				if (lineWidth / 2 == j) {
					print(" ");
				}
				if (offset + j < data.length) {
					print(String.format("%02x ", data[offset + j]));
				} else {
					print("   ");
				}
			}

			// printable
			print(" |");
			for (int j = 0; j < lineWidth; j++) {
				if (offset + j < data.length) {
					if (isPrintable(data[offset + j])) {
						print(String.format("%c", data[offset + j]));
					} else {
						print(".");
					}
				}
			}
			print("|\n");
		}
	}

	private boolean isPrintable(byte c) {
		return !(c < 0x20 || c > 127);
	}

	private class RC4 {
		private final byte[] S = new byte[256];
		private final byte[] T = new byte[256];

		public RC4(final byte[] key) {
			if (key.length < 1 || key.length > 256) {
				throw new IllegalArgumentException("invalid key length");
			}
			for (int i = 0; i < 0x100; i++) {
				S[i] = (byte) i;
				T[i] = key[i % key.length];
			}
			int j = 0;
			for (int i = 0; i < 0x100; i++) {
				j = (j + S[i] + T[i]) & 0xFF;
				swap(i, j);
			}
		}

		public byte[] encrypt(final byte[] plainText) {
			final byte[] cipherText = new byte[plainText.length];
			int i = 0, j = 0;
			for (int pos = 0; pos < plainText.length; pos++) {
				i = (i + 1) & 0xFF;
				j = (j + S[i]) & 0xFF;
				swap(i, j);
				cipherText[pos] = (byte) (plainText[pos] ^ S[(S[i] + S[j]) & 0xFF]);
			}
			return cipherText;
		}

		public byte[] decrypt(final byte[] cipherText) {
			return encrypt(cipherText);
		}

		private void swap(int i, int j) {
			byte tmp = S[j];
			S[j] = S[i];
			S[i] = tmp;
		}
	}
}
