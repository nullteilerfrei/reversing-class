// Deobfuscate the strings in the ZLoader sample 
// 4029f9fcba1c53d86f2c59f07d5657930bd5ee64cca4c5929cbd3142484e815a
//@author larsborn 
//@category Strings

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.OptionalLong;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;

public class ZLoaderStrings extends GhidraScript {
	private byte[] deobfuscateString(byte[] data, byte[] key) {
		final byte[] ret = new byte[data.length];
		for (int k = 0; k < data.length; k++)
			ret[k] = (byte) (data[k] ^ key[k % key.length]);
		return ret;
	}

	public Boolean isGlobalBufferAccess(Instruction instruction) {
		return (instruction.getOperandType(0) & OperandType.REGISTER) == OperandType.REGISTER
				&& (instruction.getOperandType(1) & OperandType.ADDRESS) == OperandType.ADDRESS
				&& (instruction.getOperandType(1) & OperandType.DYNAMIC) == OperandType.DYNAMIC;
	}

	public void run() throws Exception {
		String deobfuscatorName;
		try {
			deobfuscatorName = askString("Enter Name", "Enter the name of the deobfuscation function below:",
					getFunctionBefore(currentAddress.next()).getName());
		} catch (CancelledException X) {
			return;
		}
		Function deobfuscator = getGlobalFunctions(deobfuscatorName).get(0);
		// TODO use first instruction with MOVZX to identify XOr key
		byte xorKey[] = { 0x59, 0x49, 0x2c, 0x72, 0x54, 0x66, 0x79, 0x23, 0x46, 0x33, 0x4d, 0x61, 0x71, 0x31, 0x33,
				0x69, 0x66 };
		OUTER_LOOP: for (Address callAddr : getCallAddresses(deobfuscator)) {
			monitor.setMessage(String.format("parsing call at %08X", callAddr.getOffset()));
			int arguments[] = { 1 };
			try {
				OptionalLong options[] = getConstantCallArgument(callAddr, arguments);
				for (OptionalLong option : options) {
					if (option == null || option.isEmpty()) {
						println(String.format("Argument to call at %08X is not a constant value.",
								callAddr.getOffset()));
						continue OUTER_LOOP;
					}
				}

				Address obfuscatedDataAddress = toAddr(options[0].getAsLong());
				byte obfuscatedBuffer[] = getOriginalBytes(obfuscatedDataAddress, 0x100);
				if (obfuscatedBuffer[1] == 0) { // indicates wide-string
					obfuscatedBuffer = readWideString(obfuscatedBuffer, 0x100);
				}

				byte decrypted[] = deobfuscateString(obfuscatedBuffer, xorKey);
				String deobfuscated = readUntilZeroByte(decrypted);
				println(String.format("0x%08X %s", callAddr.getOffset(), deobfuscated));
				setComment(callAddr, String.format("Deobfuscated: %s", deobfuscated));
				createBookmark(callAddr, "DeobfuscatedString", deobfuscated);
			} catch (UnknownVariableCopy e) {
				println(String.format("UnknownVariableCopy at %08X.", callAddr.getOffset()));
			} catch (IllegalStateException e) {
				println(String.format("IllegalStateException at %08X.", callAddr.getOffset()));
			}
		}
	}

	private byte[] readWideString(byte[] data, int len) {
		byte[] ret = new byte[len];
		for (int i = 0; i < len / 2; i++) {
			if (data[i * 2 + 1] != '\0') {
				return ret;
			}
			ret[i] = data[i * 2];
		}
		return ret;
	}

	private static byte[] getSliceOfArray(byte[] arr, int start, int end) {
		byte[] slice = new byte[end - start];
		for (int i = 0; i < slice.length; i++) {
			slice[i] = arr[start + i];
		}
		return slice;
	}

	private String readUntilZeroByte(byte[] data) throws Exception {
		int ZeroPos = -1;
		for (int i = 0; i < data.length; i++) {
			if (data[i] == '\0') {
				ZeroPos = i;
				break;
			}
		}
		if (ZeroPos == -1) {
			throw new Exception("Cannot find Zero termination");
		}
		return new String(getSliceOfArray(data, 0, ZeroPos));
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
		Memory m = getCurrentProgram().getMemory();
		MemoryBlock b = m.getBlock(addr);
		if (b == null)
			return null;
		MemoryBlockSourceInfo info = b.getSourceInfos().get(0);
		long fileOffset = addr.getOffset() - info.getMinAddress().getOffset() + info.getFileBytesOffset();
		FileBytes bytes = m.getAllFileBytes().get(0);
		try {
			byte[] result = new byte[size];
			bytes.getOriginalBytes(fileOffset, result);
			return result;
		} catch (IOException X) {
			return null;
		}
	}

	private List<Address> getCallAddresses(Function func) {
		List<Address> addresses = new ArrayList<Address>();
		for (Reference ref : getReferencesTo(func.getEntryPoint())) {
			RefType refType = ref.getReferenceType();
			if (refType != RefType.UNCONDITIONAL_CALL && refType != RefType.CONDITIONAL_CALL)
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
}
