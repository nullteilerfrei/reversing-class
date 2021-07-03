//Deobfuscates String assembly with printf
//@author larsborn
//@category malRE
//@keybinding 
//@menupath 
//@toolbar 

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.OptionalLong;

import org.apache.commons.lang3.ArrayUtils;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;

public class UnSprint extends GhidraScript {
	boolean DEBUG = false;

	public void run() throws Exception {
		String functionAddressString;
		try {
			String def = currentAddress.next().toString();
			functionAddressString = askString("Enter Name", "Enter address of (s)printf function:", def);
		} catch (CancelledException X) {
			return;
		}
		Address functionAddress = toAddr(Long.parseLong(functionAddressString, 16));
		for (Address callAddr : getCallAddresses(functionAddress)) {
			monitor.setMessage(String.format("parsing call at %08X", callAddr.getOffset()));
			dbgMsg("parsing call at %08X", callAddr.getOffset());
			String format = getSecondArgument(callAddr);
			if (format == null) {
				println(String.format("Cannot read format String for call at %08X", callAddr.getOffset()));
				continue;
			}
			int placeHolderCount = countChar(format, '%');
			Integer[] arguments = new Integer[placeHolderCount];
			for (int i = 0; i < placeHolderCount; i++) {
				arguments[i] = i + 3;
			}
			try {
				OptionalLong options[] = getConstantCallArgument(callAddr, ArrayUtils.toPrimitive(arguments));
				if (!validateArguments(options, callAddr)) {
					continue;
				}
				ArrayList<String> array = new ArrayList<String>(options.length);
				dbgMsg("Format: %s", format, arguments);
				for (OptionalLong option : options) {
					Address formatArgAddress = toAddr(option.getAsLong());
					dbgMsg("Argument Address: 0x%08x", formatArgAddress.getOffset());
					byte[] bytes = getOriginalBytes(formatArgAddress, 100);
					if (bytes == null) {
						array.add("__?_?_?__");
						continue;
					}
					String s = new String(readStringUntilZeroByte(bytes));
					dbgMsg("Argument: %s", s, arguments);
					array.add(s);
				}
				String result = String.format(format, array.toArray(new String[0]));
				setComment(callAddr, String.format("Deobfuscated: %s", result));
				createBookmark(callAddr, "DeobfuscatedString", result);

				dbgMsg("Result: %s", result, arguments);
			} catch (UnknownVariableCopy e) {
				println(String.format("Cannot read arguments 3-n for call at %08X", callAddr.getOffset()));
			}
		}
	}

	protected void dbgMsg(String message, Object... args) {
		if (DEBUG) {
			this.println(String.format(message, args));
		}
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

	private String getSecondArgument(Address callAddr) throws Exception {
		int arguments[] = { 2 };
		OptionalLong options[] = getConstantCallArgument(callAddr, arguments);
		if (!validateArguments(options, callAddr)) {
			return null;
		}
		Address stringAddress = toAddr(options[0].getAsLong());
		byte[] s = getOriginalBytes(stringAddress, 100);
		return new String(readStringUntilZeroByte(s));
	}

	private int countChar(String s, char c) {
		int count = 0;
		for (int i = 0; i < s.length(); i++) {
			if (s.charAt(i) == c) {
				count++;
			}
		}
		return count;
	}

	public static byte[] getSliceOfArray(byte[] arr, int start, int end) {
		byte[] slice = new byte[end - start];
		for (int i = 0; i < slice.length; i++) {
			slice[i] = arr[start + i];
		}
		return slice;
	}

	private byte[] readStringUntilZeroByte(byte[] data) throws Exception {
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
		return getSliceOfArray(data, 0, ZeroPos);
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

	private boolean validateArguments(OptionalLong options[], Address callAddr) {
		for (OptionalLong option : options) {
			if (option == null) {
				println(String.format("Argument to call at %08X is null.", callAddr.getOffset()));
				return false;
			}
			if (option.isEmpty()) {
				println(String.format("Argument to call at %08X is not a constant string.", callAddr.getOffset()));
				return false;
			}
		}
		return true;
	}

	private List<Address> getCallAddresses(Address address) {
		List<Address> addresses = new ArrayList<Address>();
		for (Reference ref : getReferencesTo(address)) {
			if (ref.getReferenceType() == RefType.READ) {
				int i = 0;
				for (Instruction instruction : currentProgram.getListing().getInstructions(ref.getFromAddress(),
						true)) {
					if (instruction.getMnemonicString().equals("CALL")) {
						addresses.add(instruction.getAddress());
						break;
					}
					i++;
					if (i > 20) {
						break;
					}
				}
			} else if (ref.getReferenceType() == RefType.INDIRECTION) {
				addresses.add(ref.getFromAddress());
			} else if (ref.getReferenceType() == RefType.UNCONDITIONAL_CALL) {
				addresses.add(ref.getFromAddress());
			}
		}

		return addresses;
	}

	class UnknownVariableCopy extends Exception {
		public UnknownVariableCopy(PcodeOp unknownCode, Address addr) {
			super(String.format("unknown opcode %s for variable copy at %08X", unknownCode.getMnemonic(),
					addr.getOffset()));
		}
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
}
