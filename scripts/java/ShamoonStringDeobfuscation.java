//Reverts String Obfuscation in Shamoon 2016 samples
//@author larsborn
//@category malRE
//@keybinding 
//@menupath 
//@toolbar 

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.OptionalInt;
import java.util.OptionalLong;

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

public class ShamoonStringDeobfuscation extends GhidraScript {
	private byte[] Deobfuscate(byte[] data, int key) {
		byte[] ret = new byte[data.length];
		for (int i = 0; i < data.length; i++) {
			ret[i] = (byte) (data[i] + key);
		}
		return ret;
	}

	public void run() throws Exception {
		String deobfuscatorName;
		try {
			deobfuscatorName = askString("Enter Name", "Enter the name of the deobfuscation function below:",
					getFunctionBefore(currentAddress.next()).getName());
		} catch (CancelledException X) {
			return;
		}
		List<Function> lst = getGlobalFunctions(deobfuscatorName);
		if (lst.size() != 1) {
			println(String.format("Number of functions %s: %d", deobfuscatorName, lst.size()));
			return;
		}
		Function deobfuscator = lst.get(0);
		OUTER_LOOP: for (Address callAddr : getCallAddresses(deobfuscator)) {
			monitor.setMessage(String.format("parsing call at %08X", callAddr.getOffset()));

			int arguments[] = { 1, 2 };
			OptionalLong options[] = getConstantCallArgument(callAddr, arguments);
			for (OptionalLong option : options) {
				if (option == null) {
					println(String.format("Argument to call at %08X is null.", callAddr.getOffset()));
					continue OUTER_LOOP;
				}
				if (option.isEmpty()) {
					println(String.format("Argument to call at %08X is not a constant string.", callAddr.getOffset()));
					continue OUTER_LOOP;
				}
			}
			long obfuscatedPtr = options[0].getAsLong();
			int key = (int) options[1].getAsLong();
			byte[] obfuscatedData = getOriginalBytes(toAddr(obfuscatedPtr), 10240);
			if (obfuscatedData.length < 2) {
				continue;
			}
			boolean isWideString = obfuscatedData[1] == '\0';
			OptionalInt optionalLen = isWideString ? FindWideStringEnd(obfuscatedData) : FindStringEnd(obfuscatedData);
			if (optionalLen.isEmpty()) {
				println(String.format("Cannot determine string length at %08X.", callAddr.getOffset()));
				continue;
			}
			int len = optionalLen.getAsInt();
			byte[] obfuscatedAsciiString = new byte[len];
			for (int i = 0; i < len; i++) {
				obfuscatedAsciiString[i] = isWideString ? obfuscatedData[i * 2] : obfuscatedData[i];
			}
			if (key > 256) {
				key -= 65536;
			}
			String clearString = new String(Deobfuscate(obfuscatedAsciiString, key));
			println(String.format("%08X %d (%d): %s", obfuscatedPtr, key, len, clearString));
			setComment(callAddr, String.format("Deobfuscated: %s", clearString.replace('\0', '|')));
			createBookmark(callAddr, "DeobfuscatedString", clearString);
		}
	}

	private OptionalInt FindStringEnd(byte[] data) {
		for (int i = 0; i < data.length; i++) {
			if (data[i] == '\0') {
				return OptionalInt.of(i);
			}
		}
		return OptionalInt.empty();
	}

	private OptionalInt FindWideStringEnd(byte[] data) {
		for (int i = 0; i < data.length / 2; i++) {
			if (data[i * 2 + 1] != '\0') {
				return OptionalInt.empty();
			}
			if (data[i * 2] == '\0') {
				return OptionalInt.of(i);
			}
		}
		return OptionalInt.empty();
	}

	private List<Address> getCallAddresses(Function deobfuscator) {
		List<Address> addresses = new ArrayList<Address>();
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

}
