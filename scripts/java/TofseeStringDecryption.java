//Tofsee String Decryption
//@author larsborn 
//@category malRE
//@keybinding 
//@menupath 
//@toolbar 

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.OptionalLong;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;

public class TofseeStringDecryption extends GhidraScript {

	public void run() throws Exception {
		String deobfuscatorName;
		try {
			deobfuscatorName = askString("Enter Name", "Enter the name of the deobfuscation function below:",
					getFunctionBefore(currentAddress.next()).getName());
		} catch (CancelledException X) {
			return;
		}
		Function deobfuscator = getGlobalFunctions(deobfuscatorName).get(0);
		OUTER_LOOP: for (Address callAddr : getCallAddresses(deobfuscator)) {
			monitor.setMessage(String.format("parsing call at %08X", callAddr.getOffset()));

			int arguments[] = { 2, 3, 4, 5 };
			OptionalLong options[] = getConstantCallArgument(callAddr, arguments);
			for (OptionalLong option : options) {
				if (option.isEmpty()) {
					println(String.format("Argument to call at %08X is not a constant string.", callAddr.getOffset()));
					continue OUTER_LOOP;
				}
			}

			Address bufferAddr = toAddr(options[0].getAsLong());
			int bufferLength = (int) options[1].getAsLong();
			byte xorKey = (byte) options[2].getAsLong();
			byte keyAdd = (byte) options[3].getAsLong();

			byte[] buffer = decrypt(getOriginalBytes(bufferAddr, bufferLength), xorKey, keyAdd);
			String deobfuscated = new String(buffer, StandardCharsets.UTF_8);
			println(String.format("0x%08X : data 0x%08X (len=%d), xor=%02x, add=%02x, \"%s\"", callAddr.getOffset(),
					bufferAddr.getOffset(), bufferLength, xorKey, keyAdd, deobfuscated));

			setComment(callAddr, String.format("Deobfuscated: %s", deobfuscated));
			createBookmark(callAddr, "DeobfuscatedString", deobfuscated);
		}
	}

	private byte[] decrypt(byte[] buffer, byte xorKey, byte keyAdd) {
		byte[] result = new byte[buffer.length];
		for (int i = 0; i < buffer.length; i++) {
			result[i] = (byte) (buffer[i] ^ xorKey);
			xorKey += (i % 2 == 1 ? -1 : 1) + keyAdd;
		}
		return result;
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

	class UnknownVariableCopy extends Exception {
		public UnknownVariableCopy(PcodeOp unknownCode, Address addr) {
			super(String.format("unknown opcode %s for variable copy at %08X", unknownCode.getMnemonic(),
					addr.getOffset()));
		}
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