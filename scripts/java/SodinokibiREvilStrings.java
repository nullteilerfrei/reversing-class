// Deobfuscate the strings in the Sodinokibi/REvil sample 
// 5f56d5748940e4039053f85978074bde16d64bd5ba97f6f0026ba8172cb29e93
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
		OUTER_LOOP: for (Address callAddr : getCallAddresses(deobfuscatorName)) {
			monitor.setMessage(String.format("parsing call at %08X", callAddr.getOffset()));

			int arguments[] = { 1, 2, 3, 4 };
			OptionalLong options[] = getConstantCallArgument(callAddr, arguments);
			for (OptionalLong option : options) {
				if (option.isEmpty()) {
					println(String.format("Argument to call at %08X is not a constant string.", callAddr.getOffset()));
					continue OUTER_LOOP;
				}
			}

			long blobAddress = options[0].getAsLong();
			int keyOffset = (int) options[1].getAsLong();
			int keyLength = (int) options[2].getAsLong();
			int dataLength = (int) options[3].getAsLong();
			if (dataLength == 0 || keyLength == 0)
				continue;

			byte[] key = getOriginalBytes(toAddr(blobAddress + keyOffset), keyLength);
			byte[] data = getOriginalBytes(toAddr(blobAddress + keyOffset + keyLength), dataLength);
			byte[] decrypted = new RC4(key).encrypt(data);

			String deobfuscated = AsciiDammit(decrypted, dataLength);
			println(String.format("%08X : %s", callAddr.getOffset(), deobfuscated));
			setComment(callAddr, String.format("Deobfuscated: %s", deobfuscated));
			createBookmark(callAddr, "DeobfuscatedString", deobfuscated);
		}
	}

	private String AsciiDammit(byte[] data, int len) {
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
}
