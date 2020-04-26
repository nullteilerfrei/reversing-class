// Deobfuscate the strings in the KpotStealer sample 
// 67f8302a2fd28d15f62d6d20d748bfe350334e5353cbdef112bd1f8231b5599d
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

public class KpotStealerStrings extends GhidraScript {
	private byte[] deobfuscateString(byte[] data, byte[] key) {
		final byte[] ret = new byte[data.length];
		for (int k = 0; k < data.length; k++)
			ret[k] = (byte) (data[k] ^ key[k % key.length]);
		return ret;
	}

	public OptionalLong findGlobalBufferAddress(Function func, int searchDepth) {
		int i = 0;
		for (Instruction instruction : currentProgram.getListing().getInstructions(func.getEntryPoint(), true)) {
			if (instruction.getMnemonicString().equals("LEA")) {
				// the first operand of LEA is the target register, the second is the address
				if ((instruction.getOperandType(0) & OperandType.REGISTER) == OperandType.REGISTER
						&& (instruction.getOperandType(1) & OperandType.ADDRESS) == OperandType.ADDRESS
						&& (instruction.getOperandType(1) & OperandType.DYNAMIC) == OperandType.DYNAMIC) {
					// this gets the "objects" for the second argument which. This is an array of
					// values:
					//
					// LEA globalBufferIndex,[globalBufferIndex*0x8 + GLOBAL_BUFFER]
					// Index 0: globalBufferIndex
					// Index 1: 0x8
					// Index 2: GLOBAL_BUFFER
					String hexEncoded = instruction.getOpObjects(1)[2].toString();
					return OptionalLong.of(Long.decode(hexEncoded));
				}
			}
			i++;
			if (i > searchDepth)
				break;
		}
		return OptionalLong.empty();
	}

	public void run() throws Exception {
		String deobfuscatorName = "EvStringDeobfuscate";
		try {
			deobfuscatorName = askString("Enter Name", "Enter the name of the deobfuscation function below:",
					getFunctionBefore(currentAddress.next()).getName());
		} catch (CancelledException X) {
			return;
		}
		Function deobfuscator = getGlobalFunctions(deobfuscatorName).get(0);
		long globalBufferPtr;
		OptionalLong optionalGlobalBufferPtr = findGlobalBufferAddress(deobfuscator, 0x10);
		if (optionalGlobalBufferPtr.isEmpty()) {
			try {
				globalBufferPtr = askInt("Enter Global Buffer Address",
						"Cannot automatically determine global buffer address, specify it manually:");
			} catch (CancelledException X) {
				return;
			}
		} else {
			globalBufferPtr = optionalGlobalBufferPtr.getAsLong();
		}
		println(String.format("globalBufferPtr=%08X.", globalBufferPtr));
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

				long globalBufferIndex = options[0].getAsLong();
				byte structContent[] = getOriginalBytes(toAddr(globalBufferPtr + globalBufferIndex * 8), 8);
				byte xorKey[] = { structContent[0] };
				int dataLength = (structContent[2] & 0xff) | (structContent[3] & 0xff) << 8;
				int encryptedPtr = (structContent[4] & 0xff) | ((structContent[5] & 0xff) << 8)
						| ((structContent[6] & 0xff) << 16) | ((structContent[7] & 0xff) << 24);

				byte[] obfuscatedBuffer = getOriginalBytes(toAddr(encryptedPtr), dataLength);
				byte decrypted[] = deobfuscateString(obfuscatedBuffer, xorKey);

				String deobfuscated = AsciiDammit(decrypted, dataLength);
				println(String.format("%08X (off=%d, ptr=%d, len=%d): %s", callAddr.getOffset(), globalBufferIndex,
						encryptedPtr, dataLength, deobfuscated));
				setComment(callAddr, String.format("Deobfuscated: %s", deobfuscated));
				createBookmark(callAddr, "DeobfuscatedString", deobfuscated);
			} catch (UnknownVariableCopy e) {
				println(String.format("UnknownVariableCopy at %08X.", callAddr.getOffset()));

			} catch (IllegalStateException e) {
				println(String.format("IllegalStateException at %08X.", callAddr.getOffset()));
			}
		}
	}

	public void hexdump(byte[] msg) {
		for (int j = 1; j < msg.length + 1; j++) {
			if (j % 8 == 1 || j == 0) {
				if (j != 0) {
					println("");
				}
				print(String.format("0%d\t|\t", j / 8));
			}
			print(String.format("%02X", msg[j - 1]));
			if (j % 4 == 0) {
				print(" ");
			}
		}
		println("");
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

	private List<Address> getCallAddresses(Function func) {
		List<Address> addresses = new ArrayList<Address>();
		for (Reference ref : getReferencesTo(func.getEntryPoint())) {
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
