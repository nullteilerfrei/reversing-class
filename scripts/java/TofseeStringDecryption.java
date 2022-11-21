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
import ghidra.util.exception.CancelledException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

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
		if (deobfuscator == null) {
			println("Deobfuscation function not found");
			return;
		}
		OUTER_LOOP: for (Address callAddr : getCallAddresses(deobfuscator)) {
			monitor.setMessage(String.format("parsing call at %08X", callAddr.getOffset()));

			int arguments[] = { 2, 3, 4, 5 };
			OptionalLong options[];
			try {
				options = getConstantCallArgument(callAddr, arguments);
			} catch (IllegalStateException e) {
				println(String.format("Cannot decompile call at %08X", callAddr.getOffset()));
				continue;
			} catch (UnknownVariableCopy e) {
				println(String.format("Cannot decompile call at %08X: %s", callAddr.getOffset(), e.toString()));
				continue;
			}
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
			println(String.format("0x%08X : data 0x%08X (len=%d), xor=%02x, add=%02x", callAddr.getOffset(),
					bufferAddr.getOffset(), bufferLength, xorKey, keyAdd));
			hexdump(buffer);

			String deobfuscated = new String(buffer, StandardCharsets.UTF_8).replace("\0", "");
			setComment(callAddr, String.format("Deobfuscated: %s", deobfuscated));
			createBookmark(callAddr, "DeobfuscatedString", deobfuscated);
		}
	}

	private byte[] decrypt(byte[] buffer, byte xorKey, byte keyAdd) {
		byte[] result = new byte[buffer.length];
		for (int i = 0; i < buffer.length; i++) {
			byte current = (byte) (buffer[i] ^ xorKey);
			if (current != 0) {
				result[i] = current;
			}
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

	private boolean isPrintable(byte c) {
		return !(c < 0x20 || c > 127);
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
}
