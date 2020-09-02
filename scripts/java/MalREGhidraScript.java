//Base class for MalRE scripts with an extended flat API.
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.OptionalLong;
import java.util.regex.Pattern;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.ContextEvaluatorAdapter;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.exception.CancelledException;

public abstract class MalREGhidraScript extends GhidraScript {

	static boolean DEBUG = false;
	
	class UnknownVariableCopy extends Exception {
		public UnknownVariableCopy(PcodeOp unknownCode, Address addr) {
			super(String.format("unknown opcode %s for variable copy at %08X", unknownCode.getMnemonic(),
					addr.getOffset()));
		}
	}

	class VariableValue {
		Long value;
		Map<Long, Long> membersByOffset;
		Map<String, Long> membersByName;
		HighVariable variable;
		public VariableValue(HighVariable variable) {
			this.membersByOffset = new HashMap<Long, Long>();
			this.membersByName = new HashMap<String, Long>();
			this.value = null;
			this.variable = variable;
		}
	}
	
	protected void dbgMsg(String message, Object... args) {
		if (DEBUG) logMsg(message, args);
	}
	
	protected void logMsg(String message, Object... args) {
		this.println(String.format(message, args));
	}

	private DecompileResults decompileFunctionAround(Address addr) throws IllegalStateException {
		Function caller = getFunctionBefore(addr);
		if (caller == null)
			throw new IllegalStateException();
		DecompInterface decompInterface = new DecompInterface();
		decompInterface.openProgram(currentProgram);
		DecompileResults decompileResults = decompInterface.decompileFunction(caller, 120, monitor);
		if (!decompileResults.decompileCompleted())
			throw new IllegalStateException();
		return decompileResults;
	}
	
	protected OptionalLong getConstantCallArgument(Address addr, int index)
			throws IllegalStateException, UnknownVariableCopy {
		HighFunction highFunction = decompileFunctionAround(addr).getHighFunction();
		Iterator<PcodeOpAST> pCodes = highFunction.getPcodeOps(addr);
		while (pCodes.hasNext()) {
			PcodeOpAST instruction = pCodes.next();
			if (instruction.getOpcode() == PcodeOp.CALL) {
				return traceVarnodeValue(instruction.getInput(index));
			}
		}
		throw new IllegalStateException();
	}

	protected Map<Long, String> getMemberNames(DataType dt) {
		DataTypeManager dtm = dt.getDataTypeManager();
		Iterator<Structure> allStructs= dtm.getAllStructures();
		while (allStructs.hasNext()) {
			Structure struct = allStructs.next();
			if (PointerDataType.getPointer(struct, dtm).isEquivalent(dt)) {
				Map<Long, String> offsetMap = new HashMap<Long, String>();
				for (DataTypeComponent dtc : struct.getComponents())
					offsetMap.put((long) dtc.getOffset(), dtc.getFieldName());
				return offsetMap;
			}
		}
		return null;
	}
	
	protected VariableValue getVariableCallArgument(Address addr, int index) throws IllegalStateException {
		DecompileResults decompiled = decompileFunctionAround(addr);
		Iterator<PcodeOpAST> pCodes = decompiled.getHighFunction().getPcodeOps(addr);
		HighVariable argument = null;
		while (pCodes.hasNext()) {
			PcodeOpAST instruction = pCodes.next();
			if (instruction.getOpcode() == PcodeOp.CALL) {
				argument = instruction.getInput(index).getHigh();
				break;
			}
		}
		if (argument == null)
			return null;

		Map<Long, String> memberMap = this.getMemberNames(argument.getDataType());
		VariableValue value = new VariableValue(argument);

		for (ClangLine cl : DecompilerUtils.toLines(decompiled.getCCodeMarkup())) {

			Long constant = null;
			Long offset = null;

			boolean hasUniqueConstant = false;
			boolean involvesArgumentVariable = false;
			boolean isAssignment = false;
			boolean happensBeforeCall = true;

			for (ClangToken ct: cl.getAllTokens()) {
				Address maxAddr = ct.getMaxAddress();
				if (maxAddr != null && maxAddr.getOffset() >= addr.getOffset()) {
					happensBeforeCall = false;
					break;
				}
				if (!involvesArgumentVariable && ct.getHighVariable() == argument)
					involvesArgumentVariable = true;
			}

			if (!involvesArgumentVariable || !happensBeforeCall) 
				continue;

			for (ClangToken ct: cl.getAllTokens()) {
				PcodeOp pc = ct.getPcodeOp();
				Varnode vn = ct.getVarnode();
				if (pc != null) {
					switch(pc.getOpcode()) {
					case PcodeOp.STORE:
						isAssignment = true;
						break;
					case PcodeOp.PTRSUB:
						if (ct.getHighVariable() == argument) {
							// assignment to a member
							offset = pc.getInput(1).getOffset();
						} else if (pc.getInput(0).isConstant()) {
							// a global constant is assigned
							vn = pc.getInput(1);
						} 
						break;
					default:
						break;
					}
				}
				if (vn != null) {
					if (!vn.isConstant()) {
						continue;
					}
					if (hasUniqueConstant && vn.getOffset() != constant) {
						hasUniqueConstant = false;
						break;
					}
					constant = vn.getOffset();
					hasUniqueConstant = true;
				}
			}

			if (!hasUniqueConstant) {
				dbgMsg("ignoring, no constant value: %s", cl.toString());
				continue;
			}

			if (!isAssignment) {
				dbgMsg("ignoring, not an assignment: %s", cl.toString());
				continue;
			}

			if (offset == null) {
				value.value = constant;
			} else {
				value.membersByOffset.put(offset, constant);
				if (memberMap.containsKey(offset)) {
					value.membersByName.put(memberMap.get(offset), constant);
				}
			}
		}

		return value;
	}

	protected Function askForFunction() {
		String deobfuscatorName;
		Namespace deobfuscatorNamespace = currentProgram.getGlobalNamespace();
		
		try {
			Function currentFunction = getFunctionBefore(currentAddress.next());
			String currentFunctionName = currentFunction.getName();
			String nameSpaceName = currentFunction.getParentNamespace().getName();
			if (nameSpaceName.compareTo(deobfuscatorNamespace.getName()) != 0)
				currentFunctionName = nameSpaceName + Namespace.NAMESPACE_DELIMITER + currentFunctionName;
			deobfuscatorName = askString(
					"Enter Name",
					"Enter the name of the deobfuscation function below:",
					currentFunctionName
			);
		} catch (CancelledException X) {
			return null;
		}

		if (deobfuscatorName.contains(Namespace.NAMESPACE_DELIMITER)) {
			String split[] = deobfuscatorName.split(Pattern.quote(Namespace.NAMESPACE_DELIMITER), 2);
			deobfuscatorNamespace = getNamespace(currentProgram.getGlobalNamespace(), split[0]);
			deobfuscatorName = split[1];
		}

		try {
			Symbol deobfuscatorSymbol = this
					.getCurrentProgram()
					.getSymbolTable()
					.getLabelOrFunctionSymbols(deobfuscatorName, deobfuscatorNamespace).get(0);
			return this.getFunctionAt(deobfuscatorSymbol.getAddress());
		} catch (IndexOutOfBoundsException X) {
			dbgMsg("The function %s was not found.", deobfuscatorName);
			return null;
		}
	}
	
	protected OptionalLong traceVarnodeValue(Varnode argument) throws UnknownVariableCopy {
		while (!argument.isConstant()) {
			PcodeOp ins = argument.getDef();
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

	protected byte[] getOriginalBytes(Address addr, int size) {
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
