// List all functions called in the current function together with their number of references 
//@author larsborn 
//@category Strings

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.OptionalLong;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

public class ListCallsWithXrefs extends GhidraScript {
	class UnknownVariableCopy extends Exception {
		public UnknownVariableCopy(PcodeOp unknownCode, Address addr) {
			super(String.format("unknown opcode %s for variable copy at %08X", unknownCode.getMnemonic(),
					addr.getOffset()));
		}
	}

	private class FunctionXrefs implements Comparable<FunctionXrefs> {
		public String name;
		public Address address;
		public long count;

		public FunctionXrefs(Function function) {
			name = function.getName();
			address = function.getEntryPoint();
			count = getCallAddresses(function).size();
		}

		@Override
		public int compareTo(FunctionXrefs other) {
			return other.count == count ? 0 : (other.count > count ? -1 : 1);
		}
	}

	private boolean addressAlreadyOnList(List<FunctionXrefs> lst, Address address) {
		for (FunctionXrefs xrefs : lst) {
			if (xrefs.address == address) {
				return true;
			}
		}
		return false;
	}

	private List<FunctionXrefs> getCallsAndRefs(Function func) throws UnknownVariableCopy {
		List<FunctionXrefs> ret = new ArrayList<FunctionXrefs>();
		DecompInterface decompInterface = new DecompInterface();
		decompInterface.openProgram(currentProgram);
		DecompileResults decompileResults = decompInterface.decompileFunction(func, 120, monitor);
		if (!decompileResults.decompileCompleted())
			throw new IllegalStateException();
		HighFunction highFunction = decompileResults.getHighFunction();
		for (Instruction asmInstruction : currentProgram.getListing().getInstructions(func.getEntryPoint(), true)) {
			if (asmInstruction.getMnemonicString().equals("RET")) {
				break;
			} else if (asmInstruction.getMnemonicString().equals("CALL")) {
				Iterator<PcodeOpAST> pCodes = highFunction.getPcodeOps(asmInstruction.getAddress());
				// iterate all p-code instructions of the parent function
				while (pCodes.hasNext()) {
					PcodeOpAST callInstruction = pCodes.next();
					if (callInstruction.getOpcode() == PcodeOp.CALL) {
						// get addresses of all call instructions
						OptionalLong calledAddress = traceVarnodeValue(callInstruction.getInput(0));
						if (calledAddress.isPresent()) {
							Address address = toAddr(calledAddress.getAsLong());
							Function function = getFunctionAt(address);
							if (!addressAlreadyOnList(ret, function.getEntryPoint())) {
								if (function != null) {
									ret.add(new FunctionXrefs(function));
								}
							}
						}
					}
				}
			}
		}

		return ret;
	}

	private OptionalLong traceVarnodeValue(Varnode argument) throws UnknownVariableCopy {
		while (!argument.isConstant()) {
			PcodeOp ins = argument.getDef();
			if (ins == null) {
				break;
			}
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

	public void run() throws Exception {
		// add one to address to select the correct function in case the target function
		// itself is selected
		Function functionBefore = getFunctionBefore(currentAddress.add(1));
		if (functionBefore == null) {
			return;
		}
		List<FunctionXrefs> callsAndRefs = getCallsAndRefs(functionBefore);
		Collections.sort(callsAndRefs);
		for (FunctionXrefs xrefs : callsAndRefs) {
			println(String.format("0x%08x (%s): %d", xrefs.address.getOffset(), xrefs.name, xrefs.count));
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
}
