//Noop All Calls - replaces all calls to the given function with NOP instructions
//@author larsborn
//@category malRE
//@keybinding Ctrl-Shift-N
//@menupath 
//@toolbar 

import java.util.List;
import java.util.ArrayList;

import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class NopAllCalls extends GhidraScript {

	public void run() throws Exception {
		String functionName;
		try {
			functionName = askString("Enter Name", "Enter the name the function name:",
					getFunctionBefore(currentAddress.next()).getName());
		} catch (CancelledException X) {
			return;
		}
		Function function = getGlobalFunctions(functionName).get(0);
		for (Address callAddr : getCallAddresses(function)) {
			Instruction instruction = getInstructionAt(callAddr);
			println(String.format("NOPing out call at 0x%08X.", callAddr.getOffset()));
			nopOut(callAddr, instruction.getLength());
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

	byte NOP = (byte) 0x90;

	private void nopOut(Address addressStart, long length) throws CancelledException, MemoryAccessException {
		clearListing(addressStart, addressStart.add(length));
		for (int i = 0; i < length; i++) {
			Address address = addressStart.add(i);
			setByte(address, NOP);
		}

		disassemble(addressStart);
	}
}
