//Noop This Shit - replaces current selection with 0x90 (NOP) instructions
//@author larsborn
//@category Helper
//@keybinding Ctrl-Alt-Shift-N
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;

public class nts extends GhidraScript {
	public void run() throws Exception {
		if (currentSelection != null) {
			AddressRangeIterator addressRanges = currentSelection.getAddressRanges(true);
			for (AddressRange addressRange : addressRanges) {
				nopOut(addressRange.getMinAddress(), assemblyAlignedLength(addressRange));
			}
		}
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

	short MAX_ASSEMBLY_INSTRUCTION_LENGTH = 15;

	/**
	 * Searchers backwards for the last assembly instruction and returns the length
	 * of the address range, potentially extended to fully include this last
	 * instruction.
	 */
	private long assemblyAlignedLength(AddressRange addressRange) {
		long length = addressRange.getLength();
		for (int i = 1; i <= MAX_ASSEMBLY_INSTRUCTION_LENGTH; i++) {
			Instruction instruction = getInstructionAt(addressRange.getMinAddress().add(length - i));
			if (instruction != null) {
				return length + (instruction.getLength() - i);
			}
		}

		return length;
	}
}
