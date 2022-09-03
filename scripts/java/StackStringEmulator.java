//P-Code emulator to combat stack strings
//@author mal.re 
//@category malRE
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.AddressRange;
import docking.widgets.OkDialog;

public class StackStringEmulator extends GhidraScript {
	public void run() throws Exception {
		EmulatorHelper emuHelper = new EmulatorHelper(currentProgram);
		emuHelper.enableMemoryWriteTracking(true);
		if (currentSelection == null) {
			OkDialog.show("StackStringEmulator", "Please select something");
			return;
		}
		Instruction entryInstr = getInstructionAt(currentSelection.getMinAddress());
		Instruction endInstr = getInstructionAt(currentSelection.getMaxAddress());

		emuHelper.setBreakpoint(endInstr.getNext().getAddress());
		emuHelper.run(currentSelection.getMinAddress(), entryInstr, monitor);

		StringBuilder comment = new StringBuilder();
		AddressSpace emulatedAddressSpace = entryInstr.getAddress().getAddressSpace();
		for (AddressRange writtenMemory : emuHelper.getTrackedMemoryWriteSet()) {
			if (writtenMemory.getAddressSpace() != emulatedAddressSpace) {
				continue;
			}
			Address a = writtenMemory.getMinAddress();
			for (byte b : emuHelper.readMemory(a, (int) writtenMemory.getMaxAddress().next().subtract(a))) {
				comment.append(String.format(isPrintable(b) ? "%c" : "\\x%02x", b));
			}
		}
		setPreComment(currentSelection.getMinAddress(), comment.toString());
	}

	private boolean isPrintable(byte b) {
		return b >= 32 && b <= 126;
	}
}
