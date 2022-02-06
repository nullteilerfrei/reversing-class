//Badnews Stack Strings
//@author malRE
//@category malRE
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;

public class BadnewsStackStrings extends GhidraScript {
	public void run() throws Exception {
		StringBuilder sb = new StringBuilder();
		for (AddressRange addressRange : currentSelection.getAddressRanges()) {
			for (Address a : addressRange) {
				Instruction instruction = getInstructionAt(a);
				if (instruction == null) {
					continue;
				}
				Object[] objects = instruction.getOpObjects(1);
				Scalar s = (Scalar) objects[0];
				byte bytes[] = s.getBigInteger().toByteArray();
				for (int i = bytes.length - 1; i >= 0; i--) {
					char c = (char) bytes[i];
					if (c < '!' || c > '~') {
						println(String.format("Skipping 0x%02X", bytes[i]));
						continue;
					}
					sb.append(c);
				}
				println(String.format("%s", instruction.toString()));
			}
		}

		println(String.format("%s", sb.toString()));
		setComment(currentSelection.getMinAddress(), sb.toString());
	}

	private void setComment(Address address, String comment) {
		CodeUnit codeUnit = currentProgram.getListing().getCodeUnitAt(address);
		codeUnit.setComment(CodeUnit.PLATE_COMMENT, comment);
		codeUnit.setComment(CodeUnit.PRE_COMMENT, comment);
	}
}
