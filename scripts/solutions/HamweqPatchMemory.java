//Inverts XOR-based string obfuscation technique observed in Hamweq (0x5f + invert, solution to hamweq exercise)
//@author malRE
//@category malRE
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;

public class HamweqPatchMemory extends GhidraScript {
	static byte KEY = 0x5f;

	public void run() throws Exception {
		for (AddressRange addressRange : currentSelection.getAddressRanges()) {
			decryptRange(addressRange.getMinAddress());
		}
	}

	public void runPart3() throws Exception {
		Address cursor = currentAddress;
		while (true) {
			Data data = getDataAt(cursor);
			if (data == null || !data.isPointer()) {
				break;
			}
			Address dataAddr = (Address) data.getValue();
			if (dataAddr.getOffset() == 0) {
				break;
			}
			decryptRange(dataAddr);
			cursor = cursor.add(currentProgram.getDefaultPointerSize());
			println(String.format("0x%x", cursor.getOffset()));
		}
	}

	private void decryptRange(Address start) throws Exception {
		Address current = start;
		int size = 0;
		while (true) {
			byte currentByte = getByte(current);
			if (currentByte == 0) {
				break;
			}
			setByte(current, (byte) ~(currentByte ^ KEY));
			current = current.add(1);
			size += 1;
		}

		clearListing(start, start.add(size));
		createAsciiString(start, size);
	}
}
