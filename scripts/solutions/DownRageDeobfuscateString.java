//String deobfuscation for the DownRage sample with the following SHA-256 hash:
//  2396c9dac2184405f7d1f127bec88e56391e4315d4d2e5b951c795fdc1982d59
//@author malRE
//@category malRE
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

public class DownRageDeobfuscateString extends GhidraScript {

	static byte[] KEY = { 0x5f, 0x19, 0x36, 0x2c, 0x53, 0x3e, 0x6f, 0x1a, 0x0c, 0x6a, 0x20, 0x2e, 0x34 };
	
    public void run() throws Exception {
    	for (AddressRange walker : currentSelection.getAddressRanges()) {
			int position = 0;
			for (Address address : walker) {
    			setByte(address, (byte)(getByte(address) ^ KEY[position % KEY.length]));
    			++position;
			}
			Address start = walker.getMinAddress();
			clearListing(start, start.add(position)); 
			createAsciiString(start, position);
    	}
    }
}
