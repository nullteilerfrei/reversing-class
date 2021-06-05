//Clear This Shit - Clears data of given size starting at the cursor
//@author @larsborn
//@category malRE
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class ClearThisShit extends GhidraScript {
	public void run() throws Exception {
		int clearSize = askInt("Enter Size",
				String.format("Size of area to clear (starting at %08x)", currentAddress.getOffset()));
		Address clearEnd = toAddr(currentAddress.getOffset() + clearSize);
		this.clearListing(currentAddress, clearEnd);
	}
}
