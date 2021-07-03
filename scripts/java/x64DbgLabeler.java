//Generate a x64dbg Script that labels functions as they are currently labeled in Ghidra (in x64dbg: Alt-S -> Shift-V -> Space)
//@author @larsborn
//@category malRE
//@keybinding 
//@menupath 
//@toolbar 

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class x64DbgLabeler extends GhidraScript {
	public void run() throws Exception {
		List<String> list = new ArrayList<String>();
		for (Function function : getAllFunctions()) {
			list.add(String.format("lblset 0x%x, %s", function.getEntryPoint().getOffset(), function.getName()));
		}
		setClipboard(String.join("\n", list));
		println("x64dbg script copied to clipboard: Alt-S, Shift-V, Space");
	}

	private void setClipboard(String s) {
		StringSelection selection = new StringSelection(s);
		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		clipboard.setContents(selection, selection);
	}

	private FunctionIterator getAllFunctions() {
		FunctionManager functionManager = currentProgram.getFunctionManager();
		return functionManager.getFunctions(true);
	}
}
