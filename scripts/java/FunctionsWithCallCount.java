//Prints all function addresses with their names and reference (Xref) counts
//@author @huettenhain, @larsborn
//@category malRE
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class FunctionsWithCallCount extends GhidraScript {
	public void run() throws Exception {
		List<Function> lst = new ArrayList<Function>();
		currentProgram.getFunctionManager().getFunctions(true).forEachRemaining(lst::add);
		lst.sort(new Comparator<Function>() {
			@Override
			public int compare(Function lhs, Function rhs) {
				int lhc = getReferencesTo(lhs.getEntryPoint()).length;
				int rhc = getReferencesTo(rhs.getEntryPoint()).length;
				return lhc > rhc ? 1 : (lhc < rhc) ? -1 : 0;
			}
		});
		for (Function function : lst) {
			println(String.format("0x%x %s %d", function.getEntryPoint().getOffset(), function.getName(),
					getReferencesTo(function.getEntryPoint()).length));
		}
	}
}
