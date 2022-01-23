//List functions by the number of times they are called.
//@author malRE
//@category malRE
//@keybinding 
//@menupath 
//@toolbar 

import java.util.ArrayList;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class ListFunctionsWithXRefCount extends GhidraScript {

	private class FunctionWithCallCount {
		Function function;
		int callCount;
		public FunctionWithCallCount(Function function, int callCount) {
			this.function = function;
			this.callCount = callCount;
		}
	}
	
    public void run() throws Exception {
    	ArrayList<FunctionWithCallCount> callCounts = new ArrayList<FunctionWithCallCount>(); 
    	for (Function f: currentProgram.getFunctionManager().getFunctions(true)) {
    		callCounts.add(new FunctionWithCallCount(f, getNumberOfCalls(f)));
    	}
    	callCounts.sort((a, b) -> a.callCount - b.callCount);
    	for (FunctionWithCallCount cc : callCounts) {
    		println(String.format("%6d %08X %s",
    				cc.callCount,
    				cc.function.getEntryPoint().getOffset(),
    				cc.function.getName()
			));
    	}
    }

    private int getNumberOfCalls(Function f) {
    	return getReferencesTo(f.getEntryPoint()).length;
    }

}
