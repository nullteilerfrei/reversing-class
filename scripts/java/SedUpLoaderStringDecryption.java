//Decrypt strings in SedUpLoader.
//@author mal.re
//@category malRE
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.regex.Pattern;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.ContextEvaluatorAdapter;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SedUpLoaderStringDecryption extends MalREGhidraScript {

	@Override
	protected void run() throws Exception {
		Function deobfuscator = askForFunction();

		if (deobfuscator == null)
			return;

		println(String.format("Using function at address %08X as deobfuscator.",
				deobfuscator.getEntryPoint().getOffset()));
		
		for (Reference ref : getReferencesTo(deobfuscator.getEntryPoint())) {
			if (ref.getReferenceType() != RefType.UNCONDITIONAL_CALL)
				continue;

			Address callAddr = ref.getFromAddress();
			monitor.setMessage(String.format("parsing call at %08X", callAddr.getOffset()));
			
			VariableValue var = getVariableCallArgument(callAddr, 1);
			for (Map.Entry<String, Long> item : var.membersByName.entrySet()) {
				logMsg("call at %08X - %s.%s = 0x%X",
						callAddr.getOffset(),
						var.variable.getName(),
						item.getKey(),
						item.getValue()
				);
			}
		}

	}
}
