//Labels up API hashes in NetWalker
//@author malRE
//@category malRE

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.cmd.equate.SetEquateCmd;
import ghidra.app.script.GhidraScript;
import ghidra.framework.cmd.Command;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;


public class NetWalkerAPIHashes extends GhidraScript {

	public void run() throws Exception {
		List<String> hashDescriptions;
		File hashDescriptionFile = askFile("Hash List", "Open");
		try {
			hashDescriptions = Files.readAllLines(
				hashDescriptionFile.toPath(),
				Charset.defaultCharset());
		} catch (IOException e) {
			this.println(String.format(
				"File not found: %s",
				hashDescriptionFile.getAbsolutePath()));
			return;
		}

		CategoryPath categoryPath = new CategoryPath("/NetWalker");
		EnumDataType hashEnumeration = new EnumDataType(categoryPath, "ApiHashes", 4);
		HashMap<Long, String> hashToName = new HashMap<Long, String>();
		
		for (String hashDescription: hashDescriptions) {
			Pattern patternName = Pattern.compile("\"name\"\\s*:\\s*\"(\\w*?)\"");
			Pattern patternHash = Pattern.compile("\"hash\"\\s*:\\s*(\\d+)");
			Matcher matchName = patternName.matcher(hashDescription);
			Matcher matchHash = patternHash.matcher(hashDescription);
			if (!matchName.find() || !matchHash.find())
				continue;
			Long hashAsLong = Long.parseLong(matchHash.group(1));
			println(matchName.group(1));
			try {
				hashEnumeration.add(matchName.group(1), hashAsLong);
			} catch (IllegalArgumentException e) { }
		}
		// Actually adds the EnumDataType
		getCurrentProgram().getDataTypeManager().addDataType(hashEnumeration, null);

		// Checks each and every scalar, whether it is a known API hash
		applyEquates(hashToName);
	}

	public void applyEquates(HashMap<Long, String> crcToName) {
		Listing listing = currentProgram.getListing();

		InstructionIterator iter = listing.getInstructions(currentProgram.getMemory(), true);

		/*
		 * Iterates of the instructions until operation is canceled or there
		 * are no instructions left to process
		 */
		while (iter.hasNext() && !monitor.isCancelled()) {
			// Grabs next instruction to process
			Instruction tempValue = iter.next();

			// Retrieves operands of the instruction
			int numOperands = tempValue.getNumOperands();

			// Checks each operand, if it's a scalar
			for (int i = 0; i <= numOperands; i++) {
				// Checks to see if the current value is a scalar value
				if (tempValue.getOperandType(i) == (OperandType.SCALAR)) {
					long l = tempValue.getScalar(i).getUnsignedValue();
					String eq = crcToName.get(l);

					if (eq != null && l != 0) {
						// Sets the equate to the user defined name and execute
						Command cmd = new SetEquateCmd(eq, tempValue.getAddress(), i, l);

						state.getTool().execute(cmd, currentProgram);

						// Informs the user about found equates
						println("Added a new equate named " + eq + " for the scalar " +
								l + " at address " + tempValue.getAddress() + 
								" and at operand " + i);
					}
				}
			}
		}
	}
}
