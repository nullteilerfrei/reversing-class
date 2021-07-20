//Labels up API hashes in NetWalker
//@author malRE
//@category malRE

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.EnumDataType;


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

		getCurrentProgram().getDataTypeManager().addDataType(hashEnumeration, null);
	}
}
