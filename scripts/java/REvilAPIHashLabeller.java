//Labels up API hashes in REvil Samples
//@author mal.re
//@category malRE

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.address.*;

public class REvilAPIHashLabeller extends MalREGhidraScript {

	public void run() throws Exception {
		List<String> hashDescriptions;
		Map<Long, String> hashMap = new HashMap<Long, String>();
		File hashDescriptionFile = askFile("Hash List", "LETS GO");
		try {
			hashDescriptions = Files.readAllLines(hashDescriptionFile.toPath(), Charset.defaultCharset());
		} catch (IOException e) {
			logMsg("file not found: %s", hashDescriptionFile.getAbsolutePath());
			return;
		}

		for (String hashDescription : hashDescriptions) {
			Pattern patternName = Pattern.compile("\"name\"\\s*:\\s*\"(\\w*?)\"");
			Pattern patternHash = Pattern.compile("\"hash\"\\s*:\\s*(\\d+)");
			Matcher matchName = patternName.matcher(hashDescription);
			Matcher matchHash = patternHash.matcher(hashDescription);
			if (!matchName.find() || !matchHash.find())
				continue;
			Long hashAsLong = Long.parseLong(matchHash.group(1));
			hashMap.put(hashAsLong, matchName.group(1));
		}

		int clearSize = askInt("Enter Size",
				String.format("Size of area to clear (starting at %08x)", currentAddress.getOffset()));
		Address endOfRange = toAddr(currentAddress.getOffset() + clearSize);
		clearListing(currentAddress, endOfRange);

		while (currentAddress.compareTo(endOfRange) < 0) {
			Long hashValue = (long) getInt(currentAddress);
			if (hashValue < 0)
				hashValue += 0x100000000L;
			// hashValue = (hashValue ^ 0x76c7) << 0x10 ^ hashValue;
			hashValue = (hashValue ^ 0x186f) << 0x10 ^ hashValue;			
			hashValue &= 0x1FFFFF;
			if (hashMap.containsKey(hashValue)) {
				String symbolName = hashMap.get(hashValue);
				createLabel(currentAddress, symbolName, true);
				createDWord(currentAddress);
				logMsg("%08X %s", currentAddress.getOffset(), symbolName);
			} else {
				logMsg("%08X unknown hash %d", currentAddress.getOffset(), hashValue);
			}
			currentAddress = currentAddress.add(4);
		}
	}
}
