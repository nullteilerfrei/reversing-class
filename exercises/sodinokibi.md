---
tags: api-hashing, automation, ransomware, revil, sodinokibi
---
Consider the sample with the following SHA-256 hash:
```
5f56d5748940e4039053f85978074bde16d64bd5ba97f6f0026ba8172cb29e93
```
It is a ransomware sample that uses API hashing. The task of this exercise is to:

1. identify and reverse engineer the API hashing routine,
2. compute a list of hashes for known API function symbols,
3. run a Ghidra script (provided below) to fix all obfuscated API calls.

For the second and third part, we offer a few suggested script templates, but if you feel sassy,
just stop reading here and do everything yourself.

At the bottom of this exercise is the code of a Ghidra script in Java that can be used to label a
memory region containing API hashes with the corresponding function symbol names. It requires an
input file that contains the correctly hashed API function names in the following format:
```json
{"name": "LoadLibraryA", "hash": 849394733}
{"name": "LoadLibraryW", "hash": 3980733}
{"name": "DisableFirewallAndExecutePowerShellAsAdminW", "hash": 299239333}
```
In other words, each line is a JSON object with a `name` field set to the name of the function and
the `hash` field set to the value of the corresponding API hash.

To help generate such a file, we provide:
- [a script for extracting exported function symbols from Windows DLLs][dlls-crawler],
- [a collection of Windows DLLs from the ReactOS project][dlls],

and if don't want to run that script on the DLLs yourself, [here is the output][dlls-crawled].

Here is the promised Ghidra script:
```java
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;

public class REvilAPIHashLabeller extends GhidraScript {

	public void run() throws Exception {
		List<String> hashDescriptions;
		Map<Long, String> hashMap = new HashMap<Long, String>();
		File hashDescriptionFile = askFile("Hash List", "Open");
		try {
			hashDescriptions = Files.readAllLines(
				hashDescriptionFile.toPath(),
				Charset.defaultCharset());
		} catch (IOException e) {
			this.println(String.format(
				"file not found: %s",
				hashDescriptionFile.getAbsolutePath()));
			return;
		}

		for (String hashDescription: hashDescriptions) {
			Pattern patternName = Pattern.compile("\"name\"\\s*:\\s*\"(\\w*?)\"");
			Pattern patternHash = Pattern.compile("\"hash\"\\s*:\\s*(\\d+)");
			Matcher matchName = patternName.matcher(hashDescription);
			Matcher matchHash = patternHash.matcher(hashDescription);
			if (!matchName.find() || !matchHash.find())
				continue;
			Long hashAsLong = Long.parseLong(matchHash.group(1));
			hashMap.put(hashAsLong, matchName.group(1));
		}

		int clearSize = askInt("Enter Size", String.format(
			"Size of area to clear (starting at %08x)",
			currentAddress.getOffset()));

		Address endOfRange = toAddr(currentAddress.getOffset() + clearSize);
		clearListing(currentAddress, endOfRange);
		
		while (currentAddress.compareTo(endOfRange) < 0) {
			Long hashValue = (long) getInt(currentAddress);
			if (hashValue < 0)
				hashValue += 0x100000000L;
			// ...
            // maybe you need to do something more here.
            // ...
			if (hashMap.containsKey(hashValue)) {
				String symbolName = hashMap.get(hashValue);
				createLabel(currentAddress, symbolName, true);
				createDWord(currentAddress);
				this.println(String.format(
					"%08X %s", currentAddress.getOffset(),
					symbolName));
			} else {
				this.println(String.format(
					"%08X unknown hash %d", currentAddress.getOffset(),
					hashValue));
			}
			currentAddress = currentAddress.add(4);
		}
	}
}
```

[dlls]: https://mal.re/tmp/resources/react-os-dlls.zip
[dlls-crawler]: https://raw.githubusercontent.com/nullteilerfrei/reversing-class/master/scripts/python/get_pe_exports.py
[dlls-crawled]: https://raw.githubusercontent.com/nullteilerfrei/reversing-class/master/scripts/python/get_pe_exports.json