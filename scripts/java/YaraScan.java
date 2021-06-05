//Perform a YARA scan of the binary, show results, comment on those lines and add bookmarks
//@author larsborn
//@category Search
//@keybinding Ctrl+Alt+F9
//@menupath 
//@toolbar 

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.OptionalLong;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;

public class YaraScan extends GhidraScript {
	String YARA_PATH = "C:\\bin\\yara.exe";

	private class YaraMatch {
		public String ruleName;
		public String stringName;
		public long offset;

		private YaraMatch(String ruleName, String stringName, long offset) {
			this.ruleName = ruleName;
			this.stringName = stringName;
			this.offset = offset;
		}
	}

	private File dumpToTempFile(byte[] content) throws IOException {
		File tempFile = File.createTempFile("GhidraYaraScan-", ".bin");
		FileOutputStream fos = new FileOutputStream(tempFile);
		fos.write(content);
		fos.close();
		tempFile.deleteOnExit();
		return tempFile;
	}

	private OptionalLong getStringMatchPosition(String line) {
		String[] tripple = getRuleName(line).split(":", 3);
		if (tripple.length < 2) {
			return OptionalLong.empty();
		}
		this.println(line);

		return OptionalLong.of(Long.decode(tripple[0]));
	}

	private String getStringName(String line) {
		String[] tripple = getRuleName(line).split(":", 3);
		if (tripple.length < 2) {
			return null;
		}

		return tripple[1];
	}

	private String getRuleName(String line) {
		String[] pair = line.split(" ", 2);
		if (pair.length != 2) {
			return null;
		}
		return pair[0];
	}

	private List<YaraMatch> scanFile(File file, String rulePath) {
		List<YaraMatch> ret = new ArrayList<YaraMatch>();
		try {
			String command = String.format("%s -s %s %s", YARA_PATH, rulePath, file.getAbsolutePath());
			Runtime run = Runtime.getRuntime();
			Process proc = run.exec(command);
			BufferedReader stdInput = new BufferedReader(new InputStreamReader(proc.getInputStream()));
			String line = null;
			String currentRule = null;
			while ((line = stdInput.readLine()) != null) {
				OptionalLong position = getStringMatchPosition(line);
				if (position.isPresent()) {
					if (currentRule == null) {
						continue;
					}
					ret.add(new YaraMatch(currentRule, getStringName(line), position.getAsLong()));
					continue;
				}

				String ruleName = getRuleName(line);
				if (ruleName != null) {
					currentRule = ruleName;
					continue;
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return ret;
	}

	public void run() throws Exception {
		File rule = askFile("YARA Rules File", "Scan!");
		for (AddressRange addressRange : currentProgram.getMemory().getAddressRanges()) {
			File tmp = dumpToTempFile(getBytes(addressRange.getMinAddress(), (int) addressRange.getLength()));
			for (YaraMatch match : scanFile(tmp, rule.getAbsolutePath())) {
				long offset = addressRange.getMinAddress().getOffset() + match.offset;
				this.println(String.format("YARA Match %s: 0x%x (%s)", match.ruleName, offset, match.stringName));
				Address address = findNearestAssemblyInstructionBackwards(offset);
				setComment(address, String.format("YARA Match: %s (%s)", match.ruleName, match.stringName));
				createBookmark(toAddr(offset), "YARAMatch", String.format("%s (%s)", match.ruleName, match.stringName));

			}
			tmp.delete();
		}
	}

	protected void setComment(Address address, String comment) {
		setPlateComentToDisassembly(address, comment);
		setCommentToDecompiledCode(address, comment);
	}

	protected void setPlateComentToDisassembly(Address address, String comment) {
		currentProgram.getListing().getCodeUnitAt(address).setComment(CodeUnit.PLATE_COMMENT, comment);
	}

	protected void setCommentToDecompiledCode(Address address, String comment) {
		currentProgram.getListing().getCodeUnitAt(address).setComment(CodeUnit.PRE_COMMENT, comment);
	}

	short MAX_ASSEMBLY_INSTRUCTION_LENGTH = 15;

	/**
	 * Searchers backwards for the last complete assembly instruction and returns
	 * its address
	 */
	protected Address findNearestAssemblyInstructionBackwards(long offset) {
		for (int i = 0; i <= MAX_ASSEMBLY_INSTRUCTION_LENGTH; i++) {
			Address addr = toAddr(offset - i);
			Instruction instruction = getInstructionAt(addr);
			if (instruction != null) {
				return addr;
			}
		}
		return toAddr(offset);
	}
}
