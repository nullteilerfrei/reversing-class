//Deobfuscates Strings in Hamweq sample 4eb33ce768def8f7db79ef935aabf1c712f78974237e96889e1be3ced0d7e619
//@author larsborn
//@category Strings
//@keybinding 
//@menupath 
//@toolbar 

import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;

public class HamweqStrings extends GhidraScript {
	private byte[] getOriginalBytes(Address addr, int size) {
		Memory m = getCurrentProgram().getMemory();
		MemoryBlock b = m.getBlock(addr);
		if (b == null)
			return null;
		MemoryBlockSourceInfo info = b.getSourceInfos().get(0);
		long fileOffset = info.getFileBytesOffset() + (addr.getOffset() - info.getMinAddress().getOffset());
		FileBytes bytes = m.getAllFileBytes().get(0);
		try {
			byte[] result = new byte[size];
			bytes.getOriginalBytes(fileOffset, result);
			return result;
		} catch (IOException X) {
			return null;
		}
	}

	public static byte[] getSliceOfArray(byte[] arr, int start, int end) {
		byte[] slice = new byte[end - start];
		for (int i = 0; i < slice.length; i++) {
			slice[i] = arr[start + i];
		}
		return slice;
	}

	private byte[] readUntilZeroByte(byte[] data) throws Exception {
		int ZeroPos = -1;
		for (int i = 0; i < data.length; i++) {
			if (data[i] == '\0') {
				ZeroPos = i;
				break;
			}
		}
		if (ZeroPos == -1) {
			throw new Exception("Cannot find Zero termination");
		}
		return getSliceOfArray(data, 0, ZeroPos);
	}

	private byte[] reduceKey(String key) {
		byte ret[] = new byte[1];
		for (byte b : key.getBytes()) {
			ret[0] ^= b;
		}
		return ret;
	}

	private Address unpackAddressLE(byte[] data) {
		return toAddr((data[0] & 0xff) | ((data[1] & 0xff) << 8) | ((data[2] & 0xff) << 16) | ((data[3] & 0xff) << 24));
	}

	public void run() throws Exception {
		byte[] key = reduceKey("I0L0v3Y0u0V1rUs");
		Address stringTable = askAddress("Enter Address", "Specify address of string table");
		while (true) {
			Address stringAddress = unpackAddressLE(getOriginalBytes(stringTable, 4));
			if (stringAddress.getOffset() == 0)
				break;
			byte data[] = getOriginalBytes(stringAddress, 0x40);
			if (data == null) {
				break;
			}
			byte cypherText[] = readUntilZeroByte(data);
			byte plainText[] = cryptXorAndInvert(cypherText, key);
			println(String.format("0x%08X %s", stringAddress.getOffset(), new String(plainText)));

			setBytes(stringAddress, plainText);
			clearListing(stringAddress, stringAddress.add(plainText.length - 1));
			createData(stringAddress, new ArrayDataType(CharDataType.dataType, plainText.length, 1));
			createBookmark(stringAddress, "DeobfuscatedString", new String(plainText));

			stringTable = toAddr(stringTable.getOffset() + 4);
		}
	}

	private byte[] cryptXorAndInvert(byte[] data, byte[] key) {
		final byte[] ret = new byte[data.length];
		for (int k = 0; k < data.length; k++)
			ret[k] = (byte) (~(data[k] ^ key[k % key.length]));
		return ret;
	}

}
