//Deobfuscate the strings in 2396c9dac2184405f7d1f127bec88e56391e4315d4d2e5b951c795fdc1982d59
//@author malRE
//@category malRE
import java.io.IOException;
import java.util.Iterator;
import java.util.OptionalLong;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;

import ghidra.util.exception.CancelledException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;


public class DownRageStrings extends MalREGhidraScript {

    static byte KEY[] = new byte[] {
        0x5f, 0x19, 0x36, 0x2c, 0x53, 0x3e, 0x6f, 0x1a, 0x0c, 0x6a, 0x20, 0x2e, 0x34
    };

    private void deobfuscateString(byte[] string) {
        for (int k = 0; k < string.length; k++)
            string[k] = (byte) (string[k] ^ KEY[k % KEY.length]);
    }
    
    public void run() throws Exception {
        String deobfuscatorName;
        try {
            deobfuscatorName = askString(
                "Enter Name",
                "Enter the name of the deobfuscation function below:",
                getFunctionBefore(currentAddress.next()).getName()
            );
        } catch (CancelledException X) {
            return;
        }
        
        Function deobfuscator = getGlobalFunctions(deobfuscatorName).get(0);
        
        println(String.format("Using function at address %08X as deobfuscator.",
            deobfuscator.getEntryPoint().getOffset()));

        for (Reference ref : getReferencesTo(deobfuscator.getEntryPoint())) {
            if (ref.getReferenceType() != RefType.UNCONDITIONAL_CALL)
                continue;

            Address callAddr = ref.getFromAddress();
            
            monitor.setMessage(String.format("parsing call at %08X", callAddr.getOffset()));

            OptionalLong a1Option = getConstantCallArgument(callAddr, 1);
            OptionalLong a2Option = getConstantCallArgument(callAddr, 2);

            if (a1Option.isEmpty() || a2Option.isEmpty()) {
                println(String.format("Argument to call at %08X is not a constant string.",
                    callAddr.getOffset()));
                continue;
            }
            
            long offset = a1Option.getAsLong();
            int size = (int) a2Option.getAsLong();

            byte[] buffer = getOriginalBytes(toAddr(offset), size);

            if (buffer == null) {
                println(String.format("Failed to trace argument value for call at %08X, got %08X.",
                   callAddr.getOffset(), offset));
                continue;
            }
            
            Address stringAddr = toAddr(offset);

            deobfuscateString(buffer);
            setBytes(stringAddr, buffer);
            clearListing(stringAddr, stringAddr.add(size - 1));
            createData(stringAddr, new ArrayDataType(CharDataType.dataType, size, 1));
            createBookmark(stringAddr, "DeobfuscatedString", new String(buffer));
        }
    }
}
