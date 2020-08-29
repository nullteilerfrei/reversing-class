//Base class for MalRE scripts with an extended flat API.
import java.io.IOException;
import java.util.Iterator;
import java.util.OptionalLong;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import malRE.MalREGhidraScript.UnknownVariableCopy;

public abstract class MalREGhidraScript extends GhidraScript {

    class UnknownVariableCopy extends Exception {
        public UnknownVariableCopy(PcodeOp unknownCode, Address addr) {
            super(String.format("unknown opcode %s for variable copy at %08X",
                    unknownCode.getMnemonic(), addr.getOffset()));
        }
    }

    protected void logMsg(String message, Object... args){
        this.println(String.format(message, args));
    }

    protected OptionalLong getConstantCallArgument(Address addr, int index)
            throws IllegalStateException, UnknownVariableCopy
    {
        Function caller = getFunctionBefore(addr);
        if (caller == null)
            throw new IllegalStateException();

        DecompInterface decompInterface = new DecompInterface();
        decompInterface.openProgram(currentProgram);
        DecompileResults decompileResults = decompInterface.decompileFunction(caller, 120, monitor);
        if (!decompileResults.decompileCompleted())
            throw new IllegalStateException();

        HighFunction highFunction = decompileResults.getHighFunction();
        Iterator<PcodeOpAST> pCodes = highFunction.getPcodeOps(addr);
        while (pCodes.hasNext()) {
            PcodeOpAST instruction = pCodes.next();
            if (instruction.getOpcode() == PcodeOp.CALL) {
                return traceVarnodeValue(instruction.getInput(index));
            }
        }
        throw new IllegalStateException();
    }

    protected OptionalLong traceVarnodeValue(Varnode argument) throws UnknownVariableCopy {
        while (!argument.isConstant()) {
            PcodeOp ins = argument.getDef();
            switch (ins.getOpcode()) {
            case PcodeOp.CAST:
            case PcodeOp.COPY:
                argument = ins.getInput(0);
                break;
            case PcodeOp.PTRSUB:
            case PcodeOp.PTRADD:
                argument = ins.getInput(1);
                break;
            case PcodeOp.INT_MULT:
            case PcodeOp.MULTIEQUAL:
                // known cases where an array is indexed
                return OptionalLong.empty();
            default:
                // don't know how to handle this yet.
                throw new UnknownVariableCopy(ins, argument.getAddress());
            }
        }
        return OptionalLong.of(argument.getOffset());
    }

    protected byte[] getOriginalBytes(Address addr, int size) {
        MemoryBlock stringMemoryBlock = currentProgram.getMemory().getBlock(addr);
        if (stringMemoryBlock == null)
            return null;
        FileBytes fileBytes = currentProgram.getMemory().getAllFileBytes().get(0);
        MemoryBlockSourceInfo memoryInformation = stringMemoryBlock.getSourceInfos().get(0);
        long fileOffset = addr.getOffset() 
                - memoryInformation.getMinAddress().getOffset()
                + memoryInformation.getFileBytesOffset();
        try {
            byte[] result = new byte[size];
            fileBytes.getOriginalBytes(fileOffset, result);
            return result;
        } catch (IOException X) {
            return null;
        }
    }
}
