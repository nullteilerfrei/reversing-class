# Sofacy Malware String Deobfuscation
# @author MC
# @category Memory
# @keybinding
# @menupath Tools.String Deobfuscation.Sofacy
# @toolbar

# TODO Add User Code Here


from java.awt import Color


def fatal_error(message):
    print("ERROR: {}".format(message))
    exit()


def deobfuscate(address, length):
    """
        - re-implementation of deobfuscation function FUN_00407FBA
        - this could be improved (e.g., we could ask for the key address vs. hard coding the bytes), etc.
    """
    print("INFO: deobfuscating string at address 0x{:X} (length {})".format(int(address.toString(), 16), length))

    obfuscated_bytes = getBytes(address, length)

    key = [0x5f, 0x19, 0x36, 0x2c, 0x53, 0x3e, 0x6f, 0x1a, 0x0c, 0x6a, 0x20, 0x2e, 0x34]
    len_key = len(key)

    deobfuscated_chars = ['?'] * len(obfuscated_bytes)

    for i, b in enumerate(obfuscated_bytes):
        deobfuscated_chars[i] = chr(b ^ key[i % len_key])

    print("deobfuscated string: {}".format("".join(deobfuscated_chars)))


def get_call_params(reference):
    """
        - from the call instruction go back number_of_instr_back instructions
        - look for the two push instructions (those push the parameters to the obfuscation function)
        - we assume that we have __stdcall or __cdecl
        - gather push operands and return them
	- if the obfuscated string address is referenced by a register the respective instruction will be colored in red
    """
    number_of_instr_back = 10

    arg_instructions = []
    prev_instructions = []

    address_of_reference = reference.getFromAddress()
    instruction = getInstructionAt(address_of_reference)

    prev_instructions.append(instruction)

    for i in range(number_of_instr_back):
        prev_instructions.append(prev_instructions[-1].getPrevious())

    for tmp_instr in prev_instructions:
        if len(arg_instructions) == 2:
            break
        if tmp_instr.getMnemonicString() == "PUSH":
            arg_instructions.append(tmp_instr)

    first_push_instr_string = arg_instructions[0].toString()
    operand = first_push_instr_string.split(" ")[1].lower()

    if operand in ["eax", "ebx", "ecx", "edx"]:
        print("WARNING: deobfuscated string accessed vie register; manual analysis required at 0x{:X}".format(
            reference.getFromAddress().getUnsignedOffset()))
        setBackgroundColor(address_of_reference, Color.RED)

    if len(arg_instructions) != 2:
        print("WARNING: Oooops did not find arguments for reference 0x{:X}".format(
            reference.getFromAddress().getUnsignedOffset()))
        return None, None

    return arg_instructions[0].getAddress(0), arg_instructions[1].getScalar(0).getValue()


def main():
    """
        - the starting point is the reversed deobfuscation function
        - we get all references (where is this function called?)
        - we inspect the function call parameters by search backwards through the instructions
            - we search for PUSH instructions
            - they always must be in the same order (calling convention)
            - we might miss parameter setups like MOV DWORD PTR[ESP], 0x12 (where no PUSH is used)
        - we deobfuscate the strings
    """
    function_name = askString("Input", "Enter the name of the obfuscation function")
    #function_name = "xor_obfuscate"

    obfuscation_function = getFunction(function_name)

    if not obfuscation_function:
        fatal_error("function not found")

    calling_convention = obfuscation_function.getCallingConventionName()

    if calling_convention not in ["__stdcall", "__cdecl"]:
        fatal_error("unsupported calling convention")

    references = getReferencesTo(obfuscation_function.getEntryPoint())

    for reference in references:
        if reference.getReferenceType().isCall():
            string_offset, string_len = get_call_params(reference)

            if string_offset and string_len:
                deobfuscate(string_offset, string_len)
                print("")


main()
