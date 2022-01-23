---
tags: bottom-up, rat, string-obfuscation
---
Consider the sample with the following SHA-256 hash:
```
2396c9dac2184405f7d1f127bec88e56391e4315d4d2e5b951c795fdc1982d59
```
Your first task is to write a script that can help you locate the string deobfuscation function:

1. Write a Ghidra Script that lists all functions in the binary with their respective address,
   sorted by the number of times that they are referenced in the code. You will likely have to
   use the [getFunctions][] method of the current function manager.
   Going from most referenced to least referenced, the third function in this list is the one
   we are looking for. 
2. Write a second script that you can use to deobfuscate strings by pressing a hotkey. Remember
   that [createAsciiString][] can be used to convert a memory range to an ASCII string.
3. (**Bonus**) Extend your script to deobfuscate all constant strings that are passed to the
   string deobfuscation function across the entire program. The tricky part is to obtain the
   arguments to a function call programmatically. We have an example implementation in the script
   called `getConstantCallArgument`.


[getFunctions]: https://mal.re/api/ghidra/program/model/listing/FunctionManager.html#getFunctions(ghidra.program.model.address.Address,boolean)
[createAsciiString]: https://mal.re/api/ghidra/program/flatapi/FlatProgramAPI.html#createAsciiString(ghidra.program.model.address.Address,int)