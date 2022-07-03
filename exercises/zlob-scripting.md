---
tags: zlob, des, encryption, algorithm-identification, scale-yourself, automation
---
Consider the sample with the following SHA-256 hash:
```
0b38ca277bbb042d43bd1f17c4e424e167020883526eb2527ba929b2f0990a8f
```
The sample employs a very simple junk code obfuscation technique and the goal of this exercise is
to write a script that will allow you to remove this junk code. You will often see sequences of
API calls littered across the decompiled code; they often start with the following calls:
```c
GetCurrentProcessId();
GetCurrentProcessId();
GetLastError();
GetConsoleCP();
```
These correspond to the following assembly instructions:
```
10003e6c ff d3                CALL     EBX
10003e6e ff d3                CALL     EBX
10003e70 8b 35 c0 80 00 10    MOV      ESI, dword ptr [->GetLastError]
10003e76 ff d6                CALL     ESI
10003e78 8b 3d c4 80 00 10    MOV      EDI, dword ptr [->GetConsoleCP]
10003e7e ff d7                CALL     EDI
```
We want to replace all of these assembly instructions by NOPs (byte value `0x90`) so that the
decompiler no longer displays the irrelevant API calls. To do so, proceed in two steps:

1. Write a script that can replace a selection in the listing view by NOP values. Remember that you
   will have to call [clearListing][] before using [setByte][]. After having written the NOP
   values, you will have to call [disassemble][] to turn the bytes into code.
2. Re-write the script so that you can select the function calls in the decompiler. Remember to
   study [the Ghidra API reference](https://mal.re/api/) if you get stuck.

**Note:** In this specific example, it is possible to simply overwrite all opcodes that correspond
to the selected function calls with NOP bytes. This is not always a good idea for deobfuscating
junk code because you might overwrite instructions that are essential to the remaining code flow.

[clearListing]: https://mal.re/api/ghidra/program/flatapi/FlatProgramAPI.html#clearListing(ghidra.program.model.address.Address,ghidra.program.model.address.Address)
[setByte]: https://mal.re/api/ghidra/program/flatapi/FlatProgramAPI.html#setByte(ghidra.program.model.address.Address,byte)
[disassemble]: https://mal.re/api/ghidra/program/flatapi/FlatProgramAPI.html#disassemble(ghidra.program.model.address.Address)