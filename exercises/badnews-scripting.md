---
tags: automation, string-obfuscation, stack-strings
---
Consider the sample with the following SHA-256 hash:
```
f65eeb136e23d06b54b15834ad15d4bcd2cd51af9e8c134da32da02bdcb68996
```
It uses a number of obfuscation techniques, this exercise is about deobfuscating the stack strings:
```
0x10002a4d: MOV dword ptr [DAT_10018e80],0x6e72656b
0x10002a57: MOV dword ptr [DAT_10018e84],0x32336c65
0x10002a61: MOV dword ptr [DAT_10018e88],0x6c6c642e
```
This is a sequence of `mov` instructions that build the stack string "kernel32.dll".

Your task is to write a script that works as follows: The user (which would commonly be you) has to
select the sequence of variable assignments that correspond to a stack string and then execute the
script. It will then compute the contents of the stack string and insert them as a comment. There
is a function you can copy & paste from the lecture notes to create comments. Here are a few other
things that might help you:

- You should know how to iterate over selected addresses by now.
- Look into [getInstructionAt][] from the Flat API and the [Instruction][] class.
- The operand of a `mov` instruction with an immediate argument is of type [Scalar][].

[Scalar]: https://mal.re/api/ghidra/program/model/scalar/Scalar.html
[Instruction]: https://mal.re/api/ghidra/program/model/listing/Instruction.html
[getInstructionAt]: https://mal.re/api/ghidra/program/flatapi/FlatProgramAPI.html#getInstructionAt(ghidra.program.model.address.Address)