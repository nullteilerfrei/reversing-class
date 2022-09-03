---
tags: automation, string-obfuscation, stack-strings, scale-yourself, automation, emulation
---
Consider the sample with the following SHA-256 hash:
```
f65eeb136e23d06b54b15834ad15d4bcd2cd51af9e8c134da32da02bdcb68996
```
Your task is to write a script that emulates instructions using the [EmulatorHelper] class, in
order to extract the stack strings. The goal is not a fully automated script, but rather one where
the user selects a sequence of instructions to be emulated. It is recommended to use the memory
write tracking feature built into Ghidra's emulator, see the [enableMemoryWriteTracking] and
[getTrackedMemoryWriteSet] methods. After obtaining a string from emulated memory, add a comment
to the beginning of the emulated code area.

There is already a script called [EmuX86DeobfuscateExampleScript] that illustrates well how to use
the emulator; note however, that since we use memory write tracking, you do not necessarily have to
set up the stack manually.


[EmulatorHelper]: https://mal.re/api/ghidra/app/emulator/EmulatorHelper.html
[enableMemoryWriteTracking]: https://mal.re/api/ghidra/app/emulator/EmulatorHelper.html#enableMemoryWriteTracking(boolean)
[getTrackedMemoryWriteSet]: https://mal.re/api/ghidra/app/emulator/EmulatorHelper.html#getTrackedMemoryWriteSet()
[EmuX86DeobfuscateExampleScript]: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/ghidra_scripts/EmuX86DeobfuscateExampleScript.java