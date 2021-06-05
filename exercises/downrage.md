---
tags: bottom-up, rat, string-obfuscation
---
Consider the sample with the following SHA-256 hash:
```
2396c9dac2184405f7d1f127bec88e56391e4315d4d2e5b951c795fdc1982d59
```
It is a piece of malware that communicates with a C2 server. Your task is to understand the string obfuscation technique and extract the C2 server hostname. We recommend to use a **bottom-up** approach: Identify all calls to the Windows API function [`InternetConnectA`][InternetConnectA] and work your way upwards to the C2 server from there.

**Scripting Bonus.** A different approach to this problem is the following: 
1. Write a Ghidra Script that lists all functions in the binary with their respective address, sorted by the number of times that they are referenced in the code.
2. Search this list, starting with the function that is most frequently referenced, for a function that looks like it could be the string deobfuscation routine.
3. Verify your suspicion.
4. Find the part of the code where this function is used to deobfuscate the C2 server.

Hint: To get all functions, first factory yourself a function manager using `currentProgram.getFunctionManager()`, it should have everything you need. Furthermore, the `GhidraFlat` API has a function called `getReferencesTo` which might also come in handy.

[InternetConnectA]: https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetconnecta
[FunctionsWithCallCount]: https://github.com/nullteilerfrei/reversing-class/blob/master/scripts/java/FunctionsWithCallCount.java