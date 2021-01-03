---
tags: algorithm-identification, aplib, compression, dynamic-api-resolution, junk-code, obfuscation, shellcode, structs, top-down
---
Your task, should you choose to accept it, is to unpack and analyze a complex crimeware sample. We will start with the first stage and unpack several layers until we arrive at the final payload.

1. Obtain the sample with the SHA-256 hash
   ```
   ad320839e01df160c5feb0e89131521719a65ab11c952f33e03d802ecee3f51f
   ```
   and perform a **top-down** analysis to identify the shellcode that is responsible for loading the next stage.
   There is a lot of junk code in this executable, so make sure to prune your analysis accordingly.
2. Analyze the shellcode and write a script that is able to extract the payload statically.
   You will be confronted with the following challenges:
   - The shellcode performs dynamic API resolution.
   - The shellcode decrypts the payload using a custom algorithm.
   - That's not all it does.
3. Run your script to extract the DLL payload from this loader. It has the following SHA-256 hash:
   ```
   25e9af3dd5f04e33b54f562cf6db864e0406e3752c2283d0c4ff6907038da3e2
   ```
   Determine the purpose of this payload and extract any relevant host and network indicators (C2 addresses, file names, cryptographic secrets).

Bonus Exercise (0 Points): Write a Ghidra script which allows you to:

1. Select lines of code in the listing view and replace all selected instructions by an appropriate number of `NOP` instructions.
2. The same, but allow selection of lines in the decompiler window.
