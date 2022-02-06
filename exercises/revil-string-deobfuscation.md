---
tags: algorithm-identification, automation, ransomware, revil, rc4, sodinokibi
---
Consider the sample with the following SHA256 hash:
```
12d8bfa1aeb557c146b98f069f3456cc8392863a2f4ad938722cd7ca1a773b39
```
It leverages string obfuscation as an anti-analysis technique and uses RC4 to do so.

1. Perform a top-down analysis to find the string deobfuscation function and the underlying RC4
   implementation. Before you head off to the strings, the RC4 routine is called in another spot.
   Find it and manually decrypt the data.
2. Coming back to the string deobfuscation function: determine the memory layout and manually
   decrypt a few strings before going to the next step.
3. Use the file `REvilStringDeobfuscation_Exercise.java` as a template to emulate the algorithm in
   Java and use it to deobfuscate all strings. It has a member function called `deobfuscate` that
   has a similar signature to the original string deobfuscation function. Your task is to implement
   it, double check the output by using `hexdump` before ruining your project. Once you are happy
   with the output, comment out the two lines that populate the Ghidra database with the
   deobfuscated strings.

Hints:
- The built-in `toAddr` function converts a `long` value to an Ghidra-specific `Address` object.
- Our very own block-buster function `getOriginalBytes` can be used to extract bytes from the
  original file by specifying an address and a size.
- Since the string deobfuscation uses the RC4 algorithm and we don't want to install the dependency
  ```
  Java.Default.Crypto.Factories.Ciphers.Stream.Legacy.ARC4
  ```
  we include a self-contained implementation in the template, you can use it like so:
  ```
  new RC4(key).decrypt(data)
  ```
