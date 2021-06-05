---
tags: top-down, file-wiper
---
Consider the sample with the following SHA-256 hash:
```
9f613a49d893d030c450186ef3abbac92fe068c84f94858620972781e15d86fe
```
Import the binary into Ghidra, and open it in the decompiler. Let Ghidra analyze it. Use the
`Symbol Table` or `Symbol Tree` to find the function called `entry` (the executable entry point)
and navigate to it. Determine what the program does.

**Do not execute it on your machine under any circumstances.**
