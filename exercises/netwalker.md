---
tags: api-hashing, ransomware, netwalker, python
---
Consider the sample with the following SHA-256 hash:
```
de04d2402154f676f757cf1380671f396f3fc9f7dbb683d9461edd2718c4e09d
```
The sample belongs to the ransomware family "Netwalker" and this exercise focuses on its API hashing functionality.

1. Identify and analyze the API hashing function.
2. Generate an enum for import in Ghidra. Feel free to use the supplied Python script so you can focus on implementing the actual hashing algorithm.
3. Find the function that uses `FindFirstFileW` to list directories and files.
