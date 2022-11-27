---
tags: algorithm-identification, NedDnLoader, lz4, aes, md5
---
Consider the sample which belongs to the [NedDnLoader][] malware family with SHA256 hash
```
0fe796e1b7db725115a7de7ee8a56540f838305356b5de2f24de0883300e2c23
```
It was observed as an artifact that resulted from execution with a similar command line as the
following:
```
rundll32.exe desktop.dat, BZ2_bzZip S-2-20-8798-18246938-238138-0443 0 0 8000 1
```
Identify the algorithms implemented by the following functions:
1. `FUN_180005b40`: Further analysis will suggest that one of the above command line switchs is
   passed to this function resulting in `80a001178482591b63753ee04ccdf517`.
2. `FUN_180002590`: It receives `80a001178482591b63753ee04ccdf517` as an argument as well as the
   buffer of length `0x340` located at `0x180026994`.
3. Under certain conditions - which are not fulfilled in this sample - the result is then
   passed to the function below. What does this function do?
   ```
   FUN_180004eb0(BYTE *Input, BYTE *Output, int InputLen, int OutputLen)
   ```
   We include `test.jpg.wat` along with this exercise to allow you to validate your findings.

[NedDnLoader]: https://malpedia.caad.fkie.fraunhofer.de/details/win.neddnloader
