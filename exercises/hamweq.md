---
tags: string-obfuscation, automation
---
Consider the sample with the following SHA-256 hash:
```
4eb33ce768def8f7db79ef935aabf1c712f78974237e96889e1be3ced0d7e619
```
Your first exercise is to find the string decryption function and reverse engineer it. This should
not take you very long. The main exercise is to automate the string decryption by means of a Ghidra
script:

1. Write a script to decrypt the currently selected memory contents with the key from this sample.
   - Note that the [Flat API](https://mal.re/api/ghidra/app/script/GhidraScript.html) has methods
     to get and set the value of a byte in memory. 
   - To get the currently selected bytes, look for the right Ghidra Script State variable in the
     Flat API documentation.
   - The `Address` interface has the useful methods [getOffset][], [add][], [subtract][]. If you
     want to turn a `long` value into an `Address`, the Flat API exposes [toAddr][].
2. Extend your script to convert the memory contents into a string literal after successfully
   decrypting it.
   - Ghidra is very reluctant to make any changes to the listing unless you call [clearListing][].
   - The Ghidra `Listing` interface represents the disassembly & memory view. It is responsible for
     assigning data types to memory contents. You can access this API by calling the [getListing][]
     method of the [currentProgram][] variable.
   - In Ghidra language, the data type of a memory region is modified by calling the [createData][]
     method of the `Listing` interface.
   - The Flat API implements several shortcuts to interact with the listing; you should be able to
     write this script without having to call [getListing][].
3. Re-write your script so that it decrypts all of the malware's strings.
   - Just as we used [createData][] to set the data type of a memory region, you can use the Flat
     API method [getDataAt][] to get the data at a given address including type information.
   - If a `Data` interface represents a pointer, the return value of [getValue][] will be of type
     `Address`.

[FlatProgramAPI]: https://mal.re/api/ghidra/program/flatapi/FlatProgramAPI.html
[add]: https://mal.re/api/ghidra/program/model/address/Address.html#add(long)
[createData]: https://mal.re/api/ghidra/program/model/listing/Listing.html#createData(ghidra.program.model.address.Address,ghidra.program.model.data.DataType)
[currentProgram]: https://mal.re/api/ghidra/program/flatapi/FlatProgramAPI.html#currentProgram
[getDataAt]: https://mal.re/api/ghidra/program/flatapi/FlatProgramAPI.html#getDataAt(ghidra.program.model.address.Address)
[getListing]: https://mal.re/api/ghidra/program/model/listing/Program.html#getListing()
[getOffset]: https://mal.re/api/ghidra/program/model/address/Address.html#getOffset()
[getValue]: https://mal.re/api/ghidra/program/model/listing/Data.html#getValue()
[subtract]: https://mal.re/api/ghidra/program/model/address/Address.html#subtract(long)
[toAddr]: https://mal.re/api/ghidra/program/flatapi/FlatProgramAPI.html#toAddr(long)
[clearListing]: https://mal.re/api/ghidra/program/flatapi/FlatProgramAPI.html#clearListing(ghidra.program.model.address.Address,ghidra.program.model.address.Address)