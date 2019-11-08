# Introduction

## What is Reverse Engineering?

In the context of software, reverse engineering is the process of recovering an abstract description of how a program operates. In many cases, the reverse engineer has nothing to work with except for a compiled binary, which is also the situation we will focus on. 

One important discipline of reverse engineering is _dynamic_ analysis, which focuses on studying the behaviour of a program during execution, often by means of a debugger. Conversely, _static_ analysis is the art of deducing program logic by pure deductive reasoning from the code. In reality, a hybrid approach is widely considered to be most efficient. Be that as it may, this is the last we are going to say about dynamic analysis here.

There are many tools available to translate the machine code of a given binary into easier to read types of code. The first step is usually to recover the assembly code. Up until recently, there was no freely available software to recover high-level code. On March 5th, 2019, the NSA publicly released their _decompiler_ and made it freely available: It is called _Ghidra_ and is pronounced the way it is spelled.

Ghidra transforms machine code into C-like code. The remaining task of a reverse engineer becomes refactoring of this code in order to improve its readability. In many cases, this makes it possible to deduce the internal logic of a program without reading assembly language. The time saved in this way is quite considerable, and it also lowers the entry barrier for up and coming reverse engineers.

One important application of software reverse engineering is the analysis of malicious programs. We focus here on reverse engineering of Windows malware because it is quite simply the most prevalent threat.

## What don't we do?

The course does not cover the following topics:

- Ghidra Scripting
- Dynamic Analysis
- Malware that is not Windows malware
- Any software that is not malware
- MSIL Malware (because it is not compiled (ಠ_ಠ))
- Malware Unpacking

Furthermore, the binaries analyzed during the course will usually have been compiled with a C/C++ compiler and were not originally written in other languages such as Delphi, GoLang, or VB. We mention these languages in particular because they are popular choices among malware authors.

## Alternatives

The industry standard for binary reverse engineering is [IDA], using the [HexRays Decompiler]. However, these are not exactly cheap. Before the release of the Ghidra, the only alternatives were [RetDec] and [Hopper], but both of these are arguably less powerfull than Ghidra and IDA. Given these considerations, we consider Ghidra the best choice for entry level reverse engineering. 

## Motivations for Reverse Engineering

There is a number of reasons to reverse engineer software in general:

- Quality Assurance: _"Does it do what it is supposed to do?"_
- Interoperability: A wild undocumented binary blog appears.
- Educational Purposes: A welcome excuse to hack.
- Malware Analysis: Understand The Bad Guys™.
- Exploit Development: _"Are there bugs? Can I exploit them to make it behave in a way it was not intended?"_
- Cracking: Circumvent copy right protection.
- Economic Espionage: How does it work with the goal to reimplement it and then sell it.

We are not lawyers, but we believe the above list to roughly be sorted by how nefarious the purpose is.

## Types of Malware

Classifying malware is a desaster. Here is our miserable attempt:

### Stagers

A _stager_ is anything whose primary goal is to eventually deliver additional malware, which is referred to as the _next stage_. We roughly classify stagers as one of the following:

- Downloader
- Dropper
- Loader

A _downloader_ retrieves the next stage from a remote host in some way while a _dropper_ already contains the next stage. A _loader_ is similar to a dropper but does not write the next stage to disk; instead it executes it in memory.

### Final Stages

The following are some possible final stages of a malware deployment:

- Backdoor
- Remote Access Tool
- Bot
- Rootkit
- Bootkit
- Banker
- Stealer
- Ransomware
- Wiper

We try to give a brief description of all of these, but note that the lines between these terms are quite blurry. Any malware can be one, or multiple, or not quite any of the above. 

A _backdoor_ is the most rudimentary malware; it simply offers some way to gain access to the infected system. Common types of backdoors are connect-back shells or bindshells, or even more simple tools that can execute arbitrary commands. A _Remote Access Tool_ (RAT) is any malware that implements remote access to the operating system. The scope and extent of this access is left intentionally vague but may include things such as file system access, registry modification, command execution, upload, download, and remote desktop capabilities. 

Malware is referred to as a _bot_ not primarily because of its capabilities, but because of its large-scale distribution and operation: All the bots together form a _botnet_, and bots are often used to perform tasks for which it is useful to have control over a large number of machines: DDoS, spam mailing, etcetera. 

The definition of a _rootkit_ is among the more testy subjects. We will quote Wikipedia:

> A rootkit is a collection of computer software, typically malicious, designed to enable access to a computer or an area of its software that is not otherwise allowed (for example, to an unauthorized user) and often masks its existence or the existence of other software.

The most infamous rootkits are so called _kernel-mode_ rootkits which nest in the operating system kernel to hide nefarious processes, files, and even network activity. A _bootkit_ is malware which persists in a different memory area than RAM or hard disk, thereby becoming resistent even against reinstallation of the OS.

The primary purpose of a _banker_ is to steal money by interfering with the communication between the victim and their online banking provider. The details of this can range from simple social engineering techniques to complex frameworks that act as a man in the middle. The term _stealer_ refers to malware that primarily exfiltrates information, documents, and credentials. _Ransomware_ encrypts all your files and demands ransom for them. That's about it. In contrast, a _wiper_ is a program that simply destroys data irrecoverably, usually by deleting files or overwriting them with junk.

Some malware is produced by so-called _Builders_. While these are not precisely malware, they may contain malware stubs and are arguably related to it.

### Where to Get The Malware

- Malware Repositories:
  - Get a job in the industry to get access to [VirusTotal].
  - If that is not an option, use [MalShare].
- Sometimes, friendly cyber criminals just send you malware. Keep an eye on your inbox.
- If you are very important, you might even get targeted malware. Lucky you!

## Common Tasks of Malware Reverse Engineers

- Recover indicators of compromise (IOC)
  - Command and control (C2) servers
  - File paths
  - Mutex names
- Design signatures
  - Snort (network communication), i.e. User-Agent strings
  - YARA: binary patterns
- Describe malware features
- identification (at least partly, if possible)
  - subroutines may be taken from publicly available repositories
  - the whole malware may be open source
  - malware family / strain (also possible for closed source malware)
- programming styles: experience, habits and skill level of the author
  - used libraries
  - used programming patterns
  - uncommon techniques
    - non-standard implementations for algorithms
    - unique magic constants
  - reimplementations of standard algorithms
  - tendency to use static or dynamic linking
  - prefences for certain APIs
- understand if a given sample even is malware.

## Reversing Styles

- deductive vs inductive
- top down vs. bottom up
- dynamic vs. static

# Ghidra

## A few Hints

- When importing a file, click `Options` and check `Load External Libraries` (potentially edit the import paths) to make Ghidra follow Win32 API imports into the corresponding dynamic link libraries (DLLs). This is a good thing. If you have a Windows OS, you can use the DLLs from that machine. Alternatively, we provide DLLs from a copy of ReactOS, which is a free and open source Windows clone.
- You should import our keybindings. These keybindings strive to be as close as possible to the [IDA] keybindings because we are used to them. Also, they are good. Look, if you use different keybindings, this will only be confusing during the course! Just import the damn keybindings!


## Reversing First Steps

Open the binary with Ghidra, and open it in the decompiler. Let Ghidra analyze it. For a top-down approach, use the `Symbol Table` or `Symbol Tree` to find the function called `entry` (the executable entry point) and navigate to it. This is the code that is executed when the program starts. As a first sample, we will investigate the file with the following SHA-256 hash:
```
9f613a49d893d030c450186ef3abbac92fe068c84f94858620972781e15d86fe
```
When we look at its entry point, we see function calls named `GetProcessHeap()`, `HeapAlloc()`, and `GetWindowsDirectoryW()` which are highlighted in a dark shade of blue. These are calls to Windows API functions, i.e. these are functions that are provided by the Windows OS. To understand what they do, you will have to refer to the [MSDN Library]. If you are on Windows, then you can refer to [this blog article][NTF-MSDN] for how to obtain an offline copy of this API reference. Sadly, we do not know of any cross-platform alternative at this point in time. However, it is quite efficient to simply Google the name of the API function and take the first hit.

Having understood that `GetWindowsDirectoryW()` retrieves the path to the Windows directory, we can proceed to rename the variable `DAT_140003208` as `WINDOWS_DIRECTORY`. To do so, right-click the variable and use the `Rename Global` option. In the menu, you will also note the keyboard shortcut for this operation. Remember it and never use the menu option again. When we encounter a reference to this variable later in our analysis, we will know what it is. It is generally recommendable to choose good names for every variable and function that we have understood; reverse engineering is quite similar to refactoring a really horribly written legacy codebase. Note however, that you will not always have a good understanding of every variable and function right away - in this case, it is often a good idea to give it _some_ name, so that you recognize it later when it occurs in a different context. This can help you to give it a good name later.

For example, as we proceed to investigate the purpose of the next function `BCryptOpenAlgorithmProvider()`, it occurs to us that we (possibly) have no idea what this is all about. Sometimes, in reverse engineering, it is important to skip over certain parts and continue with the code that comes after in the hope to fill the gaps later. If you do not quite understand what `BCryptOpenAlgorithmProvider()` does; simply continue. But it's probably something with crypto. Could this be ransomware? Let's rename the variable `DAT_140003420` to `STH_WITH_CRYPTO` and worry about this later. The convention here is that we prefix unknown globals with `STH` for _"something"_.

For a bottom-up approach, investigate the `Imports` section in the `Symbol Tree` to find API functions that are used by the program. Find references to these functions in the code and study how they are being applied.


## Recognizing Compression and Cryptographic Routines

For Both:
- If you know the algorithm, you might recognize the structure.
- Lots of arithmetic
- Characteristic constant values

Compression:
- Backreferences into already decompressed data
- No decryption key

Cryptography:
- Several algorithms can be detected with YARA rules.
- The arguments could be a ciphertext buffer and a decryption key.



[IDA]: https://www.hex-rays.com/products/ida/
[HexRays Decompiler]: https://www.hex-rays.com/products/decompiler/
[Hopper]: https://www.hopperapp.com/
[RetDec]: https://github.com/avast/retdec
[MalShare]: https://malshare.com/
[VirusTotal]: https://www.virustotal.com/
[MSDN Library]: https://docs.microsoft.com/en-us/windows/win32/api/
[NTF-MSDN]: https://blag.nullteilerfrei.de/2019/07/29/ghidra-msdn-offline-library-love/