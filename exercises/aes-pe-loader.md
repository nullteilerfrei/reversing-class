---
tags: top-down, loader, aes, encryption, algorithm-identification
---
Consider the sample with the following SHA-256 hash:
```
ed675db1e7c93526141d40ba969bdc5bbdfd013932aaf1e644c66db66ff008e0
```
It is a dynamic link library (DLL) which implements a loader.

1. The malware protects itself from dynamic analysis. Explain how, and identify the algorithm that
   is used.
2. Identify the encryption algorithm that is used to decrypt the payload, and extract all relevant
   cryptographic secrets.
   
To verify that you have the correct data, you can decrypt the following message (hexadecimal
encoding):
```
18199ea3ffb4c4a1552eb4e42bf86bfe1cc4381a30402be60c86ea4d6584d0eb
```
It should decrypt to a plaintext string.
