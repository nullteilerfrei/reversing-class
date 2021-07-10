---
tags: algorithm-identification, flawed-downloader, encryption, rc4
---
In a previous exercise, we extracted the C2 server address from a FlawedDownloader sample. It was
```
http[:]//92.38.135[.]99/22.b
```
and an online sandbox was able to retrieve a next-stage payload with a SHA256 hash of:
```
3530b085f7de6d275ed7ac948ece7a463393a55f6c371456b9dc4c6f0da01f8c
```

1. Take another look at the FlawedDownloader sample with SHA256 hash
   ```
   25e9af3dd5f04e33b54f562cf6db864e0406e3752c2283d0c4ff6907038da3e2
   ```
   and determine the algorithm used to decrypt the next-stage payload as well as corresponding
   cryptographic material.
2. Can you identify its malware family without doing a full deep dive?
