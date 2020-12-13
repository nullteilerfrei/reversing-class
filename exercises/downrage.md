---
tags: bottom-up, rat, string-obfuscation
---
Consider the sample with the following SHA-256 hash:
```
2396c9dac2184405f7d1f127bec88e56391e4315d4d2e5b951c795fdc1982d59
```
It is a piece of malware that communicates with a C2 server. Your task is to understand the string obfuscation technique and extract the C2 server hostname. We recommend to use a **bottom-up** approach: Identify all calls to the Windows API function [`InternetConnectA`][InternetConnectA] and work your way upwards to the C2 server from there.

[InternetConnectA]: https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetconnecta