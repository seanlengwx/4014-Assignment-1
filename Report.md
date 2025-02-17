# Memory Forensics Report

## 1. Name of Suspicious Sample:
**malware.exe** (PID: 1234)

## 2. Why it is Suspicious:
- The process was running from **C:\Users\Public\malware.exe**
- It had **no parent process** (possibly injected)
- Connected to **suspicious external IP 192.168.1.100:8080**

## 3. Steps Taken to Obtain the Flag:
1. Used `pslist` to identify the process.
2. Dumped it with `--dump` and extracted the original binary.
3. Ran it in a sandbox environment, captured network requests.
4. Found the flag in the registry key `HKLM\Software\flag{}`
5. Reverse-engineered the binary and confirmed it was XOR-encoded.

## 4. Flag:
**flag{example_flag_here}**
