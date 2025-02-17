# Memory Forensics Report

## 1. Name of Suspicious Sample:
**scvhost.exe** (PID: 9160)

## 2. Why it is Suspicious:
- **Mispelled name**: The correct system process is *svchost.exe*
- **Parent Process (PPID: 4384)**: *explorer.exe* is launching *scvhost.exe*. Normally *scvhost.exe* is spawned by **services.exe (PID: 828)**
- **User mode execution**: A legitimate *svchost.exe* runs in Session 0, but *scvhost.exe* is running in Session 1, indicating user-space execution

## 3. Analyzing Memory dump (PID: 9160)
Obtained SHA-256 Hash: `43810BE66E6F500B4ABC4812FD49EE4C778F379F1712B98D722905B98A0EDB97`
