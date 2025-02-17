# Memory Forensics Report
## OS Profile and Kernel Version:
- Kernel Base: 0xf80651600000
- OS: WindowsIntel32
- more details in: [info output](./info_output.txt)

## Name of Suspicious Sample:
**scvhost.exe** (PID: 9160)

## Why it is Suspicious:
- **Mispelled name**: The correct system process is `svchost.exe`
- **Parent Process (PPID: 4384)**: `explorer.exe` is launching `scvhost.exe`. Normally `scvhost.exe` is spawned by `services.exe (PID: 828)`
- **User mode execution**: A legitimate `svchost.exe` runs in Session 0, but `scvhost.exe` is running in Session 1, indicating user-space execution

## Analyzing Memory dump (PID: 9160)
Obtained SHA-256 Hash: `43810BE66E6F500B4ABC4812FD49EE4C778F379F1712B98D722905B98A0EDB97`

- **VirusTotal**: 4/72 security vendors flagged as malicious.

- Further analysis of [pslist output](./pslist_output.txt) shows that `scvhost.exe` also creates `conhost.exe (PID: 6568)` but **VirusTotal** doesn't show anything for `conhost.exe (PID: 6568)`

## NetScan [(Full output)](./netscan_output.txt)
### 1. `EXCEL.EXE` Making External Connections (PID 8040)
```
0x850bb3566a20	TCPv4	192.168.221.131	49734	23.217.112.41	443	ESTABLISHED	8040	EXCEL.EXE	2025-01-27 09:08:18.000000 UTC
0x850bb3b22b50	TCPv4	192.168.221.131	49732	23.217.112.41	443	ESTABLISHED	8040	EXCEL.EXE	2025-01-27 09:08:18.000000 UTC
0x850bb3dac010	TCPv4	192.168.221.131	49733	23.217.112.41	443	ESTABLISHED	8040	EXCEL.EXE	2025-01-27 09:08:18.000000 UTC
```
- Microsoft Excel should not normally establish network connections.
- The remote IP `23.217.112.41` belongs to **Akamai** which hosts legitimate services but is also know to be used for malware delivery.
- Possibly indiciate macro-based malware, DDE injection, or weaponized Excel documents communicating with an external server.

### 2. `calc.exe` Establishing External Connections (PID 1132)
```
0x850bb3b32b50	TCPv4	192.168.221.131	49753	192.168.170.132	65432	ESTABLISHED	1132	calc.exe	2025-01-27 09:07:48.000000 UTC
```
- `calc.exe` is a legitimate Windows calculator application, but it should never establish network connections.
- The remote IP `192.168.170.132:65432)` suggests a local persistence mechanism or reverse shell.
- The port **65432** is often used in meterpreter shells or backdoors

### 3. `SearchApp.exe` Communicating with Multiple IPs (PID 6160)
```
0x850bb37cc720	TCPv4	192.168.221.131	49685	103.1.139.65	443	ESTABLISHED	6160	SearchApp.exe	2025-01-27 09:06:55.000000 UTC
0x850bb37ce4a0	TCPv4	192.168.221.131	49684	103.1.139.34	443	ESTABLISHED	6160	SearchApp.exe	2025-01-27 09:06:55.000000 UTC
```
- `SearchApp.exe` is part of Windows Search, but it rarely makes external connections.
- IP Addresses (`103.1.139.65` and `103.1.139.34`) are not typical Microsoft servers.
- Possibly indicate processs hollowing, DLL injection, or C2 beaconing.

### 4. `smartscreen.exe` Connecting to External IP (PID 6516)
```
0x850bb36e64a0	TCPv4	192.168.221.131	49698	52.139.252.32	443	ESTABLISHED	6516	smartscreen.ex	2025-01-27 09:07:05.000000 UTC
```
- `smartscreen.exe` is a Windows Defender Component but attackers often use fake versions for bypassing security.
- Connection is to `52.139.252.32`, which belongs to Microsoft Azure, but malware could still use this service.

### 5. `svchost.exe` Connecting to suspicious IP (PID 3572)
```
0x850bb2ba64d0	TCPv4	192.168.221.131	49751	20.198.162.76	443	ESTABLISHED	3572	svchost.exe	2025-01-27 09:07:48.000000 UTC
```
- `svchost.exe` normally communicates with Microsoft services, but its parent should be `services.exe`
- IP `20.198.162.76` is a Microsoft IP, but some malware hides within legitimate traffic.
