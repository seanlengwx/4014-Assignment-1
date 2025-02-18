# Memory Forensics Report
## OS Profile and Kernel Version:
- Kernel Base: 0xf80651600000
- OS: WindowsIntel32
- more details in: [info output](4014-Assignment-1/Output Files/info_output.txt)

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

## Exploring `EXCEL.EXE` (PID 8040)
- From looking at commands executed we see that it downloaded a file called `capbudg.xlsm`
```
8040    EXCEL.EXE       "C:\Program Files (x86)\Microsoft Office\Root\Office16\EXCEL.EXE" "C:\Users\User\Downloads\capbudg.xlsm"
```
- Looking at the [filescan](Output Files/filescan_output.txt) we see that `capbudg.xlsm` has a virtual address of `0x850bb4652940`.
```
0x850bb4652940	\Users\User\Downloads\capbudg.xlsm
```
- Using the virtual address, we dump the files and obtain 2 files
  1. `file.0x850bb4652940.0x850bb3c0b010.SharedCacheMap.capbudg.xlsm.vacb`
  2. `file.0x850bb4652940.0x850bb45c4370.DataSectionObject.capbudg.xlsm.dat`
- Since it is a xlsm file, it could potentially have macros. Checking for that, we see VBA commands that utilize cells in the excel. Exploring the excel workbook, we navigate to the cells mentioned in the VBA command: `E14`, `F14`, `G14`, `H14`
- Here we find: `flag(memory_corruption_is_bad)`

## Exploring `calc.exe` (PID 1132)
- Looking at the [cmdline output](/Output Files/cmdline_output.txt) we see nothing suspicious
```
1132	calc.exe	"C:\Windows\calc.exe" 
3276	calc.exe	"C:\Windows\calc.exe" 
```

## Exploring `notepad.exe` (PID 10200)
- Looking at the [cmdline output](/Output Files/cmdline_output.txt) we see that the file `flag.txt` was created
```
10200	notepad.exe	"C:\Windows\system32\NOTEPAD.EXE" C:\Users\User\Desktop\flag.txt
```
- Exploring the [filescan](Output Files/filescan_output.txt) we see that the file `flag.txt.lnk` has the virtual address: `0x850bb4aa4190`
```
0x850bb4aa4190	\Users\User\AppData\Roaming\Microsoft\Windows\Recent\flag.txt.lnk
```
- Dumping the virtual address, we find the file `file.0x850bb4aa4190.0x850bb665e5d0.DataSectionObject.flag.txt.lnk.dat`
```
DataSectionObject       0x850bb4aa4190  flag.txt.lnk    file.0x850bb4aa4190.0x850bb665e5d0.DataSectionObject.flag.txt.lnk.dat
```
- However, renaming the extension reveals a bunch of scrambled unreadable text.
- Taking another approach, we **memdump** the PID 10200 and get the following output when searching for any flags
```
flag{d0nt_foRg3t_uN1c0de_$tR1nGsxt
flag{d0nt_foRg3t_uN1c0de_$tR1nGs}
flag{d0nt_foRg3t_uN1c0de_$tR1n
flag{d0nt_foRg3t_uN1c0de_$tR1nGs}
flag{d0nt_foRg3t_uN1c0de_$tR
flag{d0nt_foRg3t_uN1c
flag{d0nt_foRg3t_uN1c0de_
flag{d0nt_foRg3t_uN1c0de_$t
flag{d0nt_foRg3t_uN1c0de
```
- so we see that the 2nd flag is: `flag{d0nt_foRg3t_uN1c0de_$tR1nGs}`

## Exploring `scvhost.exe` (PID 9160)
- Dumpfiles gave us an error for dumping **DataSectionObject** but a successful dump for **ImageSectionObject** suggesting self-protection techniques
```
DataSectionObject       0x850bb6239960  scvhost.exe     Error dumping file
ImageSectionObject      0x850bb6239960  scvhost.exe   file.0x850bb6239960.0x850bb33757d0.ImageSectionObject.scvhost.exe.img
```

- The presence of `wow64cpu.dll`, `wow64.dll`, and `wow64win.dll` indicates 32-bit exewcution on a 64-bit system, which malware sometimes do to bypass security mechanisms.
- It is possible that `scvhost.exe` may be injecting itself into 64-bit processes
```
ImageSectionObject      0x850baef93830  wow64cpu.dll
ImageSectionObject      0x850baef92570  wow64.dll
ImageSectionObject      0x850bae4836a0  wow64win.dll
```
- Dependencies on `ntdll.dll` and `KernelBase.dll` which are used for process creation, memory manipulation, and API hooking strongly suggest that `scvhost.exe` is a malware which use API function hooks to evade detection.
```
ImageSectionObject      0x850baecf0070  ntdll.dll
ImageSectionObject      0x850baefe0d40  kernel32.dll
ImageSectionObject      0x850baee621f0  KernelBase.dll
```

