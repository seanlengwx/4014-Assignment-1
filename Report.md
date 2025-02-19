# Memory Forensics Report
## OS Profile and Kernel Version:
- 🖥️Command: ``` vol.py -f "C:\Users\Malware_Analyst\Desktop\memory.dmp" windows.info > info_output.txt ```
- Kernel Base: 0xf80651600000
- OS: WindowsIntel32
- more details in: [info output](<./Output Files/info_output.txt>)


## Name of Suspicious Sample:
**scvhost.exe** (PID: 9160)

## Parent and Child Processes
- 🖥️Command: ``` vol.py -f "C:\Users\Malware_Analyst\Desktop\memory.dmp" windows.pstree > pstree_output.txt ```
- Looking at the [pstree](<./Output Files/pstree_output.txt>) we see that the suspicious sample is spawned by a few processes:
```
764	700	winlogon.exe	0x850bb1bf0180
* 4344	764	userinit.exe	0x850bb31f0340
** 4384	4344	explorer.exe	0x850bb320c300
*** 7812	4384	OneDrive.exe	0x850bb3fed080
**** 9208	7812	Microsoft.Shar	0x850bb47db080
*** 8040	4384	EXCEL.EXE	0x850bb3fec080
*** 9160	4384	scvhost.exe	0x850bb65de080
**** 6568	9160	conhost.exe	0x850bb656f080
*** 3276	4384	calc.exe	0x850bb4450300
**** 7656	3276	conhost.exe	0x850bb3e612c0
**** 1132	3276	calc.exe	0x850bb49240c0
*** 7668	4384	SecurityHealth	0x850bb460f080
*** 7732	4384	vmtoolsd.exe	0x850bb4125240
*** 10200	4384	notepad.exe	0x850bb656c080
*** 6524	4384	msedge.exe	0x850bb36e7280
**** 5056	6524	msedge.exe	0x850bb4257080
**** 7204	6524	msedge.exe	0x850bb3d650c0
**** 8	6524	msedge.exe	0x850bb3384080
**** 6864	6524	msedge.exe	0x850bb3aa60c0
**** 6672	6524	msedge.exe	0x850bb3382080
**** 6704	6524	msedge.exe	0x850bb4141080
**** 8632	6524	msedge.exe	0x850bb4136080
* 940	764	fontdrvhost.ex	0x850bb1d11080
* 1044	764	dwm.exe	0x850bb2453080
```
### Suspicious indicators
- Mispelled Process Name
  1. The correct Windows system process is `svchost.exe` but here it is `scvhost.exe`
  2. Probably an attempt to avoid detection
- Parent Process: `explorer.exe` (PID 4384)
  1. Legitimate `svchost.exe` should be launched by `services.exe` (PID 828)
  2. `scvhost.exe` was started by `explorer.exe`, which is NOT normal
  3. This suggests that it was executed manually either by a maliucious script or user action
- `scvhost.exe` has a `conhost.exe` child process (PID 6568)
  1. `conhost.exe` is often used to execute command-line instructions
  2. Malware often use this to execute PowerShell, batch scripts, or reverse shells
- Execution timestamp
  1. Started at `09:08:01 UTC` later than system processes (e.g., `winlogon.exe` at `09:06:35 UTC`)
  2. Indicates it was executed after login, potentially as a user-space malware
- Other suspicious child processes
  1. `calc.exe` (PID 3276, 1132) -> Sometimes used for LOLBin
  2. `notepad.exe` (PID 10200) -> opened `flag.txt`

## Analyzing Memory dump (PID: 9160)
- 🖥️Command: ``` vol.py -f "C:\Users\Malware_Analyst\Desktop\memory.dmp" windows.dumpfiles.DumpFiles --pid 9160 ```
- Obtained SHA-256 Hash: `43810BE66E6F500B4ABC4812FD49EE4C778F379F1712B98D722905B98A0EDB97`
- **VirusTotal**: 4/72 security vendors flagged as malicious.

## NetScan [output](<./Output Files/netscan_output.txt>)
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
- 🖥️Command: ```vol.py -f "C:\Users\Malware_Analyst\Desktop\memory.dmp" windows.cmdline | findstr "EXCEL.EXE"```
- From looking at commands executed we see that it downloaded a file called `capbudg.xlsm`
```
8040    EXCEL.EXE       "C:\Program Files (x86)\Microsoft Office\Root\Office16\EXCEL.EXE" "C:\Users\User\Downloads\capbudg.xlsm"
```
- 🖥️Command: ```vol.py -f "C:\Users\Malware_Analyst\Desktop\memory.dmp" windows.filescan | findstr "capbug.xlsm"```
- Looking at the [filescan](<./Output Files/filescan_output.txt>) we see that `capbudg.xlsm` has a virtual address of `0x850bb4652940`.
```
0x850bb4652940	\Users\User\Downloads\capbudg.xlsm
```
- 🖥️Command: ```vol.py -f "C:\Users\Malware_Analyst\Desktop\memory.dmp" windows.dumpfiles.DumpFiles --virtaddr 0x850bb4652940"```
- Using the virtual address, we dump the files and obtain 2 files
  1. `file.0x850bb4652940.0x850bb3c0b010.SharedCacheMap.capbudg.xlsm.vacb`
  2. `file.0x850bb4652940.0x850bb45c4370.DataSectionObject.capbudg.xlsm.dat`
- Since it is a xlsm file, it could potentially have macros.
- 🖥️Command: ```olevba file.0x850bb4652940.0x850bb45c4370.DataSectionObject.capbudg.xlsm.dat"```
- Checking for that, we see VBA commands that utilize cells in the excel. Exploring the excel workbook itself, we navigate to the cells mentioned in the VBA command: `E14`, `F14`, `G14`, `H14`
- 🚩Here we find: `flag(memory_corruption_is_bad)`

## Exploring `calc.exe` (PID 1132)
- 🖥️Command: ```vol.py -f "C:\Users\Malware_Analyst\Desktop\memory.dmp" windows.cmdline | findstr "calc.exe"```
- Looking at the [cmdline output](<./Output Files/cmdline_output.txt>) we see nothing suspicious
```
1132	calc.exe	"C:\Windows\calc.exe" 
3276	calc.exe	"C:\Windows\calc.exe" 
```

- 🖥️Command: ```vol.py -f "C:\Users\Malware_Analyst\Desktop\memory.dmp" windows.dumpfiles.DumpFiles --pid 1132```
- Looking at the memory dump of (PID 1132), we see that it contains Python-related files (`python39.dll`, `_hashlib.pyd`, `_socket.pyd`,etc.).
- This suggests the execution of Python scripts within `calc.exe`
- This is a known persistence technique where malware uses `calc.exe` to execute hidden payloads.
```
ImageSectionObject      0x850baef94ed0  KernelBase.dll  file.0x850baef94ed0.0x850baef9cc00.ImageSectionObject.KernelBase.dll.img
ImageSectionObject      0x850bb3a50420  python39.dll    file.0x850bb3a50420.0x850bb48b9d60.ImageSectionObject.python39.dll.img
ImageSectionObject      0x850bb4d260e0  md__mypyc.cp39-win_amd64.pyd    file.0x850bb4d260e0.0x850bb4905b00.ImageSectionObject.md__mypyc.cp39-win_amd64.pyd.img
DataSectionObject       0x850bb3334560  calc.exe        Error dumping file
ImageSectionObject      0x850bb3334560  calc.exe        file.0x850bb3334560.0x850bb3768a20.ImageSectionObject.calc.exe.img
ImageSectionObject      0x850bb4aa9460  _bz2.pyd        file.0x850bb4aa9460.0x850bb49058a0.ImageSectionObject._bz2.pyd.img
ImageSectionObject      0x850bb4d247e0  _lzma.pyd       file.0x850bb4d247e0.0x850bb1cf1730.ImageSectionObject._lzma.pyd.img
ImageSectionObject      0x850bb4d26d60  unicodedata.pyd file.0x850bb4d26d60.0x850bb3f03a20.ImageSectionObject.unicodedata.pyd.img
ImageSectionObject      0x850bb4d25dc0  backend_c.cp39-win_amd64.pyd    file.0x850bb4d25dc0.0x850bb3076270.ImageSectionObject.backend_c.cp39-win_amd64.pyd.img
ImageSectionObject      0x850bb4d26a40  _hashlib.pyd    file.0x850bb4d26a40.0x850bb48f4b00.ImageSectionObject._hashlib.pyd.img
ImageSectionObject      0x850bb4aa8970  libssl-1_1.dll  file.0x850bb4aa8970.0x850bb4a22d30.ImageSectionObject.libssl-1_1.dll.img
ImageSectionObject      0x850bb4aa44b0  libcrypto-1_1.dll       file.0x850bb4aa44b0.0x850bb46ef4a0.ImageSectionObject.libcrypto-1_1.dll.img
ImageSectionObject      0x850bb4d24970  _ssl.pyd        file.0x850bb4d24970.0x850bb30bf270.ImageSectionObject._ssl.pyd.img
ImageSectionObject      0x850bb260b0c0  version.dll     file.0x850bb260b0c0.0x850bb2689c30.ImageSectionObject.version.dll.img
ImageSectionObject      0x850bb4d25aa0  select.pyd      file.0x850bb4d25aa0.0x850bb49048a0.ImageSectionObject.select.pyd.img
ImageSectionObject      0x850bb4a96220  _socket.pyd     file.0x850bb4a96220.0x850bb1d0f010.ImageSectionObject._socket.pyd.img
ImageSectionObject      0x850bb4d3b0d0  ucrtbase.dll    file.0x850bb4d3b0d0.0x850bb4a1e8a0.ImageSectionObject.ucrtbase.dll.img
ImageSectionObject      0x850bb4d26bd0  md.cp39-win_amd64.pyd   file.0x850bb4d26bd0.0x850bb4906d60.ImageSectionObject.md.cp39-win_amd64.pyd.img
ImageSectionObject      0x850bb3a56b40  _queue.pyd      file.0x850bb3a56b40.0x850bb3c24cc0.ImageSectionObject._queue.pyd.img
ImageSectionObject      0x850bb4d3a770  VCRUNTIME140.dll        file.0x850bb4d3a770.0x850bb48b5a20.ImageSectionObject.VCRUNTIME140.dll.img
ImageSectionObject      0x850bb40255f0  python3.dll     file.0x850bb40255f0.0x850bb48acdf0.ImageSectionObject.python3.dll.img
ImageSectionObject      0x850bb2a471d0  rasadhlp.dll    file.0x850bb2a471d0.0x850bb2923b40.ImageSectionObject.rasadhlp.dll.img
ImageSectionObject      0x850bb27d79c0  FWPUCLNT.DLL    file.0x850bb27d79c0.0x850bb2898cc0.ImageSectionObject.FWPUCLNT.DLL.img
ImageSectionObject      0x850bb1cc5390  cryptsp.dll     file.0x850bb1cc5390.0x850bb1cb2cc0.ImageSectionObject.cryptsp.dll.img
ImageSectionObject      0x850bb1cc5e80  IPHLPAPI.DLL    file.0x850bb1cc5e80.0x850bb1cbaa20.ImageSectionObject.IPHLPAPI.DLL.img
ImageSectionObject      0x850bb1ce4150  rsaenh.dll      file.0x850bb1ce4150.0x850bb1cecd00.ImageSectionObject.rsaenh.dll.img
ImageSectionObject      0x850bb1cc6c90  mswsock.dll     file.0x850bb1cc6c90.0x850bb1cb4cc0.ImageSectionObject.mswsock.dll.img
ImageSectionObject      0x850bb1cc5cf0  dnsapi.dll      file.0x850bb1cc5cf0.0x850bb1cb9cc0.ImageSectionObject.dnsapi.dll.img
ImageSectionObject      0x850baef95830  win32u.dll      file.0x850baef95830.0x850baefc1920.ImageSectionObject.win32u.dll.img
ImageSectionObject      0x850bb1cc6b00  cryptbase.dll   file.0x850bb1cc6b00.0x850bb1cb2a20.ImageSectionObject.cryptbase.dll.img
ImageSectionObject      0x850baef94bb0  gdi32full.dll   file.0x850baef94bb0.0x850baefbfd00.ImageSectionObject.gdi32full.dll.img
ImageSectionObject      0x850baef93ce0  user32.dll      file.0x850baef93ce0.0x850baef3e9e0.ImageSectionObject.user32.dll.img
ImageSectionObject      0x850baef95510  gdi32.dll       file.0x850baef95510.0x850baeee7510.ImageSectionObject.gdi32.dll.img
ImageSectionObject      0x850baef951f0  bcrypt.dll      file.0x850baef951f0.0x850baef47c90.ImageSectionObject.bcrypt.dll.img
ImageSectionObject      0x850baef956a0  msvcp_win.dll   file.0x850baef956a0.0x850baef9c050.ImageSectionObject.msvcp_win.dll.img
ImageSectionObject      0x850baef95e70  bcryptprimitives.dll    file.0x850baef95e70.0x850baeee7a50.ImageSectionObject.bcryptprimitives.dll.img
ImageSectionObject      0x850baef94250  ucrtbase.dll    file.0x850baef94250.0x850baef47790.ImageSectionObject.ucrtbase.dll.img
ImageSectionObject      0x850baef94700  crypt32.dll     file.0x850baef94700.0x850baeee77b0.ImageSectionObject.crypt32.dll.img
ImageSectionObject      0x850baef920c0  advapi32.dll    file.0x850baef920c0.0x850baeee8010.ImageSectionObject.advapi32.dll.img
ImageSectionObject      0x850baef931f0  ws2_32.dll      file.0x850baef931f0.0x850baeee8550.ImageSectionObject.ws2_32.dll.img
ImageSectionObject      0x850baef92ed0  nsi.dll file.0x850baef92ed0.0x850baeee72b0.ImageSectionObject.nsi.dll.img
ImageSectionObject      0x850baef93e70  msvcrt.dll      file.0x850baef93e70.0x850baef45d60.ImageSectionObject.msvcrt.dll.img
ImageSectionObject      0x850baef93510  sechost.dll     file.0x850baef93510.0x850baeee6d50.ImageSectionObject.sechost.dll.img
ImageSectionObject      0x850baef936a0  kernel32.dll    file.0x850baef936a0.0x850baeef5220.ImageSectionObject.kernel32.dll.img
ImageSectionObject      0x850bae483e70  imm32.dll       file.0x850bae483e70.0x850baeeef6f0.ImageSectionObject.imm32.dll.img
ImageSectionObject      0x850bae482250  rpcrt4.dll      file.0x850bae482250.0x850baef27a90.ImageSectionObject.rpcrt4.dll.img
ImageSectionObject      0x850baecf0070  ntdll.dll       file.0x850baecf0070.0x850baed1b9a0.ImageSectionObject.ntdll.dll-2.img
```

- However, searching the SHA256 hash of `calc.exe image` does not return any result on **VirusTotal**.
- 🖥️Command: ```vol.py -f "C:\Users\Malware_Analyst\Desktop\memory.dmp" windows.netscan | findstr "calc.exe" ``` 
- Looking at the [NetScan](<./Output Files/netscan_output.txt>) we see that `calc.exe` (PID 3276) actually connects to an external IP address `192.168.170.132	65432`. This could mean that `calc.exe (PID 1132)` is used to execute the malicious code and establishes connection with a C2 server for data exfiltration or downloading of payloads.
```
0x850bb3b32b50	TCPv4	192.168.221.131	49753	192.168.170.132	65432	ESTABLISHED	1132	calc.exe	2025-01-27 09:07:48.000000 UTC
```

- 🖥️Command: ```vol.py -f "C:\Users\Malware_Analyst\Desktop\memory.dmp" windows.filescan | findstr "pyd"```
- Looking at the [filescan](<./Output Files/filescan_output.txt>) we find the following `.pyd` files in unusual locations, suggesting that the malware dropped these files to enable the execution of malicious Python code:
  1. `0x850bb3a56b40	\Users\User\AppData\Local\Temp\_MEI32762\_queue.pyd`
  2. `0x850bb4a96220	\Users\User\AppData\Local\Temp\_MEI32762\_socket.pyd`
  3. `0x850bb4aa9460	\Users\User\AppData\Local\Temp\_MEI32762\_bz2.pyd`
  4. `0x850bb4d247e0	\Users\User\AppData\Local\Temp\_MEI32762\_lzma.pyd`
  5. `0x850bb4d24970	\Users\User\AppData\Local\Temp\_MEI32762\_ssl.pyd`
  6. `0x850bb4d25aa0	\Users\User\AppData\Local\Temp\_MEI32762\select.pyd`
  7. `0x850bb4d25dc0	\Users\User\AppData\Local\Temp\_MEI32762\zstandard\backend_c.cp39-win_amd64.pyd`
  8. `0x850bb4d260e0	\Users\User\AppData\Local\Temp\_MEI32762\charset_normalizer\md__mypyc.cp39-win_amd64.pyd`
  9. `0x850bb4d26a40	\Users\User\AppData\Local\Temp\_MEI32762\_hashlib.pyd`
  10. `0x850bb4d26bd0	\Users\User\AppData\Local\Temp\_MEI32762\charset_normalizer\md.cp39-win_amd64.pyd`
  11. `0x850bb4d26d60	\Users\User\AppData\Local\Temp\_MEI32762\unicodedata.pyd`

- Knowing that `calc.exe` is connecting to an external IP address, and using python libraries to execute some malicious code, we get a `.dmp` of it using the command: ```vol.py -f "C:\Users\Malware_Analyst\Desktop\memory.dmp" windows.memmap --pid 1132 --dump```
- Since we see that the child processes of the malicious sample `scvhost.exe` spawns multiple `msedge.exe`, we search for any suspicious looking URLs.
- 🖥️Command: ```strings "C:\Windows\System32\volatility3\pid.1132.dmp" | findstr /R "\.com[\"'\s]"```
- 🚩From the [output](<./Output Files/calc_exe_mem_output.txt>) we find the flag: `faken3t_t1ll_u_mak3_1t.com`

## Exploring `notepad.exe` (PID 10200)
- 🖥️Command: ```vol.py -f "C:\Users\Malware_Analyst\Desktop\memory.dmp" windows.cmdline```
- Looking at the [cmdline output](<./Output Files/cmdline_output.txt>) we see that the file `flag.txt` was created
```
10200	notepad.exe	"C:\Windows\system32\NOTEPAD.EXE" C:\Users\User\Desktop\flag.txt
```

- 🖥️Command: ```vol.py -f "C:\Users\Malware_Analyst\Desktop\memory.dmp" windows.filescan | findstr "flag.txt"```
- Exploring the [filescan](<./Output Files/filescan_output.txt>) we see that the file `flag.txt.lnk` has the virtual address: `0x850bb4aa4190`
```
0x850bb4aa4190	\Users\User\AppData\Roaming\Microsoft\Windows\Recent\flag.txt.lnk
```

- 🖥️Command: ```vol.py -f "C:\Users\Malware_Analyst\Desktop\memory.dmp" windows.dumpfiles.DumpFiles --virtaddr 0x850bb4aa4190```
- Dumping the virtual address, we find the file `file.0x850bb4aa4190.0x850bb665e5d0.DataSectionObject.flag.txt.lnk.dat`
```
DataSectionObject       0x850bb4aa4190  flag.txt.lnk    file.0x850bb4aa4190.0x850bb665e5d0.DataSectionObject.flag.txt.lnk.dat
```
- However, renaming the extension reveals a bunch of scrambled unreadable text.
- 🖥️Command: ```vol.py -f "C:\Users\Malware_Analyst\Desktop\memory.dmp" windows.memdump --pid 10200 | findstr "flag{"```
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
- 🚩Taking the complete flag: `flag{d0nt_foRg3t_uN1c0de_$tR1nGs}`

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

## Exploring `svchost.exe` (PID 3644)
- Normally `svchost.exe` will have the following properties:
  1. Runs from `C:\Windows\System32\svchost.exe`
  2. Has a valid service name (-s ServiceName)
  3. Parent process is services.exe (PID 828)
  4. Uses known service groups (-k LocalService, -k netsvcs, etc.)
  5. Has a reasonable number of threads & handles
 
- Based on the above, `svchost.exe` **(PID 3644)** is suspicious because:
  1. No -k parameter, meaning it's not grouped with a valid Windows service.
  2. No -s parameter, meaning it's not hosting a known service.
  3. Parent process is SearchFilterHost.exe (PID 3452), which is not a typical parent for svchost.exe.
  4. Unusually low thread count (1) — normal svchost.exe processes have multiple threads.

- 🖥️Command: ```vol.py -f "C:\Users\Malware_Analyst\Desktop\memory.dmp" windows.cmdline | findstr "3644""```
- We see that `svchost.exe` is executing from `C:\Windows\svchost.exe` instead of the normal `C:\Windows\System32\svchost.exe`
- Implying that it is a fake `svchost.exe`
```
3644    svchost.exe     C:\Windows\svchost.exeinished
```

- 🖥️Command: ```vol.py -f "C:\Users\Malware_Analyst\Desktop\memory.dmp" windows.pslist --pid 3644 --dump ```
- 🖥️Command: ```strings "C:\Windows\System32\volatility3\pid.3644.dmp" | findstr /i "flag  fla9  fl@g  fl@9  fl4g  fl49  f1ag  f1a9  f1@g  f1@9  f14g  f149  phlag  phla9  phl@g  phl@9  phl4g  phl49  ph1ag  ph1a9  ph1@g  ph1@9  ph14g  ph149 "```
- 🚩Analysing strings in the `.dmp` file, we find the flag: flag{5vch0st_1s_l3g1t1m4t3}
