The Sherlock provides a zip file containing a log file:
- `Microsoft-Windows-Sysmon-Operational`
To inspect the log file, I fired up a Windows VM and used Event Viewer to get an overview and Get-WinEvent for easy querying.

# Task 1 
**How many Event logs are there with Event ID 11?**

```powershell
PS C:\Users\kali-win\Downloads> (Get-WinEvent -FilterHashtable @{ Path='C:\Users\kali-win\Downloads\unit42\Microsoft-Windows-Sysmon-Operational.evtx'; Id=11}).Count

56
```

# Task 2
**Whenever a process is created in memory, an event with Event ID 1 is recorded with details such as command line, hashes, process path, parent process path, etc. This information is very useful for an analyst because it allows us to see all programs executed on a system, which means we can spot any malicious processes being executed. What is the malicious process that infected the victim's system?**

After sysmon is installed on the VM, Get-WinEvent can read the event data.

```powershell
PS C:\Users\kali-win\Downloads> Get-WinEvent -FilterHashtable @{ Path='C:\Users\kali-win\Downloads\unit42\Microsoft-Windows-Sysmon-Operational.evtx'; Id=1} | ForEach-Object {$_.properties[4]}

Value
-----
C:\Windows\SysWOW64\msiexec.exe
C:\Windows\SysWOW64\msiexec.exe
C:\Windows\SysWOW64\msiexec.exe
C:\Windows\System32\msiexec.exe
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
C:\Program Files\Mozilla Firefox\pingsender.exe
```

The process `C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe` looks suspicious.

How did I know the correct index of th properties array? In the query, find the index by looking at the properties array (the image path is 5th in the list).
```powershell
PS C:\Users\kali-win\Downloads> (Get-WinEvent -FilterHashtable @{ Path='C:\Users\kali-win\Downloads\unit42\Microsoft-Windows-Sysmon-Operational.evtx'; Id=1} -MaxEvents 1).Properties

Value
-----
technique_id=T1218,technique_name=Signed Binary Proxy Execution
2024-02-14 03:41:58.178
817bddf3-3686-65cc-3102-000000001900
10280
C:\Windows\SysWOW64\msiexec.exe
5.0.19041.3636 (WinBuild.160101.0800)
Windows® installer
Windows Installer - Unicode
Microsoft Corporation
msiexec.exe
C:\Windows\syswow64\MsiExec.exe -Embedding 5250A3DB12224F77D2A18B4EB99AC5EB
C:\Windows\SysWOW64\
DESKTOP-887GK2L\CyberJunkie
817bddf3-311e-65cc-a7ae-1b0000000000
1814183
1
Medium
SHA1=9AB9B12901E1EA2DF943B45AD20D8732618608CD,MD5=898277AC5894C4E1412A49040053B0D3,SHA256=445A2E800DC68DF89ABF713F3B4B632D40AE6310EF3660B42D974BB582426BC5,IMPHASH=E4E40938E4BF6C664248...
817bddf3-3685-65cc-2e02-000000001900
10220
C:\Windows\System32\msiexec.exe
C:\Windows\system32\msiexec.exe /V
NT AUTHORITY\SYSTEM
```

# Task 3
**Which Cloud drive was used to distribute the malware?**

DNS queries are event Id 22.

```powershell
PS C:\Users\kali-win\Downloads> Get-WinEvent -FilterHashtable @{ Path='C:\Users\kali-win\Downloads\unit42\Microsoft-Windows-Sysmon-Operational.evtx'; Id=22}  | Format-List


TimeCreated  : 2/14/2024 4:41:58 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 22
Message      : Dns query:
               RuleName: -
               UtcTime: 2024-02-14 03:41:56.955
               ProcessGuid: {817bddf3-3684-65cc-2d02-000000001900}
               ProcessId: 10672
               QueryName: www.example.com
               QueryStatus: 0
               QueryResults: ::ffff:93.184.216.34;199.43.135.53;2001:500:8f::53;199.43.133.53;2001:500:8d::53;
               Image: C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
               User: DESKTOP-887GK2L\CyberJunkie

TimeCreated  : 2/14/2024 4:41:45 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 22
Message      : Dns query:
               RuleName: -
               UtcTime: 2024-02-14 03:41:43.924
               ProcessGuid: {817bddf3-3514-65cc-0802-000000001900}
               ProcessId: 4292
               QueryName: d.dropbox.com
               QueryStatus: 0
               QueryResults: type:  5 d.v.dropbox.com;type:  5 d-edge.v.dropbox.com;162.125.8.20;205.251.192.57;2600:9000:5300:3900::1;
               Image: C:\Program Files\Mozilla Firefox\firefox.exe
               User: DESKTOP-887GK2L\CyberJunkie

TimeCreated  : 2/14/2024 4:41:26 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 22
Message      : Dns query:
               RuleName: -
               UtcTime: 2024-02-14 03:41:25.269
               ProcessGuid: {817bddf3-3514-65cc-0802-000000001900}
               ProcessId: 4292
               QueryName: uc2f030016253ec53f4953980a4e.dl.dropboxusercontent.com
               QueryStatus: 0
               QueryResults: type:  5 edge-block-www-env.dropbox-dns.com;::ffff:162.125.81.15;198.51.44.6;2620:4d:4000:6259:7:6:0:1;198.51.45.6;2a00:edc0:6259:7:6::2;198.51.44.70;2620:4d
               :4000:6259:7:6:0:3;198.51.45.70;2a00:edc0:6259:7:6::4;
               Image: C:\Program Files\Mozilla Firefox\firefox.exe
               User: DESKTOP-887GK2L\CyberJunkie
```

The "cloud drive" is `dropbox`.

# Task 4

**For many of the files it wrote to disk, the initial malicious file used a defense evasion technique called Time Stomping, where the file creation date is changed to make it appear older and blend in with other files. What was the timestamp changed to for the PDF file?**

File creation time changed is event Id 2. Filter for `pdf` in the `TargetFilename`.

```powershell
PS C:\Users\kali-win\Downloads> Get-WinEvent -FilterHashtable @{ Path='C:\Users\kali-win\Downloads\unit42\Microsoft-Windows-Sysmon-Operational.evtx'; Id=2} | Where-Object {$_.Properties[5].Value -like "*.pdf*" } | Format-List


TimeCreated  : 2/14/2024 4:41:58 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 2
Message      : File creation time changed:
               RuleName: technique_id=T1070.006,technique_name=Timestomp
               UtcTime: 2024-02-14 03:41:58.404
               ProcessGuid: {817bddf3-3684-65cc-2d02-000000001900}
               ProcessId: 10672
               Image: C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
               TargetFilename: C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\TempFolder\~.pdf
               CreationUtcTime: 2024-01-14 08:10:06.029
               PreviousCreationUtcTime: 2024-02-14 03:41:58.404
               User: DESKTOP-887GK2L\CyberJunkie
```

The timestamp is `2024-01-14 08:10:06`.
# Task 5
**The malicious file dropped a few files on disk. Where was "once.cmd" created on disk? Please answer with the full path along with the filename.**

File creation is event Id 11. Filter by "once.cmd".
```powershell
PS C:\Users\kali-win\Downloads> Get-WinEvent -FilterHashtable @{ Path='C:\Users\kali-win\Downloads\unit42\Microsoft-Windows-Sysmon-Operational.evtx'; Id=11} | Where-Object {$_.Properties[5].Value -like "*once.cmd*" } | Format-List


TimeCreated  : 2/14/2024 4:41:58 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 11
Message      : File created:
               RuleName: -
               UtcTime: 2024-02-14 03:41:58.577
               ProcessGuid: {817bddf3-3685-65cc-2e02-000000001900}
               ProcessId: 10220
               Image: C:\Windows\system32\msiexec.exe
               TargetFilename: C:\Games\once.cmd
               CreationUtcTime: 2024-02-14 03:41:58.577
               User: NT AUTHORITY\SYSTEM

TimeCreated  : 2/14/2024 4:41:58 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 11
Message      : File created:
               RuleName: -
               UtcTime: 2024-02-14 03:41:58.404
               ProcessGuid: {817bddf3-3684-65cc-2d02-000000001900}
               ProcessId: 10672
               Image: C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
               TargetFilename: C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd
               CreationUtcTime: 2024-02-14 03:41:58.404
               User: DESKTOP-887GK2L\CyberJunkie
```

The full path is `C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd`.

# Task 6

**The malicious file attempted to reach a dummy domain, most likely to check the internet connection status. What domain name did it try to connect to?**

From Task 3: `QueryName: www.example.com`.

# Task 7
**Which IP address did the malicious process try to reach out to?**

Network connections are event Id 3. 
```powershell
PS C:\Users\kali-win\Downloads> Get-WinEvent -FilterHashtable @{ Path='C:\Users\kali-win\Downloads\unit42\Microsoft-Windows-Sysmon-Operational.evtx'; Id=3} | Format-List


TimeCreated  : 2/14/2024 4:41:58 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: technique_id=T1036,technique_name=Masquerading
               UtcTime: 2024-02-14 03:41:57.159
               ProcessGuid: {817bddf3-3684-65cc-2d02-000000001900}
               ProcessId: 10672
               Image: C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
               User: DESKTOP-887GK2L\CyberJunkie
               Protocol: tcp
               Initiated: true
               SourceIsIpv6: false
               SourceIp: 172.17.79.132
               SourceHostname: -
               SourcePort: 61177
               SourcePortName: -
               DestinationIsIpv6: false
               DestinationIp: 93.184.216.34
               DestinationHostname: -
               DestinationPort: 80
               DestinationPortName: 
```

The destination IP is `93.184.216.34`.

# Task 8

**The malicious process terminated itself after infecting the PC with a backdoored variant of UltraVNC. When did the process terminate itself?**

Process termination is event Id 5.

```powershell
PS C:\Users\kali-win\Downloads> Get-WinEvent -FilterHashtable @{ Path='C:\Users\kali-win\Downloads\unit42\Microsoft-Windows-Sysmon-Operational.evtx'; Id=5} | Format-List


TimeCreated  : 2/14/2024 4:41:58 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 5
Message      : Process terminated:
               RuleName: -
               UtcTime: 2024-02-14 03:41:58.795
               ProcessGuid: {817bddf3-3684-65cc-2d02-000000001900}
               ProcessId: 10672
               Image: C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
               User: DESKTOP-887GK2L\CyberJunkie
```

The process terminated on `2024-02-14 03:41:58`.