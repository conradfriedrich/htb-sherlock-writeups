The Sherlock provides a zip file containing 5 log files:
- `Powershell-Operational.evtx`
- `Security.evtx`
- `System.evtx`
- `Windows Defender-Operational.evtx`
- `Windows Firewall-Firewall.evtx`

To inspect the log files, I fired up a Windows VM and used Event Viewer and Get-WinEvent.
# Task 1
**When did the cyberjunkie user first successfully log into his computer? (UTC)**

Logons are ID 4624 in the Security log. To filter with Get-WinEvent by Account Name, first find out the array position in the properties value. Check the content of message for the value (here Account Name: DWM-1), and cross-reference with properties (DWM-1 is 6th in line, so value 5).

```powershell
PS C:\Users\kali-win> $e = Get-WinEvent -FilterHashtable @{Path='C:\Users\kali-win\Downloads\logjammer\Event-Logs\Security.evtx'; Id=4624} -MaxEvents 1

PS C:\Users\kali-win> $e.Message
An account was successfully logged on.

Subject:
        Security ID:            S-1-5-18
        Account Name:           DESKTOP-887GK2L$
        Account Domain:         WORKGROUP
        Logon ID:               0x3E7

Logon Information:
        Logon Type:             2
        Restricted Admin Mode:  -
        Virtual Account:                Yes
        Elevated Token:         No

Impersonation Level:            Impersonation

New Logon:
        Security ID:            S-1-5-90-0-1
        Account Name:           DWM-1
        Account Domain:         Window Manager
        Logon ID:               0x553B36
        Linked Logon ID:                0x553B1E
        Network Account Name:   -
        Network Account Domain: -
        Logon GUID:             {00000000-0000-0000-0000-000000000000}

Process Information:
        Process ID:             0x2d0
        Process Name:           C:\Windows\System32\winlogon.exe

Network Information:
        Workstation Name:       -
        Source Network Address: -
        Source Port:            -

Detailed Authentication Information:
        Logon Process:          Advapi
        Authentication Package: Negotiate
        Transited Services:     -
        Package Name (NTLM only):       -
        Key Length:             0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
        - Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
        - Transited services indicate which intermediate services have participated in this logon request.
        - Package name indicates which sub-protocol was used among the NTLM protocols.
        - Key length indicates the length of the generated session key. This will be 0 if no session key was requested.
PS C:\Users\kali-win> $e.Properties

Value
-----
S-1-5-18
DESKTOP-887GK2L$
WORKGROUP
999
S-1-5-90-0-1
DWM-1
Window Manager
5585718
2
Advapi
Negotiate
-
00000000-0000-0000-0000-000000000000
-
-
0
720
C:\Windows\System32\winlogon.exe
-
-
%%1833
-
-
-
%%1842
5585694
%%1843
```

Then query for cyberjunkie:

```powershell
PS C:\Users\kali-win> Get-WinEvent -FilterHashtable @{Path='C:\Users\kali-win\Downloads\logjammer\Event-Logs\Security.evtx'; Id=4624} -Oldest -MaxEvents 100 | Where-Object {$_.Properties[5].Value -like "*cyberjunkie*"}


   ProviderName: Microsoft-Windows-Security-Auditing

TimeCreated                      Id LevelDisplayName Message
-----------                      -- ---------------- -------
3/27/2023 4:37:09 PM           4624 Information      An account was successfully logged on....
3/27/2023 4:37:09 PM           4624 Information      An account was successfully logged on....
3/27/2023 4:38:32 PM           4624 Information      An account was successfully logged on....
3/27/2023 4:38:32 PM           4624 Information      An account was successfully logged on....
```

So it seems that the first Logon was on `3/27/2023 4:37:09 PM`. But my VM is on UTC+1 currently, so it seems like the correct time seems should be  `3:37:09 PM`. However, that's not right: Powershell uses my timezone at the time of the event, at which it was UTC+2 (because of daylight saving). So the correct time is `2:37:09 PM`.

Let's double check that:
```powershell
PS C:\Users\kali-win> $a = Get-WinEvent -FilterHashtable @{Path='C:\Users\kali-win\Downloads\logjammer\Event-Logs\Security.evtx'; Id=4624} -Oldest -MaxEvents 100 | Where-Object {$_.Properties[5].Value -like "*cyberjunkie*"} | Select-Object -First 1

PS C:\Users\kali-win> $a.TimeCreated.ToUniversalTime()

Monday, March 27, 2023 2:37:09 PM
```

# Task 2
**The user tampered with firewall settings on the system. Analyze the firewall event logs to find out the Name of the firewall rule added?**

Firewall rule additions are Event ID 2004. 
```powershell
PS C:\Users\kali-win> (Get-WinEvent -FilterHashtable @{ Path='C:\Users\kali-win\Downloads\logjammer\Event-Logs\Windows Firewall-Firewall.evtx'; Id=2004}).Count
490
```

That's a lot. Let's look at just the Rule Names (I determined the index for the properties Array just like above).
```powershell
PS C:\Users\kali-win> Get-WinEvent -FilterHashtable @{ Path='C:\Users\kali-win\Downloads\logjammer\Event-Logs\Windows Firewall-Firewall.evtx'; Id=2004} | ForEach-Object { $_.Properties[1].Value }
Metasploit C2 Bypass
Microsoft Edge
Microsoft Edge
Microsoft Edge (mDNS-In)
Microsoft Edge (mDNS-In)
Microsoft Edge (mDNS-In)
Microsoft Edge (mDNS-In)
WinDefend Outbound for TCP
Outbound service restriction rule for WinDefend
Inbound service restriction rule for WinDefend
Microsoft Edge
Microsoft Edge
Python 3.10
Python 3.10
Firefox (C:\Program Files\Mozilla Firefox)
Firefox (C:\Program Files\Mozilla Firefox)
Microsoft Edge (mDNS-In)
Microsoft Edge (mDNS-In)
Microsoft Edge
Microsoft Edge
...
```

`Metasploit C2 Bypass` Looks suspicious. 

# Task 3
**Whats the direction of the firewall rule?**

The info is in the object's message:
```powershell
PS C:\Users\kali-win> Get-WinEvent -FilterHashtable @{ Path='C:\Users\kali-win\Downloads\logjammer\Event-Logs\Windows Firewall-Firewall.evtx'; Id=2004} -MaxEvents 20 | Select-Object -First 1 | Format-List

TimeCreated  : 3/27/2023 4:44:43 PM
ProviderName : Microsoft-Windows-Windows Firewall With Advanced Security
Id           : 2004
Message      : A rule has been added to the Windows Defender Firewall exception list.

               Added Rule:
                Rule ID:        {11309293-FB68-4969-93F9-7F75A9032570}
                Rule Name:      Metasploit C2 Bypass
                Origin: Local
                Active: Yes
                Direction:      Outbound
                Profiles:       Private,Domain, Public
                Action: Allow
                Application Path:
                Service Name:
                Protocol:       TCP
                Security Options:       None
                Edge Traversal: None
                Modifying User: S-1-5-21-3393683511-3463148672-371912004-1001
                Modifying App:  C:\Windows\System32\mmc.exe
```

Direction is `Outbound`.
# Task 4
**The user changed audit policy of the computer. Whats the Subcategory of this changed policy?**

Audit policy changes are Id 4719 in the security log. 
```powershell
PS C:\Users\kali-win> Get-WinEvent -FilterHashtable @{ Path='C:\Users\kali-win\Downloads\logjammer\Event-Logs\Security.evtx'; Id=4719} | Format-List


TimeCreated  : 3/27/2023 4:50:03 PM
ProviderName : Microsoft-Windows-Security-Auditing
Id           : 4719
Message      : System audit policy was changed.

               Subject:
                Security ID:            S-1-5-18
                Account Name:           DESKTOP-887GK2L$
                Account Domain:         WORKGROUP
                Logon ID:               0x3E7

               Audit Policy Change:
                Category:               Object Access
                Subcategory:            Other Object Access Events
                Subcategory GUID:       {0cce9227-69ae-11d9-bed3-505054503030}
                Changes:                Success Added
```

The subcategory is `Other Object Access Events`.
# Task 5
**The user "cyberjunkie" created a scheduled task. Whats the name of this task?**

Creating Scheduled task is Id ==**4698**== in the security log.
```powershell
PS C:\Users\kali-win> Get-WinEvent -FilterHashtable @{ Path='C:\Users\kali-win\Downloads\logjammer\Event-Logs\Security.evtx'; Id=4698} | Format-List


TimeCreated  : 3/27/2023 4:51:21 PM
ProviderName : Microsoft-Windows-Security-Auditing
Id           : 4698
Message      : A scheduled task was created.

               Subject:
                Security ID:            S-1-5-21-3393683511-3463148672-371912004-1001
                Account Name:           CyberJunkie
                Account Domain:         DESKTOP-887GK2L
                Logon ID:               0x25F28

               Task Information:
                Task Name:              \HTB-AUTOMATION
                Task Content:           <?xml version="1.0" encoding="UTF-16"?>
               <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
                 <RegistrationInfo>
                   <Date>2023-03-27T07:51:21.4599985</Date>
                   <Author>DESKTOP-887GK2L\CyberJunkie</Author>
                   <Description>practice</Description>
                   <URI>\HTB-AUTOMATION</URI>
                 </RegistrationInfo>
                 <Triggers>
                   <CalendarTrigger>
                     <StartBoundary>2023-03-27T09:00:00</StartBoundary>
                     <Enabled>true</Enabled>
                     <ScheduleByDay>
                       <DaysInterval>1</DaysInterval>
                     </ScheduleByDay>
                   </CalendarTrigger>
                 </Triggers>
                 <Principals>
                   <Principal id="Author">
                     <RunLevel>LeastPrivilege</RunLevel>
                     <UserId>DESKTOP-887GK2L\CyberJunkie</UserId>
                     <LogonType>InteractiveToken</LogonType>
                   </Principal>
                 </Principals>
                 <Settings>
                   <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                   <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
                   <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
                   <AllowHardTerminate>true</AllowHardTerminate>
                   <StartWhenAvailable>false</StartWhenAvailable>
                   <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
                   <IdleSettings>
                     <Duration>PT10M</Duration>
                     <WaitTimeout>PT1H</WaitTimeo==**4698**==ut>
                     <StopOnIdleEnd>true</StopOnIdleEnd>
                     <RestartOnIdle>false</RestartOnIdle>
                   </IdleSettings>
                   <AllowStartOnDemand>true</AllowStartOnDemand>
                   <Enabled>true</Enabled>
                   <Hidden>false</Hidden>
                   <RunOnlyIfIdle>false</RunOnlyIfIdle>
                   <WakeToRun>false</WakeToRun>
                   <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
                   <Priority>7</Priority>
                 </Settings>
                 <Actions Context="Author">
                   <Exec>
                     <Command>C:\Users\CyberJunkie\Desktop\Automation-HTB.ps1</Command>
                     <Arguments>-A cyberjunkie@hackthebox.eu</Arguments>
                   </Exec>
                 </Actions>
               </Task>

               Other Information:
                ProcessCreationTime:            4222124650660162
                ClientProcessId:                        9320
                ParentProcessId:                        6112
                FQDN:           0

```

The task name is `HTB-AUTOMATION`.
# Task 6
**Whats the full path of the file which was scheduled for the task?**

From above:
The path is `C:\Users\CyberJunkie\Desktop\Automation-HTB.ps1`.
# Task 7 
**What are the arguments of the command?**

Again, from above:
The arguments are `-A cyberjunkie@hackthebox.eu`.
# Task 8
**The antivirus running on the system identified a threat and performed actions on it. Which tool was identified as malware by antivirus?**

Malware detection is event Id 1116. Get all unique names of the identified malware. I found the properties value again by the method described above.

```powershell
PS C:\Users\kali-win> Get-WinEvent -FilterHashtable @{ Path='C:\Users\kali-win\Downloads\logjammer\Event-Logs\Windows Defender-Operational.evtx'; Id=1116} | ForEach-Object { $_.Properties[7].Value } | Select-Object -Unique

HackTool:MSIL/SharpHound!MSR
HackTool:PowerShell/SharpHound.B
Trojan:Win64/Meterpreter.B
```

Performing actions on detected malware is event Id 1117. Cross-check the names.

```powershell
PS C:\Users\kali-win> Get-WinEvent -FilterHashtable @{ Path='C:\Users\kali-win\Downloads\logjammer\Event-Logs\Windows Defender-Operational.evtx'; Id=1117} | ForEach-Object { $_.Properties[7].Value } | Select-Object -Unique

HackTool:MSIL/SharpHound!MSR
Trojan:Win64/Meterpreter.B
```

So both sharphound and meterpreter seem like valid answers. HTB accepts sharphound.

# Task 9
**Whats the full path of the malware which raised the alert?**

Look at the 1116 Event:

```powershell
PS C:\Users\kali-win> Get-WinEvent -FilterHashtable @{ Path='C:\Users\kali-win\Downloads\logjammer\Event-Logs\Windows Defender-Operational.evtx'; Id=1116} | Where-Object {$_.Properties[7].Value -like 'HackTool:MSIL/SharpHound!MSR'} | Format-List

TimeCreated  : 3/27/2023 4:42:34 PM
ProviderName : Microsoft-Windows-Windows Defender
Id           : 1116
Message      : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
                For more information please see the following:
               https://go.microsoft.com/fwlink/?linkid=37020&name=HackTool:MSIL/SharpHound!MSR&threatid=2147814944&enterprise=0
                        Name: HackTool:MSIL/SharpHound!MSR
                        ID: 2147814944
                        Severity: High
                        Category: Tool
                        Path: containerfile:_C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip; file:_C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip->SharpHound.exe; webfile:_C:\Users\
               CyberJunkie\Downloads\SharpHound-v1.1.0.zip|https://objects.githubusercontent.com/github-production-release-asset-2e65be/385323486/70d776cc-8f83-44d5-b226-2dccc4f7c1e3?X-A
               mz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A4.18.2302.7F202303274.18.2302.7Fus-east-14.18.2302.7Fs34.18.2302.7Faws4_request&X-Amz-Date=20230327T1442
               28Z&X-Amz-Expires=300&X-Amz-Signature=f969ef5ca3eec150dc1e23623434adc1e4a444ba026423c32edf5e85d881a771&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=385323486&respo
               nse-content-disposition=attachment{0EBC4BEA-5532-4EFB-8A34-64F91CC8702E}BDESKTOP-887GK2L\CyberJunkiefilename{0EBC4BEA-5532-4EFB-8A34-64F91CC8702E}DSharpHound-v1.1.0.zip&re
               sponse-content-type=application4.18.2302.7Foctet-stream|pid:3532,ProcessStart:133244017530289775
                        Detection Origin: Internet
                        Detection Type: Concrete
                        Detection Source: Downloads and attachments
                        User: DESKTOP-887GK2L\CyberJunkie
                        Process Name: Unknown
                        Security intelligence Version: AV: 1.385.1261.0, AS: 1.385.1261.0, NIS: 1.385.1261.0
                        Engine Version: AM: 1.1.20100.6, NIS: 1.1.20100.6
```

The full path is `C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip`.
# Task 10

Look at the 1117 Event: 
```powershell
Get-WinEvent -FilterHashtable @{ Path='C:\Users\kali-win\Downloads\logjammer\Event-Logs\Windows Defender-Operational.evtx'; Id=1117} | Where-Object {$_.Properties[7].Value -like 'HackTool:MSIL/SharpHound!MSR'} | Format-List

TimeCreated  : 3/27/2023 4:42:48 PM
ProviderName : Microsoft-Windows-Windows Defender
Id           : 1117
Message      : Microsoft Defender Antivirus has detected malware or potentially unwanted software using Defender security intelligence and applied the remediation action defined in the
               security settings.
                For more information please see the following:
               https://go.microsoft.com/fwlink/?linkid=37020&name=HackTool:MSIL/SharpHound!MSR&threatid=2147814944&enterprise=0
                        Name: HackTool:MSIL/SharpHound!MSR
                        ID: 2147814944
                        Severity: High
                        Category: Tool
                        Path: containerfile:_C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip; file:_C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip->SharpHound.exe; webfile:_C:\Users\
               CyberJunkie\Downloads\SharpHound-v1.1.0.zip|https://objects.githubusercontent.com/github-production-release-asset-2e65be/385323486/70d776cc-8f83-44d5-b226-2dccc4f7c1e3?X-A
               mz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A4.18.2302.7F202303274.18.2302.7Fus-east-14.18.2302.7Fs34.18.2302.7Faws4_request&X-Amz-Date=20230327T1442
               28Z&X-Amz-Expires=300&X-Amz-Signature=f969ef5ca3eec150dc1e23623434adc1e4a444ba026423c32edf5e85d881a771&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=385323486&respo
               nse-content-disposition=attachment{0EBC4BEA-5532-4EFB-8A34-64F91CC8702E}BDESKTOP-887GK2L\CyberJunkiefilename{0EBC4BEA-5532-4EFB-8A34-64F91CC8702E}DSharpHound-v1.1.0.zip&re
               sponse-content-type=application4.18.2302.7Foctet-stream|pid:3532,ProcessStart:133244017530289775
                        Detection Origin: Internet
                        Detection Type: Concrete
                        Detection Source: Downloads and attachments
                        User: NT AUTHORITY\SYSTEM
                        Process Name: Unknown
                        Action: Quarantine
                        Action Status:  No additional actions required
                        Error Code: 0x80508023
                        Error description: The program could not find the malware and other potentially unwanted software on this device.
                        Security intelligence Version: AV: 1.385.1261.0, AS: 1.385.1261.0, NIS: 1.385.1261.0
                        Engine Version: AM: 1.1.20100.6, NIS: 1.1.20100.6

TimeCreated  : 3/27/2023 4:42:48 PM
ProviderName : Microsoft-Windows-Windows Defender
Id           : 1117
Message      : Microsoft Defender Antivirus has detected malware or potentially unwanted software using Defender security intelligence and applied the remediation action defined in the
               security settings.
                For more information please see the following:
               https://go.microsoft.com/fwlink/?linkid=37020&name=HackTool:MSIL/SharpHound!MSR&threatid=2147814944&enterprise=0
                        Name: HackTool:MSIL/SharpHound!MSR
                        ID: 2147814944
                        Severity: High
                        Category: Tool
                        Path: containerfile:_C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip; file:_C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip->SharpHound.exe; webfile:_C:\Users\
               CyberJunkie\Downloads\SharpHound-v1.1.0.zip|https://objects.githubusercontent.com/github-production-release-asset-2e65be/385323486/70d776cc-8f83-44d5-b226-2dccc4f7c1e3?X-A
               mz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A4.18.2302.7F202303274.18.2302.7Fus-east-14.18.2302.7Fs34.18.2302.7Faws4_request&X-Amz-Date=20230327T1442
               28Z&X-Amz-Expires=300&X-Amz-Signature=f969ef5ca3eec150dc1e23623434adc1e4a444ba026423c32edf5e85d881a771&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=385323486&respo
               nse-content-disposition=attachment{0EBC4BEA-5532-4EFB-8A34-64F91CC8702E}BDESKTOP-887GK2L\CyberJunkiefilename{0EBC4BEA-5532-4EFB-8A34-64F91CC8702E}DSharpHound-v1.1.0.zip&re
               sponse-content-type=application4.18.2302.7Foctet-stream|pid:3532,ProcessStart:133244017530289775
                        Detection Origin: Internet
                        Detection Type: Concrete
                        Detection Source: Downloads and attachments
                        User: NT AUTHORITY\SYSTEM
                        Process Name: Unknown
                        Action: Quarantine
                        Action Status:  No additional actions required
                        Error Code: 0x80508023
                        Error description: The program could not find the malware and other potentially unwanted software on this device.
                        Security intelligence Version: AV: 1.385.1261.0, AS: 1.385.1261.0, NIS: 1.385.1261.0
                        Engine Version: AM: 1.1.20100.6, NIS: 1.1.20100.6
```

The action is `Quarantine`.

# Task 11
**The user used Powershell to execute commands. What command was executed by the user?**

Remote command execution is event Id 4104. Looking at the first couple: 

```powershell
PS C:\Users\kali-win> Get-WinEvent -FilterHashtable @{ Path='C:\Users\kali-win\Downloads\logjammer\Event-Logs\Powershell-Operational.evtx'; Id=4104} -MaxEvents 3 | Format-List


TimeCreated  : 3/27/2023 4:58:33 PM
ProviderName : Microsoft-Windows-PowerShell
Id           : 4104
Message      : Creating Scriptblock text (1 of 1):
               prompt

               ScriptBlock ID: 040e087a-07e5-40ca-a7c9-f3e760d6f6c6
               Path:

TimeCreated  : 3/27/2023 4:58:33 PM
ProviderName : Microsoft-Windows-PowerShell
Id           : 4104
Message      : Creating Scriptblock text (1 of 1):
               Get-FileHash -Algorithm md5 .\Desktop\Automation-HTB.ps1

               ScriptBlock ID: b4fcf72f-abdc-4a84-923f-8e06a758000b
               Path:

TimeCreated  : 3/27/2023 4:58:07 PM
ProviderName : Microsoft-Windows-PowerShell
Id           : 4104
Message      : Creating Scriptblock text (1 of 1):
               prompt

               ScriptBlock ID: daafd82b-8566-444f-b5e8-7d29072f96dc
               Path:

```

The command is `Get-FileHash -Algorithm md5 .\Desktop\Automation-HTB.ps1.
# Task 12
**We suspect the user deleted some event logs. Which Event log file was cleared?**

There are several event Ids related to log clearing. Check 1102 and 104.
```powershell
PS C:\Users\kali-win> Get-WinEvent -FilterHashtable @{ Path='C:\Users\kali-win\Downloads\logjammer\Event-Logs\Security.evtx'; Id=1102} | Format-List


TimeCreated  : 3/27/2023 4:36:45 PM
ProviderName : Microsoft-Windows-Eventlog
Id           : 1102
Message      : The audit log was cleared.
               Subject:
                Security ID:    S-1-5-21-3393683511-3463148672-371912004-1001
                Account Name:   CyberJunkie
                Domain Name:    DESKTOP-887GK2L
                Logon ID:       0x25235
```

```powershell
PS C:\Users\kali-win> Get-WinEvent -FilterHashtable @{ Path='C:\Users\kali-win\Downloads\logjammer\Event-Logs\System.evtx'; Id=104} | ForEach-Object { $_.message } | Select-Object -Unique 

The Microsoft-Windows-Windows Firewall With Advanced Security/Firewall log file was cleared.
The Microsoft-Windows-Sysmon/Operational log file was cleared.
```

The event log is `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`.