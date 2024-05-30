## Introduction to Windows : 

![[Windows Version.png]]

To retrieve the Build number and System Version :
```powershell-session
Get-WmiObject -Class win32_OperatingSystem | select Version,BuildNumber
```

To connect to a machine :
```shell-session
xfreerdp /v:<targetIp> /u:htb-student /p:Password
```

## Operating System Structure : 

![[Dir1.png]]
![[Dir2.png]]

This command lists the files present at the root.
```cmd-session
dir c:\ /a
```

We can also use (/f for more details) :
```cmd-session
tree "c:" /f
```
## File System : 

Fat32: 
(+): 
- Compatible with computers, cameras, consoles, smartphones.
- Works with all OS (Windows, MacOS, Linux).
(-): 
- Files are no more than 4GB.
- No data protection or compression mechanism.
- Must use file encryption tools.

NTFS (default with Windows): 
(+): 
- In the event of failure or power loss, the data can be recovered.
- Provides security with permissions on files and folders.
- Support for very large partitions.
- Modifications, file additions are in logs.
(-): 
- Most phones do not support NTFS natively.
- Older devices do not also support NTFS.

Some permissions with NTFS:
![[Permission NTFS.png]]

This command allows you to list the files and associated rights.
```cmd-session
icacls c:\windows
```

![[Type Droits.png]]
![[Droits.png]]

This command gives full control of the directory to Joe.
```cmd-session
icacls c:\users /grant joe:f
```

## NTFS vs. Share Permissions : 

![[File Sharing Using SMB.png]]![[Share perm.png]]![[NTFS Basic.png]]![[NTFS  Special 1.png]]![[NTFS Special 2.png]]

Files created in a folder inherit the permissions of the parent folder by default.

Command to connect to file share using smbclient :
```shell-session
smbclient -L IPaddressOfTarget -U htb-student
```

Windows Defender Firewall Profiles:
- `Public`
- `Private`
- `Domain`

Mount the share :
```shell-session
sudo mount -t cifs -o username=htb-student,password=Academy_WinFun! //ipaddoftarget/"Company Data" /home/user/Desktop/
```

View shared folders :
```cmd-session
net share
```

Event Viewer: allows you to view logs from Windows.

## Windows Services & Processes : 

services.msc: Lists the services.

Command to list running services (fl for details) :
```powershell-session
Get-Service | ? {$_.Status -eq "Running"} | fl
```

Services that cannot be stopped or restarted :
![[Services non stop.png]]

## Service Permissions : 

Command to configure/manage the services :
```cmd-session
sc qc wuauserv
```

Command to change the Windows Update service :
```cmd-session
sc config wuauserv binPath=C:\Winbows\Perfectlylegitprogram.exe
```

## Windows Sessions : 

![[Account.png]]

## Interacting with the Windows Operating System : 

![[HTB Academy/Tier 0/Fundamental/WINDOWS FUNDAMENTALS/Images/Policy.png]]

## Windows Management Instrumentation (WMI) : 

WMI is a Windows internal management system that supports monitoring and control of system resources through a set of interfaces.

![[VMI.png]]

Some of the uses for WMI are :
- Status information for local/remote systems.
- Configuring security settings on remote machines/applications.
- Setting and changing user and group permissions.
- Setting/modifying system properties.
- Code execution.
- Scheduling processes.
- Setting up logging.

Command help:
```cmd-session
wmic /?
```

Displays system information :
```cmd-session
wmic os list brief
```

## Microsoft Management Console (MMC) : 

_**Microsoft Management Console**_ (abbr. **MMC**) is an embedded virtual [console](https://fr.wikipedia.org/wiki/Console_syst%C3%A8me “System Console”) manager in [Microsoft Windows](https://fr.wikipedia.org/wiki/Microsoft_Windows "Microsoft Windows"), which serves as a container for [graphical interfaces](https://fr.wikipedia.org/wiki/Graphical_Interface " Graphical interface") from [configuration](https://fr.wikipedia.org/wiki/Configuration_(computing) "Configuration (computing)"). This [utility software](https://fr.wikipedia.org/wiki/Logiciel_utility “Utility software”) is the basis of many configuration tools incorporated into Windows, and allows you to create [system administration]( https://fr.wikipedia.org/wiki/Administration_syst%C3%A8me "System Administration") by grouping a batch of [extensions](https://fr.wikipedia.org/wiki/Plugin "Plugin") in the same window[1](https://fr.wikipedia.org/wiki/Microsoft_Management_Console#cite_note-1).

## Windows Subsystem for Linux (WSL) : 

Command to enable WSL :
```powershell-session
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
```

## Desktop Experience vs. Server Core :

![[Server.png]]

## Windows Security

![[SID.png]]![[uacarchitecture1.png]]
![[REG1.png]]![[REG2.png]]