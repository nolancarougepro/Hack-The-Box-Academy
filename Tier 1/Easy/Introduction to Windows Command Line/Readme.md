## Introduction : 

The built-in command shell CMD.exe and PowerShell are two implementations included in all Windows hosts. These tools provide direct access to the operating system, automate routine tasks, and provide the user with granular control of any aspect of the computer and installed applications. This module will give us the knowledge, skills, and abilities to effectively administer Windows hosts via the command line.

There are some key differences between Windows Command Prompt and PowerShell. One key difference is that you can run Command Prompt commands from a PowerShell console, but to run PowerShell commands from a Command Prompt, you would have to preface the command with `powershell` (i.e., `powershell get-alias`). The following table outlines some other key differences.

![[cmd_vs_pshell.png]]
## Command Prompt Basics : 

The Command Prompt, also known as [cmd.exe](https://https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd) or CMD, is the default command line interpreter for the Windows operating system. While often overshadowed by its sleek counterpart [PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.2), knowledge of cmd.exe and its commands continue to pay dividends even in modern times.

`How do we access the Command Prompt?`

Local access is synonymous with having direct physical access ( or virtual in the instance of a Virtual Machine (VM)) to the machine itself. From the desktop, we can open up the command prompt by :

- Using the Windows key + `r` to bring up the run prompt, and then typing in `cmd`. OR
- Accessing the executable from the drive path `C:\Windows\System32\cmd.exe`.

On the other hand, remote access is the equivalent of accessing the machine using virtual peripherals over the network. We can do this through the use of `telnet`(insecure and not recommended), Secure Shell (`SSH`), `PsExec`, `WinRM`, `RDP`, or other protocols as needed.

Using the dir Command : 

```cmd-session
C:\Users\htb\Desktop> dir
  
 Volume in drive C has no label.
 Volume Serial Number is DAE9-5896

 Directory of C:\Users\htb\Desktop

06/11/2021  11:59 PM    <DIR>          .
06/11/2021  11:59 PM    <DIR>          ..
06/11/2021  11:57 PM                 0 file1.txt
06/11/2021  11:57 PM                 0 file2.txt
06/11/2021  11:57 PM                 0 file3.txt
04/13/2021  11:24 AM             2,391 Microsoft Teams.lnk
06/11/2021  11:57 PM                 0 super-secret-sauce.txt
06/11/2021  11:59 PM                 0 write-secrets.ps1
               6 File(s)          2,391 bytes
               2 Dir(s)  35,102,117,888 bytes free
```

1. The current path location (`C:\Users\htb\Desktop`)
2. The command we have issued (`dir`)
3. The results of the command (`output below the line the command was issued on`)

## Getting Help : 

- How do we utilize the help functionality within Command Prompt ?
- Why utilizing the help functionality is essential ?
- Where can we find additional external resources for help ?
- How to utilize additional tips and tricks in the Command Prompt ?

```cmd-session
C:\htb> help

For more information on a specific command, type HELP command-name
ASSOC          Displays or modifies file extension associations.
ATTRIB         Displays or changes file attributes.
BREAK          Sets or clears extended CTRL+C checking.
BCDEDIT        Sets properties in boot database to control boot loading.
CACLS          Displays or modifies access control lists (ACLs) of files.
CALL           Calls one batch program from another.
CD             Displays the name of or changes the current directory.
CHCP           Displays or sets the active code page number.
CHDIR          Displays the name of or changes the current directory.
CHKDSK         Checks a disk and displays a status report.

<snip>
```

```cmd-session
C:\htb> help time
```

The `help` utility serves as an `offline` manual for `CMD` and `DOS` compatible Windows operating system commands. `Offline` refers to the fact that this utility can be used on a system without network access.

[Microsoft Documentation](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands) has a complete listing of the commands that can be issued within the command-line interpreter as well as detailed descriptions of how to use them. Think of it as an online version of the Man pages.
[ss64](https://ss64.com/nt/) Is a handy quick reference for anything command-line related, including cmd, PowerShell, Bash, and more.

If we need to `clear` the screen and provide us an empty prompt. We can use the command `cls` to clear our terminal window of our previous results.

Command history is a dynamic thing. It allows us to `view previously ran commands` in our Command Prompt's `current active session`. The last way we can view our history is by utilizing the command `doskey /history`. [Doskey](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/doskey) is an MS-DOS utility that keeps a history of commands issued and allows them to be referenced again.

![[useful_commands.png]]

When running a command or process we want to interrupt, we can do so by pressing the `ctrl+c` key combination.

## System Navigation :

One of the easiest things we can do when initially poking around on a Windows host is to get a listing of the directory we are currently working in. We do that with the `dir` command.

Before doing anything on a host, it is helpful to know where we are in the filesystem. We can determine that by utilizing the `cd` or `chdir` commands. These commands will also move us to whatever directory we specify after the command. The specified directory can either be a directory relative to our current working directory or an absolute directory starting from the filesystem's root.

We can get a printout of the entire path we specify and its subdirectories by utilizing the `tree` command. We can utilize the `/F` parameter with the tree command to see a listing of each file and the directories along with the directory tree of the path.
 
![[interest_folder.png]]

## Working with Directories and Files : 

Creating a directory to add to our structure is a simple endeavor. We can utilize the `md` and `mkdir` commands.

Deleting directories can be accomplished using the `rd` or `rmdir` commands. The commands rd and rmdir are explicitly meant for removing directory trees and do not deal with specific files or attributes. Rd has a switch `/S` that we can utilize to erase the directory and its contents.

`Move`, `Robocopy`, and `xcopy` can copy and make changes to directories and their structures.

- To use `move`, we have to issue the syntax in this order. When moving directories, it will take the directory and any files within and move it from the `source` to the `destination` path specified.
- The syntax for `xcopy` is `xcopy` `source` `destination` `options`. As it was with move, we can use wildcards for source files, not destination files. Utilizing the `/E` switch, we told Xcopy to copy any files and subdirectories to include empty directories. If you wish to retain the file's attributes ( such as read-only or hidden ), you can use the `/K` switch.
- `Robocopy` is xcopy's successor built with much more capability. We need to be aware that Robocopy was made for large directories and drive syncing, so it does not like to copy or move singular files by default. Robocopy can also work with system, read-only, and hidden files. As a user, this can be problematic if we do not have the `SeBackupPrivilege` and `auditing privilege` attributes. We can utilize the `/MIR` switch to permit ourselves to copy the files we need temporarily.

if we wish to view the contents of a file, we can utilize the `more`, `openfiles`, and `type` commands.

Creating and modifying a file from the command line is relatively easy. We have several options that include `echo`, `fsutil`, `ren`, `rename`, and `replace`. First, `echo` with output redirection allows us to modify a file if it already exists or create a new file at the time of the call.

- With `fsutil`, we can do many things, but in this instance, we will use it to create a file.
- `Ren` allows us to change the name of a file to something new.

We can utilize the `<`, `>`, `|`, and `&` to send input and output from the console and files to where we need them.

When utilizing `del` or `erase`, remember that we can specify a directory, a filename, a list of names, or even a specific attribute to target when trying to delete files. del /A:R * if you want to delete read-only file.

To identify if there are any hidden files within the directory, we can use `dir /A:H`

Just like directories, we have several options to copy or move files. `Copy` and `move` are the easiest ways to accomplish this.

## Gathering System Information :

Gathering `system information`(aka `host enumeration`) may seem daunting at first; however, it is a crucial step in providing a good foundation for getting to know our environment. The goal of `host enumeration` is to provide an overall picture of the target host, its environment, and how it interacts with other systems across the network.

![[InformationTypesChart_Updated.webp]]

As we can see from the diagram above, the types of information that we would be looking for can be broken down into the following categories :

![[general_info.png]]

CMD provides a one-stop shop for information via the `systeminfo` command. It is excellent for finding relevant information about the host, such as hostname, IP address(es), if it belongs to a domain, what hotfixes have been installed, and much more. Having quick access to things such as the OS version, hotfixes installed, and OS build version can help us quickly determine from a quick Google or [ExploitDB](https://www.exploit-db.com/) search, if an exploit exists that can be quickly leveraged to exploit this host further, elevate privileges, and more.

As shown previously, `systeminfo` contains a lot of information to sift through; however, if we need to retrieve some basic system information such as the `hostname` or `OS version`, we can use the `hostname` and `ver` utilities built into the command prompt.

To gather this information quickly and in one simple-to-use command, Command Prompt offers the `ipconfig` utility. The [ipconfig](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig) utility displays all current TCP/IP network configurations for the machine. Let us look at an example `ipconfig` configuration without providing additional parameters. `Ipconfig` is a highly versatile command for gathering information about the network connectivity of the target host; however, if we need to quickly see what hosts our target has come into contact with, look no further than the `arp` command.

[Whoami](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami) allows us to display the user, group, and privilege information for the user that is currently logged in.

```cmd-session
C:\htb> whoami 
C:\htb> whoami /priv # Privileges
C:\htb> whoami /groups # Groups
```

[Net User](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771865(v=ws.11)) allows us to display a list of all users on a host, information about a specific user, and to create or delete users. [Net Group](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754051(v=ws.11)) will display any groups that exist on the host from which we issued the command, create and delete groups, and add or remove users from groups. [Net Share](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh750728(v=ws.11)) allows us to display info about shared resources on the host and to create new shared resources as well. [Net View](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh875576(v=ws.11)) will display to us any shared resources the host you are issuing the command against knows of. This includes domain resources, shares, printers, and more.

## Finding Files and Directories : 

This section will cover how to search for particular files and directories utilizing CMD, why enumerating system files and directories are vital, and provide an essential list of what to look out for while enumerating the system.

```cmd-session
C:\Users\student\Desktop>where calc.exe

C:\Windows\System32\calc.exe

C:\Users\student\Desktop>where bio.txt

INFO: Could not find files for the given pattern(s).
```

For calc.exe, this command worked because the system32 folder is in our environment variable path, so the `where` command can look through those folders automatically.

```cmd-session
C:\Users\student\Desktop>where /R C:\Users\student\ bio.txt

C:\Users\student\Downloads\bio.txt
```

The `/R` switch forced the `where` command to search through every folder in the student user directory hive.

On top of looking for files, we can also search wildcards for specific strings, file types, and more. Below is an example of searching for the `csv` file type within the student directory.

```cmd-session
C:\Users\student\Desktop>where /R C:\Users\student\ *.csv
```

We used `where` to give us an idea of how to search for files and applications on the host. Find is used to search for text strings or their absence within a file or files.

```cmd-session
C:\Users\student\Desktop> find "password" "C:\Users\student\not-passwords.txt" 
```

The `/V` modifier can change our search from a matching clause to a `Not` clause.
We can also use the `/N` switch to display line numbers for us and the `/I` display to ignore case sensitivity.

```cmd-session
C:\Users\student\Desktop> find /N /I /V "IP Address" example.txt  
```

If we need something more specific, `findstr` is what we need. The `findstr` command is similar to `find` in that it searches through files but for patterns instead. It will look for anything matching a pattern, regex value, wildcards, and more.

`Comp` will check each byte within two files looking for differences and then displays where they start. By default, the differences are shown in a decimal format. We can use the `/A` modifier if we want to see the differences in ASCII format. The `/L` modifier can also provide us with the line numbers.

```cmd-session
C:\Users\student\Desktop> comp .\file-1.md .\file-2.md

Comparing .\file-1.md and .\file-2.md...
Files compare OK  
```

Now let us look at `FC` for a minute. `FC` differs in that it will show you which lines are different, not just an individual character (`/A`) or byte that is different on each line.

With `Sort`, we can receive input from the console, pipeline, or a file, sort it and send the results to the console or into a file or another command.

## Environment Variables : 

Environment variables are settings that are often applied globally to our hosts. They can be found on Windows, Linux, and macOS hosts. Environment variables can be accessed by most users and applications on the host and are used to run scripts and speed up how applications function and reference data.

On a Windows host, environment variables are `not` case sensitive and can have spaces and numbers in the name.

```cmd-session
%SUPER_IMPORTANT_VARIABLE%
```

`Scope` is a programming concept that refers to where variables can be accessed or referenced. 'Scope' can be broadly separated into two categories :

- **Global:**
    - Global variables are accessible `globally`. In this context, the global scope lets us know that we can access and reference the data stored inside the variable from anywhere within a program.
- **Local:**
    - Local variables are only accessible within a `local` context. `Local` means that the data stored within these variables can only be accessed and referenced within the function or context in which it has been declared.

![[scope.png]]
 
Creating environment variables is quite a simple task. We can use either `set` or `setx` depending on the task at hand and our overall goal.

```cmd-session
C:\htb> set DCIP=172.16.5.2
C:\htb> echo %DCIP%

C:\htb> setx DCIP 172.16.5.2
```

Some crucial variables we should be aware of when performing enumeration on a host's environment : 

![[important_var.png]]

## Managing Services : 

[SC](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754599(v=ws.11)) is a Windows executable utility that allows us to query, modify, and manage host services locally and over the network. We have other tools, like Windows Management Instrumentation (`WMIC`) and `Tasklist` that can also query and manage services for local and remote hosts. 

Let's see what services are currently actively running on the system. We can do so by issuing the following command : `sc query type= service`.

```cmd-session
C:\htb> sc query type= service    
```

Returning to our scenario, we recently landed on a host and need to `query` the host and determine if Windows Defender is active.

```cmd-session
C:\htb> sc query windefend    
```

Stopping an Elevated Service : 

```cmd-session
C:\htb> sc stop windefend

Access is denied.  
```

In this scenario, the only thing that can stop and start the Defender service is the [SYSTEM](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts#default-local-system-accounts) machine account.

Starting the Print Spooler Service : 

```cmd-session
C:\WINDOWS\system32> sc start Spooler
```

Disabling Windows Update Service : 

```cmd-session
C:\WINDOWS\system32> sc config wuauserv start= disabled
C:\WINDOWS\system32> sc config bits start= disabled
```

[Tasklist](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist) is a command line tool that gives us a list of currently running processes on a local or remote host. However, we can utilize the `/svc` parameter to provide a list of services running under each process on the system.

[Net start](https://ss64.com/nt/net-service.html) is a very simple command that will allow us to quickly list all of the current running services on a system. In addition to `net start`, there is also `net stop`, `net pause`, and `net continue`.

we have [WMIC](https://ss64.com/nt/wmic.html). The Windows Management Instrumentation Command (`WMIC`) allows us to retrieve a vast range of information from our local host or host(s) across the network. To list all services existing on our system and information on them, we can issue the following command: `wmic service list brief` .

## Working With Scheduled Tasks : 

Scheduled tasks are an excellent way for administrators to ensure that tasks they want to run regularly happen, but they are also an excellent persistence point for attackers.

Triggers That Can Kick Off a Scheduled Task : 

- When a specific system event occurs.
- At a specific time.
- At a specific time on a daily schedule.
- At a specific time on a weekly schedule.
- At a specific time on a monthly schedule.
- At a specific time on a monthly day-of-week schedule.
- When the computer enters an idle state.
- When the task is registered.
- When the system is booted.
- When a user logs on.
- When a Terminal Server session changes state.

We can utilize the `schtasks` command.

Display Scheduled Tasks :

![[query_syntax_stask_display.png]]

```cmd-session
C:\htb> SCHTASKS /Query /V /FO list
```

Create a New Scheduled Task :

![[query_syntax_stask_create.png]]

```cmd-session
C:\htb> schtasks /create /sc ONSTART /tn "My Secret Task" /tr "C:\Users\Victim\AppData\Local\ncat.exe 172.16.1.100 8100"
```

Change the Properties of a Scheduled Task : 

![[query_syntax_stask_change.png]]

```cmd-session
C:\htb> schtasks /change /tn "My Secret Task" /ru administrator /rp "P@ssw0rd"
```

Delete the Scheduled Task(s) : 

![[query_syntax_stask_delete.png]]
## CMD Vs. PowerShell : 

[PowerShell](https://docs.microsoft.com/en-us/powershell/) has become increasingly prominent among IT and Infosec professionals. It has widespread utility for System Administrators, Penetration Testers, SOC Analysts, and many other technical disciplines where ever Windows systems are administered. Many of them are using PowerShell to automate tasks they must accomplish daily. Among some of these tasks are:

- Provisioning servers and installing server roles
- Creating Active Directory user accounts for new employees
- Managing Active Directory group permissions
- Disabling and deleting Active Directory user accounts
- Managing file share permissions
- Interacting with [Azure](https://azure.microsoft.com/en-us/) AD and Azure VMs
- Creating, deleting, and monitoring directories & files
- Gathering information about workstations and servers
- Setting up Microsoft Exchange email inboxes for users (in the cloud &/or on-premises)

We can access PowerShell directly on a host through the peripherals attached to the local machine or through RDP over the network through various methods.

1. Using Windows `Search`
2. Using the Windows `Terminal` Application
3. Using Windows `PowerShell ISE`
4. Using PowerShell in `CMD`

```powershell
PS C:\Users\htb-student> ipconfig 

Ethernet adapter VMware Network Adapter VMnet8:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::adb8:3c9:a8af:114%25
   IPv4 Address. . . . . . . . . . . : 172.16.110.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :
```

The prompt is almost identical to what we see in CMD.

- `PS` is short for PowerShell, followed by the current working directory `C:\Users\htb-student>`.
- This is followed by the cmdlet or string we want to execute, `ipconfig`.
- Finally, below that, we see the output results of our command.

Using the Help function. If we want to see the options and functionality available to us with a specific cmdlet, we can use the [Get-Help](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-help?view=powershell-7.2) cmdlet.

```powershell
PS C:\Users\htb-student> Get-Help Test-Wsman
PS C:\Users\htb-student> Get-Help Test-Wsman -online
```

We can also use a helpful cmdlet called [Update-Help](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/update-help?view=powershell-7.2) to ensure we have the most up-to-date information for each cmdlet on the Windows system.

```powershell
PS C:\Windows\system32> Update-Help
```

We can only move around if we know where we are already, right? We can determine our current working directory (in relation to the host system) by utilizing the `Get-Location` cmdlet.

```powershell
PS C:\htb> Get-Location
```

The `Get-ChildItem` cmdlet can display the contents of our current directory or the one we specify.

```powershell
PS C:\htb> Get-ChildItem 
```

Changing our location is simple; we can do so utilizing the `Set-Location` cmdlet.

```powershell
PS C:\htb>  Set-Location .\Documents\
```

Now, if we wish to see the contents of a file, we can use `Get-Content`. Looking in the Documents directory, we notice a file called `Readme.md`. Let us check it out.

```powershell
PS C:\htb> Get-Content Readme.md  
```

By default, `Get-History` will only show the commands that have been run during this active session.

```powershell
PS C:\htb> Get-History
```

If it bothers us to have a ton of output on our screen all the time, we can remove the text from our console window by using the command `Clear-Host`.

`Hotkeys` can enable us to perform more complex actions that typically require a mouse with just our keys. Below is a quick list of some of the more useful hotkeys.

![[hotkeys_ps.png]]

One of PowerShell's best functionalities must be tab completion of commands. We can use `tab` and `SHIFT+tab` to move through options that can complete the command we are typing.

Our last tip to mention is `Aliases`. A PowerShell alias is another name for a cmdlet, command, or executable file. We can see a list of default aliases using the [Get-Alias](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-alias?view=powershell-7.2) cmdlet.

```powershell
PS C:\Windows\system32> Get-Alias
```

We can also set an alias for a specific cmdlet using [Set-Alias](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/set-alias?view=powershell-7.2). Let us practice with this by making an alias for the `Get-Help` cmdlet.

```powershell
PS C:\Windows\system32> Set-Alias -Name gh -Value Get-Help
```

Below we also include a list of several aliases we find to be most helpful. Some commands have more than one alias as well.

![[helpful_aliases.png]]

## All About Cmdlets and Modules : 

A [cmdlet](https://docs.microsoft.com/en-us/powershell/scripting/lang-spec/chapter-13?view=powershell-7.2) as defined by Microsoft is :

"`a single-feature command that manipulates objects in PowerShell.`"

Cmdlets follow a Verb-Noun structure which often makes it easier for us to understand what any given cmdlet does.

A [PowerShell module](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/understanding-a-windows-powershell-module?view=powershell-7.2) is structured PowerShell code that is made easy to use & share. As mentioned in the official Microsoft docs, a module can be made up of the following :

- Cmdlets
- Script files
- Functions
- Assemblies
- Related resources (manifests and help files)

A PowerShell data file (`.psd1`) is a [Module manifest file](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_module_manifests?view=powershell-7.2). Contained in a manifest file we can often find:

- Reference to the module that will be processed
- Version numbers to keep track of major changes
- The GUID
- The Author of the module
- Copyright
- PowerShell compatibility information
- Modules & cmdlets included
- Metadata

Once we decide what PowerShell module we want to use, we will have to determine how and from where we will run it. `Get-Module` can help us determine what modules are already loaded.

```powershell
PS C:\htb> Get-Module 
PS C:\htb> Get-Module -ListAvailable 
```

The `-ListAvailable` modifier will show us all modules we have installed but not loaded into our session.

The [Import-Module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/import-module?view=powershell-7.2) cmdlet allows us to add a module to the current PowerShell session.
It is possible to permanently add a module or several modules by adding the files to the referenced directories in the PSModulePath.

```powershell
PS C:\Users\htb-student> $env:PSModulePath
```

An essential factor to consider when attempting to use PowerShell scripts and modules is [PowerShell's execution policy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.2). As outlined in Microsoft's official documentation, an execution policy is not a security control.

Checking Execution Policy State : 

```powershell
PS C:\htb> Get-ExecutionPolicy 
```

Setting Execution Policy : 

```powershell
PS C:\htb> Set-ExecutionPolicy undefined 
```

By changing it at the Process level, our change will revert once we close the PowerShell session.

```powershell
PS C:\htb> Set-ExecutionPolicy -scope Process 
PS C:\htb> Get-ExecutionPolicy -list
```

If we wish to see what aliases, cmdlets, and functions an imported module brought to the session, we can use `Get-Command -Module <modulename>` to enlighten us.

```powershell
PS C:\htb> Get-Command -Module PowerSploit
```

In today's day and age, sharing information is extremely easy. That goes for solutions and new creations as well. When it comes to PowerShell modules, the [PowerShell Gallery](https://www.powershellgallery.com/) Is the best place for that. It is a repository that contains PowerShell scripts, modules, and more created by Microsoft and other users.

There is already a module built into PowerShell meant to help us interact with the PowerShell Gallery called `PowerShellGet`.

One module that will prove extremely useful to system admins is the [AdminToolbox](https://www.powershellgallery.com/packages/AdminToolbox/11.0.8) module. It is a collection of several other modules with tools meant for Active Directory management, Microsoft Exchange, virtualization, and many other tasks an admin would need on any given day.

```powershell
PS C:\htb> Get-Command -Module PowerShellGet 
```

Find-Module : 

```powershell
Find-Module -Name AdminToolbox 
```

Like with many other PowerShell cmdlets, we can also search using wildcards. Once we have found a module we wish to utilize, installing it is as easy as `Install-Module`.

Below we will quickly list a few PowerShell modules and projects we, as penetration testers and sysadmins, should be aware of :

- [AdminToolbox](https://www.powershellgallery.com/packages/AdminToolbox/11.0.8): AdminToolbox is a collection of helpful modules that allow system administrators to perform any number of actions dealing with things like Active Directory, Exchange, Network management, file and storage issues, and more.
    
- [ActiveDirectory](https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps): This module is a collection of local and remote administration tools for all things Active Directory. We can manage users, groups, permissions, and much more with it.
    
- [Empire / Situational Awareness](https://github.com/BC-SECURITY/Empire/tree/master/empire/server/data/module_source/situational_awareness): Is a collection of PowerShell modules and scripts that can provide us with situational awareness on a host and the domain they are apart of. This project is being maintained by [BC Security](https://github.com/BC-SECURITY) as a part of their Empire Framework.
    
- [Inveigh](https://github.com/Kevin-Robertson/Inveigh): Inveigh is a tool built to perform network spoofing and Man-in-the-middle attacks.
    
- [BloodHound / SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors): Bloodhound/Sharphound allows us to visually map out an Active Directory Environment using graphical analysis tools and data collectors written in C# and PowerShell.

## User and Group Management : 

Several accounts are created in every instance of Windows as the OS is installed to help with host management and basic usage. Below is a list of the standard built-in accounts.

![[built_in_acc.png]]

In a nutshell, `Active Directory` (AD) is a directory service for Windows environments that provides a central point of management for `users`, computers, `groups`, network devices, `file shares`, group policies, `devices`, and trusts with other organizations.

Within this section, we care about AD in the context of users and groups. We can administer them from PowerShell on `any domain joined host` utilizing the `ActiveDirectory` Module.

`Domain` users differ from `local` users in that they are granted rights from the domain to access resources such as file servers, printers, intranet hosts, and other objects based on user and group membership. Domain user accounts can log in to any host in the domain, while the local user only has permission to access the specific host they were created on.

Groups are a way to sort user accounts logically and, in doing so, provide granular permissions and access to resources without having to manage each user manually.

Like most other things in PowerShell, we use the `get`, `new`, and `set` verbs to find, create and modify users and groups. If dealing with local users and groups, `localuser & localgroup` can accomplish this. For domain assets, `aduser & adgroup` does the trick.

`Get-LocalUser` will display the users on our host.

```powershell
PS C:\htb> Get-LocalUser  
```

Let us say that we want to create a new local user named `JLawrence`. We can accomplish the task using `New-LocalUser`.

```powershell
PS C:\htb>  New-LocalUser -Name "JLawrence" -NoPassword
```

Above, we created the user `JLawrence` and did not set a password. If we wish to modify a user, we could use the `Set-LocalUser` cmdlet. For this example, we will modify `JLawrence` and set a password and description on his account.

```powershell
PS C:\htb> $Password = Read-Host -AsSecureString
****************
PS C:\htb> Set-LocalUser -Name "JLawrence" -Password $Password -Description "CEO EagleFang"
```

In the output under, we ran the `Get-LocalGroup` cmdlet to get a printout of each group on the host.

```powershell
PS C:\htb> get-localgroup
```

Now, if we wish to add another group or user to a group, we can use the `Add-LocalGroupMember` command. We will add `JLawrence` to the `Remote Desktop Users` group in the example below.

```powershell
PS C:\htb> Add-LocalGroupMember -Group "Remote Desktop Users" -Member "JLawrence"
PS C:\htb> Get-LocalGroupMember -Name "Remote Desktop Users" 
```

Before we can access the cmdlets we need and work with Active Directory, we must install the `ActiveDirectory` PowerShell Module. If you installed the AdminToolbox, the AD module might already be on your host.

The under command will install `ALL` RSAT features in the Microsoft Catalog.

```powershell
PS C:\htb> Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online
```

Now we should have the ActiveDirectory module installed. Let us check.

```powershell
PS C:\htb> Get-Module -Name ActiveDirectory -ListAvailable 
```

Nice. Now that we have the module, we can get started with AD `User` and `Group` management. The easiest way to locate a specific user is by searching with the `Get-ADUser` cmdlet.

```powershell
PS C:\htb> Get-ADUser -Filter *
```

The parameter `-Filter *` lets us grab all users within Active Directory. We can use the `-Identity` parameter to perform a more specific search for a user by `distinguished name, GUID, the objectSid, or SamAccountName`.

```powershell
PS C:\htb>  Get-ADUser -Identity TSilver
```

We can see from the output several pieces of information about the user, including:

- `Object Class`: which specifies if the object is a user, computer, or another type of object.
- `DistinguishedName`: Specifies the object's relative path within the AD schema.
- `Enabled`: Tells us if the user is active and can log in.
- `SamAccountName`: The representation of the username used to log into the ActiveDirectory hosts.
- `ObjectGUID`: Is the unique identifier of the user object.

We could also use these to filter specific attributes. For example, let us filter the user's `Email address`.

```powershell
PS C:\htb> Get-ADUser -Filter {EmailAddress -like '*greenhorn.corp'}
```

We need to create a new user for an employee named `Mori Tanaka` who just joined Greenhorn. Let us give the New-ADUser cmdlet a try.

```powershell
PS C:\htb> New-ADUser -Name "MTanaka" -Surname "Tanaka" -GivenName "Mori" -Office "Security" -OtherAttributes @{'title'="Sensei";'mail'="MTanaka@greenhorn.corp"} -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true 

PS C:\htb> Get-ADUser -Identity MTanaka -Properties * | Format-Table Name,Enabled,GivenName,Surname,Title,Office,Mail
```

The `first` portion of the output above is creating our user:

- `New-ADUser -Name "MTanaka"`  : We issue the `New-ADUser` command and set the user's SamAccountName to `MTanaka`.
- `-Surname "Tanaka" -GivenName "Mori"` : This portion sets our user's `Lastname` and `Firstname`.
- `-Office "Security"` : Sets the extended property of `Office` to `Security`.
- `-OtherAttributes @{'title'="Sensei";'mail'="MTanaka@greenhorn.corp"}` : Here we set other extended attributes such as `title` and `Email-Address`.
- `-Accountpassword (Read-Host -AsSecureString "AccountPassword")` : With this portion, we set the user's `password` by having the shell prompt us to enter a new password. (we can see it in the line below with the stars)
- `-Enabled $true` : We are enabling the account for use. The user could not log in if this was set to `\$False`.

The `second` is validating that the user we created and the properties we set exist:

- `Get-ADUser -Identity MTanaka -Properties *` : Here, we are searching for the user's properties `MTanaka`.
- `|`  : This is the Pipe symbol. It will be explored more in another section, but for now, it takes our `output` from `Get-ADUser` and sends it into the following command.
- `Format-Table Name,Enabled,GivenName,Surname,Title,Office,Mail` : Here, we tell PowerShell to `Format` our results as a `table` including the default and extended properties listed.

Now, what if we need to modify a user? `Set-ADUser` is our ticket. Many of the filters we looked at earlier apply here as well. We can change or set any of the attributes that were listed. For this example, let us add a `Description` to Mr. Tanaka.

```powershell
PS C:\htb> Set-ADUser -Identity MTanaka -Description " Sensei to Security Analyst's Rocky, Colt, and Tum-Tum"  
```

## Working with Files and Directories :

The table below lists the commonly used cmdlets used when dealing with objects in PowerShell.

![[common_comm.png]]

Permissions, simplified, are our host's way of determining who has access to a specific object and what they can do with it. These permissions allow us to apply granular security control over our objects to maintain a proper security posture. Some of the key permission types are :

- `Full Control`: Full Control allows for the user or group specified the ability to interact with the file as they see fit. This includes everything below, changing the permissions, and taking ownership of the file.
- `Modify`: Allows reading, writing, and deleting files and folders.
- `List Folder Contents`: This makes viewing and listing folders and subfolders possible along with executing files. This only applies to `folders`.
- `Read and Execute`: Allows users to view the contents within files and run executables (.ps1, .exe, .bat, etc.)
- `Write`: Write allows a user the ability to create new files and subfolders along with being able to add content to files.
- `Read`: Allows for viewing and listing folders and subfolders and viewing a file's contents.
- `Traverse Folder`: Traverse allows us to give a user the ability to access files or subfolders within a tree but not have access to the higher-level folder's contents. This is a way to provide selective access from a security perspective.

## Finding & Filtering Content : 

With PowerShell, not everything is generic text strings like in Bash or cmd. In PowerShell, everything is an `Object`. However, what is an object? Let us examine this concept further :

`What is an Object?` An `object` is an `individual` instance of a `class` within PowerShell. Let us use the example of a computer as our object. The total of everything (parts, time, design, software, etc.) makes a computer a computer.

`What is a Class?` A class is the `schema` or 'unique representation of a thing (object) and how the sum of its `properties` define it. The `blueprint` used to lay out how that computer should be assembled and what everything within it can be considered a Class.

`What are Properties?` Properties are simply the `data` associated with an object in PowerShell. For our example of a computer, the individual `parts` that we assemble to make the computer are its properties. Each part serves a purpose and has a unique use within the object.

`What are Methods?` Simply put, methods are all the functions our object has. Our computer allows us to process data, surf the internet, learn new skills, etc. All of these are the methods for our object.

Get an Object (User) and its Properties/Methods : 

```powershell
PS C:\htb> Get-LocalUser administrator | get-member
```

Now that we can see all of a user's properties let us look at what those properties look like when output by PowerShell. The [Select-Object](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/select-object?view=powershell-7.2) cmdlet will help us achieve this. In this manner, we now understand what makes up a user object.

```powershell
PS C:\htb> Get-LocalUser administrator | Select-Object -Property *
```

We could filter out the properties of an object we do not want to see by selecting the few we do. Let's look at our users and see which have set a password recently.

```powershell
PS C:\htb> Get-LocalUser * | Select-Object -Property Name,PasswordLastSet
```

We can also `sort` and `group` our objects on these properties.

```powershell
PS C:\htb> Get-LocalUser * | Sort-Object -Property Name | Group-Object -property Enabled
```

We utilized the `Sort-Object` and `Group-Object` cmdlets to find all users, `sort` them by `name`, and then `group` them together based on their `Enabled` property.

```powershell
PS C:\htb> Get-Service | Select-Object -Property *
```

This is way too much data to sift through, right? Let us break it down further and format this data as a list.

```powershell
PS C:\htb> get-service | Select-Object -Property DisplayName,Name,Status | Sort-Object DisplayName | fl 
```

Using `Where-Object` (`where` as an alias) and the parameter matching with `-like` will allow us to determine if we are safe to continue by looking for anything with "`Defender`" in the property. In this instance, we check the `DisplayName` property of all objects retrieved by `Get-Service`.

```powershell
PS C:\htb>  Get-Service | where DisplayName -like '*Defender*'
```

The output above is an excellent example of this utilizing the `-like` Comparison operator. Below is a quick list (not all-encompassing) of other useful expressions we can utilize :

![[comp_op.png]]

Some tools exist, like `Snaffler`, `Winpeas`, and the like, that can search for interesting files and strings, but what if we `cannot` bring a new tool onto the host ?
[Select-String](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/select-string?view=powershell-7.2) (`sls` as an alias) for those more familiar with using the Linux CLI, functions much in the same manner as `Grep` does or `findstr.exe` within the Windows Command-Prompt.

We can start with `Get-ChildItem` and perform a recursive search through a folder. Let us test it out.

```powershell
PS C:\htb> Get-Childitem –Path C:\Users\MTanaka\ -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.txt")}


PS C:\htb> Get-Childitem –Path C:\Users\MTanaka\ -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.txt" -or $_.Name -like "*.py" -or $_.Name -like "*.ps1" -or $_.Name -like "*.md" -or $_.Name -like "*.csv")}
```

Now that we have our list of interesting files, we could turn around and `pipe` those objects into another cmdlet (`Select-String`) that searches through their content for interesting strings and keywords or phrases.

```powershell
PS C:\htb> Get-Childitem –Path C:\Users\MTanaka\ -File -Recurse -ErrorAction SilentlyContinue | where {($_. Name -like "*.txt" -or $_. Name -like "*.py" -or $_. Name -like "*.ps1" -or $_. Name -like "*.md" -or $_. Name -like "*.csv")} | sls "Password","credential","key","UserName"
```

While looking for valuable files and other content, we can check many more valuable files in many different places. The list below contains just a few tips and tricks that can be used in our search for loot.

- Looking in a Users `\AppData\` folder is a great place to start. Many applications store `configuration files`, `temp saves` of documents, and more.
- A Users home folder `C:\Users\User\` is a common storage place; things like VPN keys, SSH keys, and more are stored. Typically in `hidden` folders. (`Get-ChildItem -Hidden`)
- The Console History files kept by the host are an endless well of information, especially if you land on an administrator's host. You can check two different points:
    - `C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt`
    - `Get-Content (Get-PSReadlineOption).HistorySavePath`
- Checking a user's clipboard may also yield useful information. You can do so with `Get-Clipboard`
- Looking at Scheduled tasks can be helpful as well.

## Working with Services : 

Service administration is crucial in managing hosts and ensuring our security posture remains unchanged. PowerShell provides us with the module `Microsoft.PowerShell.Management`, which contains several cmdlets for interacting with Services. As with everything in PowerShell, if you are unsure where to start or what cmdlet you need, take advantage of the built-in help to get you started.

```powershell
PS C:\htb> Get-Help *-Service  
```

We first need to get a quick running list of services from our target host. Services can have a status set as Running, Stopped, or Paused and can be set up to start manually (user interaction), automatically (at system startup), or on a delay after system boot.

```powershell
PS C:\htb> Get-Service | ft DisplayName,Status 
```

To make it a little clearer to run, we piped our service listing into `format-table` and chose the properties `DisplayName` and `Status` to display in our console.

From Mr. Tanaka's request, he mentioned a potential issue with Windows Defender, so let us filter out any services not related to that.

```powershell
PS C:\htb> Get-Service | where DisplayName -like '*Defender*' | ft DisplayName,ServiceName,Status
```

Now we can see just the services related to `Defender,` and we can see that for some reason, the Microsoft Defender Antivirus Service (`WinDefend`) is indeed turned off.

```powershell
PS C:\htb> Start-Service WinDefend
```

As we ran the cmdlet `Start-Service` as long as we did not get an error message like `"ParserError: This script contains malicious content and has been blocked by your antivirus software."` or others, the command executed successfully.

```powershell
PS C:\htb> Stop-Service Spooler 

PS C:\htb> Get-Service Spooler 
```

Now we can see that using the Stop-Service, we stopped the operating status of the `Spooler` service.

```powershell
PS C:\htb> Set-Service -Name Spooler -StartType Disabled
```

Ok, now our Spooler service has been stopped, and its Startup changed to Disabled for now. Modifying a running service is reasonably straightforward. Ensure that if you attempt to make any modifications, you are an Administrator for the host or on the domain.

The `-ComputerName` parameter allows us to specify that we want to query a remote host.

```powershell
PS C:\htb> get-service -ComputerName ACADEMY-ICL-DC
```

```powershell
PS C:\htb> Get-Service -ComputerName ACADEMY-ICL-DC | Where-Object {$_.Status -eq "Running"}
```

if a DisplayName is set to something specific, etc. Regarding remote interactions, we can also use the `Invoke-Command` cmdlet. Let us try and query multiple hosts and see the status of the `UserManager` service.

```powershell
PS C:\htb> invoke-command -ComputerName ACADEMY-ICL-DC,LOCALHOST -ScriptBlock {Get-Service -Name 'windefend'}
```

Let us break this down now:

- `Invoke-Command` : We are telling PowerShell that we want to run a command on a local or remote computer.
- `Computername` : We provide a comma-defined list of computer names to query.
- `ScriptBlock {commands to run}` : This portion is the enclosed command we want to run on the computer. For it to run, we need it to be enclosed in {}.

## Working with the Registry :

At its core, the `Registry` can be considered a hierarchal tree that contains two essential elements: `keys` and `values`. As Pentesters, the Registry is a great spot to find helpful information, plant persistence, and more. [MITRE](https://attack.mitre.org/techniques/T1112/) provides many great examples of what a threat actor can do with access (locally or remotely) to a host's registry hive.

`Keys`, in essence, are containers that represent a specific component of the PC. Keys can contain other keys and values as data. These entries can take many forms, and naming contexts only require that a Key be named using alphanumeric (printable) characters and is not case-sensitive.
 
A host systems Registry `root keys` are stored in several different files and can be accessed from `C:\Windows\System32\Config\`. For a detailed list of all Registry Hives and their supporting files within the OS, we can look [HERE](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives). Now let's discuss Values within the Registry.

`Values` represent data in the form of objects that pertain to that specific Key. These values consist of a name, a type specification, and the required data to identify what it's for. We can reference the complete list of Registry Key Values [HERE](https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types). In all, there are 11 different value types that can be configured.

Each Windows host has a set of predefined Registry keys that maintain the host and settings required for use. Below is a breakdown of each hive and what can be found referenced within.

![[predef_keys.png]]

From the CLI, we have several options to access the Registry and manage our keys. The first is using [reg.exe](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg). `Reg` is a dos executable explicitly made for use in managing Registry settings. The second is using the `Get-Item` and `Get-ItemProperty` cmdlets to read keys and values.

```powershell
PS C:\htb> Get-Item -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Select-Object -ExpandProperty Property  
```

If we wished to see each key and object within a hive, we could also use `Get-ChildItem` with the `-Recurse` parameter like so :

```powershell
PS C:\htb> Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion -Recurse
```

We can make our output easier to read using the `Get-ItemProperty` cmdlet. Let's try that same query but with `Get-ItemProperty`.

```powershell
PS C:\htb> Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

When it comes to querying information, we can also use Reg.exe. Let's take a look at the output from that.

```powershell
PS C:\htb> reg query HKEY_LOCAL_MACHINE\SOFTWARE\7-Zip
```

We will look at the command string `REG QUERY HKCU /F "password" /t REG_SZ /S /K`.

- `Reg query`: We are calling on Reg.exe and specifying that we want to query data.
- `HKCU`: This portion is setting the path to search. In this instance, we are looking in all of HKey_Current_User.
- `/f "password"`: /f sets the pattern we are searching for. In this instance, we are looking for "Password".
- `/t REG_SZ`: /t is setting the value type to search. If we do not specify, reg query will search through every type.
- `/s`: /s says to search through all subkeys and values recursively.
- `/k`: /k narrows it down to only searching through Key names.

When dealing with the modification or creation of `new keys and values`, we can use standard PowerShell cmdlets like `New-Item`, `Set-Item`, `New-ItemProerty`, and `Set-ItemProperty` or utilize `Reg.exe` again to make the changes we need.

```powershell
PS C:\htb> New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\ -Name TestKey
```

We now have a new key within the RunOnce key. By specifying the `-Path` parameter, we avoid changing our location in the shell to where we want to add a key in the Registry, letting us work from anywhere as long as we specify the absolute path. Let's set a Property and a value now.

```powershell
PS C:\htb>  New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey -Name  "access" -PropertyType String -Value "C:\Users\htb-student\Downloads\payload.exe"
```

If we wanted to add the same key/value pair using Reg.exe, we would do so like this :

```powershell
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce\TestKey" /v access /t REG_SZ /d "C:\Users\htb-student\Downloads\payload.exe"  
```

Let's practice deleting :

```powershell
PS C:\htb> Remove-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey -Name  "access"
```

## Working with the Windows Event Log : 

A clear understanding of event logging is crucial to success in infosec. There are a few key concepts that we need to define. The first one that needs to be explained is an `event` definition. Simply put, an `event` is any action or occurrence that can be identified and classified by a system's hardware or software. `Events` can be generated or triggered through a variety of different ways including some of the following:

- User-Generated Events
    - Movement of a mouse, typing on a keyboard, other user-controlled peripherals, etc.
- Application Generated Events
    - Application updates, crashes, memory usage/consumption, etc.
- System Generated Events
    - System uptime, system updates, driver loading/unloading, user login, etc.
    
 How does a Windows system keep track of and categorize all of them? This is where our second key concept, known as `event logging` comes into play.

[Event Logging](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging) as defined by Microsoft:

"`...provides a standard, centralized way for applications (and the operating system) to record important software and hardware events.`"

The main four log categories include application, security, setup, and system. Another type of category also exists called `forwarded events`.

![[event_log.png]]

There are five types of events that can be logged on Windows systems:

![[event_types.png]]

Each log can have one of five severity levels associated with it, denoted by a number:

![[event_security.png]]

The Windows Event Log provides information about hardware and software events on a Windows system. All event logs are stored in a standard format and include the following elements:

- `Log name`: As discussed above, the name of the event log where the events will be written. By default, events are logged for `system`, `security`, and `applications`.
- `Event date/time`: Date and time when the event occurred
- `Task Category`: The type of recorded event log
- `Event ID`: A unique identifier for sysadmins to identify a specific logged event
- `Source`: Where the log originated from, typically the name of a program or software application
- `Level`: Severity level of the event. This can be information, error, verbose, warning, critical
- `User`: Username of who logged onto the host when the event occurred
- `Computer`: Name of the computer where the event is logged

The Windows Event Log is handled by the `EventLog` services. On a Windows system, the service's display name is `Windows Event Log`, and it runs inside the service host process [svchost.exe](https://en.wikipedia.org/wiki/Svchost.exe).

By default, Windows Event Logs are stored in `C:\Windows\System32\winevt\logs` with the file extension `.evtx`.

We can interact with the Windows Event log using the [Windows Event Viewer](https://en.wikipedia.org/wiki/Event_Viewer) GUI application via the command line utility [wevtutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil), or using the [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.3) PowerShell cmdlet.

We can use the `el` parameter to enumerate the names of all logs present on a Windows system.

```cmd
C:\htb> wevtutil el
```

With the `gl` parameter, we can display configuration information for a specific log, notably whether the log is enabled or not, the maximum size, permissions, and where the log is stored on the system.

```cmd
C:\htb> wevtutil gl "Windows PowerShell"
```

The `gli` parameter will give us specific status information about the log or log file, such as the creation time, last access and write times, file size, number of log records, and more.

```cmd
C:\htb> wevtutil gli "Windows PowerShell"
```

There are many ways we can query for events. For example, let's say we want to display the last 5 most recent events from the Security log in text format. Local admin access is needed for this command.

```cmd
C:\htb> wevtutil qe Security /c:5 /rd:true /f:text
```

We can also export events from a specific log for offline processing. Local admin is also needed to perform this export.

```cmd
C:\htb> wevtutil epl System C:\system_export.evtx
```

Similarly, we can interact with Windows Event Logs using the [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.3) PowerShell cmdlet.

PowerShell - Listing All Logs : 

```powershell
PS C:\htb> Get-WinEvent -ListLog *
```

We can also list information about a specific log. Here we can see the size of the `Security` log.

```powershell
PS C:\htb> Get-WinEvent -ListLog Security
```

We can query for the last X number of events, looking specifically for the last five events using the `-MaxEvents` parameter. If we want to get older logs first, we can reverse the order to list the oldest ones first using the `-Oldest` parameter.

```powershell
PS C:\htb> Get-WinEvent -LogName 'Security' -MaxEvents 5 | Select-Object -ExpandProperty Message
```

We can dig deeper and look at specific event IDs in specific logs. Let's say we only want to look at logon failures in the Security log, checking for Event ID [4625: An account failed to log on](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625). From here, we could use the `-ExpandProperty` parameter to dig deeper into specific events, list logs from oldest to newest, etc.

```powershell
PS C:\htb> Get-WinEvent -FilterHashTable @{LogName='Security';ID='4625 '}
```

We can also look at only events with a specific information level. Let's check all System logs for only `critical` events with information level `1`.

```powershell
PS C:\htb> Get-WinEvent -FilterHashTable @{LogName='System';Level='1'} | select-object -ExpandProperty Message
```

## Networking Management from The CLI : 

Networking with Windows hosts functions much like any other Linux or Unix-based host. The TCP/IP stack, wireless protocols, and other applications treat most devices the same, so there isn't much to learn there that's new. Below we will quickly cover some standard protocols you could run into when administering or pentesting Windows hosts.

![[protocol.png]]

Local host access is when we are directly at the terminal utilizing its resources as you are right now from your PC. Usually, this will not require us to use any specific access protocols except when we request resources from networked hosts or attempt to access the Internet.

Before doing anything else, let's validate the network settings on Mr. Tanaka's host. We will start by running the `IPConfig` command.

```powershell
PS C:\htb> ipconfig 
```

We can output the full network settings by appending the `/all` modifier to the ipconfig command like so :

```powershell
PS C:\htb> ipconfig /all 
```

Let's look at `Arp` settings and see if his host has communicated with others on the network.

```powershell
PS C:\htb> arp -a
```

We will utilize `nslookup`, a built-in DNS querying tool, to attempt to resolve the IP address / DNS name of the Greenhorn domain controller.

```powershell
PS C:\htb> nslookup ACADEMY-ICL-DC
```

We can do so using `netstat -an`. Netstat will display current network connections to our host. The `-an` switch will print all connections and listening ports and place them in numerical form.

```powershell
PS C:\htb> netstat -an 
```

PowerShell has several powerful built-in cmdlets made to handle networking services and administration. The NetAdapter, NetConnection, and NetTCPIP modules are just a few that we will practice with today.

![[net_cmd.png]]

We can set up an SSH server on a Windows target using the [Add-WindowsCapability](https://docs.microsoft.com/en-us/powershell/module/dism/add-windowscapability?view=windowsserver2022-ps) cmdlet and confirm that it is successfully installed using the [Get-WindowsCapability](https://docs.microsoft.com/en-us/powershell/module/dism/get-windowscapability?view=windowsserver2022-ps) cmdlet.

```powershell
PS C:\Users\htb-student> Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'


PS C:\Users\htb-student> Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

PS C:\Users\htb-student> Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

PS C:\Users\htb-student> Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

PS C:\Users\htb-student> Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'
```

Once we have confirmed SSH is installed, we can use the [Start-Service](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-service?view=powershell-7.2) cmdlet to start the SSH service.

```powershell
PS C:\Users\htb-student> Start-Service sshd  
  
PS C:\Users\htb-student> Set-Service -Name sshd -StartupType 'Automatic'  
```

With SSH installed and running on a Windows target, we can connect over the network with an SSH client.

```powershell
PS C:\Users\administrator> ssh htb-student@10.129.224.248
```

Now that we have covered SSH let's spend some time covering enabling and using `WinRM` for remote access and management.

[Windows Remote Management (WinRM)](https://docs.microsoft.com/en-us/windows/win32/winrm/portal) can be configured using dedicated PowerShell cmdlets and we can enter into a PowerShell interactive session as well as issue commands on remote Windows target(s).

WinRM can be enabled on a Windows target using the following commands :

```powershell
PS C:\WINDOWS\system32> winrm quickconfig
```

Once we have enabled and configured WinRM, we can test remote access using the [Test-WSMan](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/test-wsman?view=powershell-7.2) PowerShell cmdlet.

```powershell
PS C:\Users\administrator> Test-WSMan -ComputerName "10.129.224.248"
PS C:\Users\administrator> Test-WSMan -ComputerName "10.129.224.248" -Authentication Negotiate
```

We also have the option to use the [Enter-PSSession](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession?view=powershell-7.2) cmdlet to establish a PowerShell session with a Windows target.

```powershell
PS C:\Users\administrator> Enter-PSSession -ComputerName 10.129.224.248 -Credential htb-student -Authentication Negotiate
[10.129.5.129]: PS C:\Users\htb-student\Documents> $PSVersionTable 
```

## Interacting With The Web : 

When it comes to interacting with the web via PowerShell, the [Invoke-WebRequest](https://learn.microsoft.com/bs-latn-ba/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-5.1) cmdlet is our champion. We can use it to perform basic HTTP/HTTPS requests (like `GET` and `POST`), parse through HTML pages, download files, authenticate, and even maintain a session with a site. It's very versatile and easy to use in scripting and automation. If you prefer aliases, the Invoke-WebRequest cmdlet is aliased to `wget`, `iwr` and `curl`.

Notice in the synopsis from the Get-Help output it states:

"`Gets content from a web page on the Internet.`"

We can perform a basic Get request of a website using the `-Method GET` modifier with the Invoke-WebRequest cmdlet : 

```powershell
PS C:\htb> Invoke-WebRequest -Uri "https://web.ics.purdue.edu/~gchopra/class/public/pages/webdesign/05_simple.html" -Method GET | Get-Member
```

Notice all the different properties this site has. We can now filter on those if we wish to show only a portion of the site. For example, what if we just wanted to see a listing of the images on the site? We can do that by performing the request and then filtering for just `Images` like so :

```powershell
PS C:\htb> Invoke-WebRequest -Uri "https://web.ics.purdue.edu/~gchopra/class/public/pages/webdesign/05_simple.html" -Method GET | fl Images
```

Now we have an easy-to-read list of the images included in the website, and we can download them if we want. This is a super easy way only to get the information we wish to see. The raw content of the website we are enumerating looks like this :

```powershell
PS C:\htb> Invoke-WebRequest -Uri "https://web.ics.purdue.edu/~gchopra/class/public/pages/webdesign/05_simple.html" -Method GET | fl RawContent
```

We can practice using Invoke-WebRequest by downloading a popular tool used by many pentesters called [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1).

```powershell
PS C:\> Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1" -OutFile "C:\PowerView.ps1"
```

So what happens if we are restricted from using `Invoke-WebRequest` for some reason? Not to fear, Windows provides several different methods to interact with web clients. The first and more challenging interaction path is utilizing the [.Net.WebClient](https://learn.microsoft.com/en-us/dotnet/api/system.net.webclient?view=net-7.0) class.

```powershell
PS C:\htb> (New-Object Net.WebClient).DownloadFile("https://github.com/BloodHoundAD/BloodHound/releases/download/4.2.0/BloodHound-win32-x64.zip", "Bloodhound.zip")
```

So it worked. Let's break down what we did :

- First we have the Download cradle `(New-Object Net.WebClient).DownloadFile()`, which is how we tell it to execute our request.
- Next, we need to include the URI of the file we want to download as the first parameter in the (). For this example, that was `"https://github.com/BloodHoundAD/BloodHound/releases/download/4.2.0/BloodHound-win32-x64.zip"`.
- Finally, we need to tell the command where we want the file written to with the second parameter `, "BloodHound.zip"`.

## PowerShell Scripting and Automation : 

The easiest way to think of it is that a script is an executable text file containing PowerShell cmdlets and functions, while a module can be just a simple script, or a collection of multiple script files, manifests, and functions bundled together. The other main difference is in their use. You would typically call a script by executing it directly, while you can import a module and all of the associated scripts and functions to call at your whim.

To familiarize ourselves with some file extensions we will encounter while working with PowerShell scripts and modules, we have put together a small table with the extensions and their descriptions.

![[ps_extensions.png]]

A module is made up of `four` essential components :

1. A `directory` containing all the required files and content, saved somewhere within `$env:PSModulePath`.

- This is done so that when you attempt to import it into your PowerShell session or Profile, it can be automatically found instead of having to specify where it is.

2. A `manifest` file listing all files and pertinent information about the module and its function.

- This could include associated scripts, dependencies, the author, example usage, etc.

3. Some code file - usually either a PowerShell script (`.ps1`) or a (`.psm1`) module file that contains our script functions and other information.
    
4. Other resources the module needs, such as help files, scripts, and other supporting documents.

So we are going to make a folder named `quick-recon`.

```powershell
PS C:\htb> mkdir quick-recon  
```

Now that we have our directory, we can create the module. Let's discuss a `module manifest` file for a second.

A module manifest is a simple `.psd1` file that contains a hash table. The keys and values in the hash table perform the following functions:

- Describe the `contents` and `attributes` of the module.
- Define the `prerequisites`. ( specific modules from outside the module itself, variables, functions, etc.)
- Determine how the `components` are `processed`.

If you add a manifest file to the module folder, you can reference multiple files as a single unit by referencing the manifest. The `manifest` describes the following information:

- `Metadata` about the module, such as the module version number, the author, and the description.
- `Prerequisites` needed to import the module, such as the Windows PowerShell version, the common language runtime (CLR) version, and the required modules.
- `Processing` directives, such as the scripts, formats, and types to process.
- `Restrictions` on the module members to export, such as the aliases, functions, variables, and cmdlets to export.

We can quickly create a manifest file by utilizing `New-ModuleManifest` and specifying where we want it placed.

```powershell
PS C:\htb> New-ModuleManifest -Path C:\Users\MTanaka\Documents\WindowsPowerShell\Modules\quick-recon\quick-recon.psd1 -PassThru
```

We can use the `New-Item` (ni) cmdlet to create our file (script file).

```powershell
PS C:\htb>  ni quick-recon.psm1 -ItemType File
```

If our new PowerShell requires other modules or cmdlets from within them to operate correctly, we will place an `Import-Module` string at the beginning of our script file.

```powershell
Import-Module ActiveDirectory 
```

Now we can get to the meat of the file, our `functions`.
We need to do four main things with this module :

- Retrieve the host ComputerName
- Retrieve the hosts IP configuration
- Retrieve basic domain information
- Retrieve an output of the "C:\Users" directory

Now let's dive in and create the rest of our variables for use.

```powershell
Import-Module ActiveDirectory 

$Hostname = $env:ComputerName
$IP = ipconfig 
$Domain = Get-ADDomain  
$Users = Get-ChildItem C:\Users\ 
```

To make things easier, we will make this output process into a callable function called `Get-Recon`.
The (`#`) will tell PowerShell that the line contains a comment within your script or module file.

```powershell
Import-Module ActiveDirectory

<# 
.Description  
This function performs some simple recon tasks for the user. We import the module and issue the 'Get-Recon' command to retrieve our output. Each variable and line within the function and script are commented for our understanding. Right now, this module will only work on the local host from which you run it, and the output will be sent to a file named 'recon.txt' on the Desktop of the user who opened the shell. Remote Recon functions are coming soon!  

.Example  
After importing the module run "Get-Recon"
'Get-Recon


    Directory: C:\Users\MTanaka\Desktop


Mode                 LastWriteTime         Length Name                                                                                                                                        
----                 -------------         ------ ----                                                                                                                                        
-a----         11/3/2022  12:46 PM              0 recon.txt '

.Notes  
Remote Recon functions coming soon! This script serves as our initial introduction to writing functions and scripts and making PowerShell modules.  

#>

function Get-Recon {  
    # Collect the hostname of our PC.
    $Hostname = $env:ComputerName  
    # Collect the IP configuration.
    $IP = ipconfig
    # Collect basic domain information.
    $Domain = Get-ADDomain 
    # Output the users who have logged in and built out a basic directory structure in "C:\Users\".
    $Users = Get-ChildItem C:\Users\
    # Create a new file to place our recon results in.
    new-Item ~\Desktop\recon.txt -ItemType File 
    # A variable to hold the results of our other variables. 
    $Vars = "***---Hostname info---***", $Hostname, "***---Domain Info---***", $Domain, "***---IP INFO---***",  $IP, "***---USERS---***", $Users
    # It does the thing 
    Add-Content ~\Desktop\recon.txt $Vars
  } 

Export-ModuleMember -Function Get-Recon -Variable Hostname  
```

We may add functions to our scripts that we do not want to be accessed, exported, or utilized by other scripts or processes within PowerShell. To protect a function from being exported or to explicitly set it for export, the `Export-ModuleMember` is the cmdlet for the job.

It ensures that the module's variables, aliases, and functions cannot be `exported`. If we wish to specify what to export, we can add them to the command string like so :

```powershell
Export-ModuleMember -Function Get-Recon -Variable Hostname 
```

PowerShell currently uses `three` different Scope levels :

![[ps_scope.png]]

From here we can save this file in our Module directory we created and import it from within PowerShell for use.

```powershell
PS C:\htb> Import-Module 'C:\Users\MTanaka\Documents\WindowsPowerShell\Modules\quick-recon.psm1`

PS C:\Users\MTanaka\Documents\WindowsPowerShell\Modules\quick-recon> get-module

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Manifest   3.1.0.0    Microsoft.PowerShell.Management     {Add-Computer, Add-Content, Checkpoint-Computer, Clear-Con...
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PS...
Script     0.0        quick-recon                         Get-Recon
```

```powershell
PS C:\htb> get-help get-recon

NAME
    Get-Recon

SYNOPSIS


SYNTAX
    Get-Recon [<CommonParameters>]


DESCRIPTION
    This function performs some simple recon tasks for the user. We simply import the module and then issue the
    'Get-Recon' command to retrieve our output. Each variable and line within the function and script are commented for
    your understanding. Right now, this only works on the local host from which you run it, and the output will be sent
    to a file named 'recon.txt' on the Desktop of the user who opened the shell. Remote Recon functions coming soon!


RELATED LINKS

REMARKS
    To see the examples, type: "get-help Get-Recon -examples."
    For more information, type: "get-help Get-Recon -detailed."
    For technical information, type: "get-help Get-Recon -full."
```

